"""Real FAISS with deterministic encoder doubles; no network or paid providers."""
import json
from dataclasses import replace

import pytest

faiss = pytest.importorskip('faiss', reason='Install requirements-index.lock for FAISS checks')
import numpy as np

from backend.chunking import persist_chunks
from backend.ingestion import ROOT, normalize_manifest
from backend.indexes import (IndexConfig, build_indexes, load_indexes, make_index,
                             one_thread, training_rows, validate_index, verify_indexes)
from backend.normalization.common import canonical, digest
from backend.storage import CorpusStore
from backend.tests.test_chunking import Tokenizer
from backend.vector_artifacts import (build_vectors, current_chunks, file_hash,
                                      inventory, load_vectors, validate_vectors, write_json)


def vectors(count):
    x = np.random.default_rng(42).normal(size=(count, 384)).astype(np.float32)
    x /= np.linalg.norm(x, axis=1, keepdims=True)
    return x


class Encoder:
    def __init__(self):
        self.calls = 0

    def __call__(self, texts, **kwargs):
        self.calls += 1
        assert kwargs['normalize_embeddings'] and kwargs['convert_to_numpy']
        return vectors(len(texts))


@pytest.fixture(autouse=True)
def mock_model_asset_validation(monkeypatch):
    # Unit tests never download weights; actual model bytes are checked by the
    # explicit full-corpus CLI validation, separately from this encoder double.
    import backend.vector_artifacts as artifacts
    monkeypatch.setattr(artifacts, 'verify_assets', lambda: None)


@pytest.fixture
def corpus(tmp_path):
    database = tmp_path / 'corpus.sqlite3'
    batch, sha = normalize_manifest(ROOT / 'data/manifests/raw-normalizers-v1.json')
    with CorpusStore(database) as store:
        store.ingest(batch, sha)
        persist_chunks(store, Tokenizer())
    return database


@pytest.fixture
def bundle(tmp_path, corpus):
    root = tmp_path / 'indexes'
    encoder = Encoder()
    report = build_indexes(corpus, root, tmp_path / 'embeddings', encoder=encoder)
    assert encoder.calls == 1
    return corpus, root, load_indexes(corpus, root), report


def refresh_manifest(root, bundle):
    """Trusted-maintainer mutation, to exercise semantic checks past file hashes."""
    write_json(bundle.directory / 'manifest.json', bundle.manifest)
    pointer = json.loads((root / 'active.json').read_bytes())
    pointer['manifest_sha256'] = file_hash(bundle.directory / 'manifest.json')
    write_json(root / 'active.json', pointer)


def test_fixture_partitions_exact_flat_and_reload(bundle):
    database, root, loaded, report = bundle
    assert report['reload_search_verified'] and report['partitions']['all']['ivf'] == 'skipped'
    for partition, part in loaded.manifest['partitions'].items():
        subset = loaded.vectors[part['rows']]
        if not len(subset):
            continue
        for strategy in ('flat', 'hnsw'):
            hits = loaded.search(subset[:1], strategy, partition, 50)
            assert hits and len(hits) == len(subset)
            assert {h['chunk_id'] for h in hits} == {loaded.rows[i]['chunk_id'] for i in part['rows']}
            assert hits[0]['score'] == pytest.approx(1, abs=1e-5)
            again = load_indexes(database, root)
            assert hits == again.search(subset[:1], strategy, partition, 50)
        with pytest.raises(ValueError, match='Undertrained'):
            loaded.search(subset[:1], 'ivf', partition)
    scores = loaded.vectors @ loaded.vectors[0]
    expected = np.argsort(-scores)[:min(10, len(scores))]
    hits = loaded.search(loaded.vectors[:1])
    assert [h['chunk_id'] for h in hits] == [loaded.rows[i]['chunk_id'] for i in expected]


@pytest.mark.parametrize('strategy', ['flat', 'ivf', 'hnsw'])
def test_real_strategies_full_vector_roundtrip_and_exact_ivf_probe(tmp_path, strategy):
    x = vectors(2496)
    config = IndexConfig(nprobe=64)
    index = make_index(strategy, x, config)
    path = tmp_path / 'index.faiss'
    with one_thread():
        scores, ids = index.search(x[:4], 10)
    faiss.write_index(index, str(path))
    restored = faiss.read_index(str(path))
    validate_index(restored, strategy, x, config)
    with one_thread():
        new_scores, new_ids = restored.search(x[:4], 10)
    np.testing.assert_array_equal(ids, new_ids)
    np.testing.assert_allclose(scores, new_scores, atol=1e-6)
    if strategy in ('flat', 'ivf'):
        brute = np.argsort(-(x[:4] @ x.T), axis=1)[:, :10]
        np.testing.assert_array_equal(ids, brute)
    assert all(i in row for i, row in enumerate(ids))


def test_ivf_training_guard_and_deterministic_sample():
    with pytest.raises(ValueError, match='need at least 2496'):
        make_index('ivf', vectors(2495), IndexConfig())
    assert np.array_equal(training_rows(100001, IndexConfig()), training_rows(100001, IndexConfig()))
    assert len(training_rows(100001, IndexConfig())) == 100000


@pytest.mark.parametrize('changes', [{'nlist': 1}, {'nprobe': 65}, {'m': 8}, {'threads': 2}, {'seed': 0}, {'ef_search': 0}])
def test_bad_build_parameters(changes):
    with pytest.raises(ValueError):
        replace(IndexConfig(), **changes).validate()


@pytest.mark.parametrize('bad', ['zero', 'nan', 'float64', 'dimension', 'nonunit'])
def test_vectors_rejected(bad):
    x = vectors(2)
    if bad == 'zero':
        x[:] = 0
    elif bad == 'nan':
        x[0, 0] = np.nan
    elif bad == 'float64':
        x = x.astype(np.float64)
    elif bad == 'dimension':
        x = x[:, :383].copy()
    else:
        x *= 2
    with pytest.raises(ValueError):
        validate_vectors(x, 2)


def test_checksum_failure_precedes_native_read(bundle, monkeypatch):
    database, root, loaded, _ = bundle
    path = loaded.directory / 'all-flat.faiss'
    path.write_bytes(path.read_bytes()[:-3])
    monkeypatch.setattr(faiss, 'read_index', lambda *_: pytest.fail('Native loader reached corrupt bytes'))
    with pytest.raises(ValueError, match='checksum'):
        load_indexes(database, root)


@pytest.mark.parametrize('field,value', [('model_revision','main'), ('dimension',128), ('corpus_sha256','bad'), ('chunk_sha256','bad'), ('model_assets_sha256','bad')])
def test_identity_mismatch_rejected(bundle, field, value):
    database, root, loaded, _ = bundle
    loaded.manifest['identity'][field] = value
    refresh_manifest(root, loaded)
    with pytest.raises(ValueError, match='active corpus'):
        load_indexes(database, root)


def test_parameter_and_vector_order_mismatch_rejected(bundle):
    database, root, loaded, _ = bundle
    loaded.manifest['config']['ef_search'] = 128
    refresh_manifest(root, loaded)
    with pytest.raises(ValueError, match='HNSW parameter'):
        load_indexes(database, root)
    loaded.manifest['config']['ef_search'] = 64
    refresh_manifest(root, loaded)
    shuffled = loaded.vectors[::-1].copy()
    index = make_index('flat', shuffled, IndexConfig())
    path = loaded.directory / 'all-flat.faiss'
    faiss.write_index(index, str(path))
    loaded.manifest['files']['all-flat.faiss'] = inventory(path)
    refresh_manifest(root, loaded)
    with pytest.raises(ValueError, match='vectors/order'):
        load_indexes(database, root)


def test_stale_chunks_and_projection_rejected(bundle):
    database, root, _, _ = bundle
    with CorpusStore(database) as store:
        store.connection.execute("UPDATE chunks SET text='tampered'")
        store.connection.commit()
    with pytest.raises(ValueError, match='projection'):
        load_indexes(database, root)


def test_failed_build_retains_previous_active_generation(bundle, tmp_path, monkeypatch):
    import backend.indexes as indexes
    database, root, _, _ = bundle
    old = (root / 'active.json').read_bytes()
    monkeypatch.setattr(indexes, 'make_index', lambda *_: (_ for _ in ()).throw(RuntimeError('build failed')))
    with pytest.raises(RuntimeError, match='build failed'):
        build_indexes(database, root, tmp_path / 'embeddings', encoder=Encoder())
    assert (root / 'active.json').read_bytes() == old
    assert load_indexes(database, root).rows


def test_manifest_pointer_path_and_row_tampering(bundle):
    database, root, loaded, _ = bundle
    original = (root / 'active.json').read_bytes()
    write_json(root / 'active.json', {'generation': '../escape', 'manifest_sha256': 'bad'})
    with pytest.raises(ValueError, match='path'):
        load_indexes(database, root)
    (root / 'active.json').write_bytes(original)
    loaded.manifest['partitions']['all']['rows'].reverse()
    refresh_manifest(root, loaded)
    with pytest.raises(ValueError, match='row mapping'):
        load_indexes(database, root)


def test_embedding_cache_reuse_and_checksum(corpus, tmp_path):
    context = current_chunks(corpus)
    encoder = Encoder()
    directory, x, manifest = build_vectors(context, tmp_path / 'vectors', encoder=encoder)
    again, y, _ = build_vectors(context, tmp_path / 'vectors', encoder=encoder)
    assert directory == again and encoder.calls == 1
    np.testing.assert_array_equal(x, y)
    (directory / 'vectors.npy').write_bytes(b'bad')
    with pytest.raises(ValueError, match='checksum'):
        load_vectors(directory, context)


def test_invalid_query_and_request_rejected(bundle):
    _, _, loaded, _ = bundle
    for kwargs in ({'strategy':'bad'}, {'partition':'bad'}, {'top_k':51}, {'top_k':0}):
        with pytest.raises(ValueError):
            loaded.search(loaded.vectors[:1], **kwargs)
    with pytest.raises(ValueError):
        loaded.search(np.zeros((1,384), dtype=np.float32))


def test_runtime_version_mismatch_and_manifest_checksum(bundle, monkeypatch):
    import backend.vector_artifacts as artifacts
    database, root, loaded, _ = bundle
    old = artifacts.versions()
    monkeypatch.setattr(artifacts, 'versions', lambda: {**old, 'numpy': 'different-runtime'})
    with pytest.raises(ValueError, match='active corpus'):
        load_indexes(database, root)
    monkeypatch.setattr(artifacts, 'versions', lambda: old)
    with (loaded.directory / 'manifest.json').open('ab') as stream:
        stream.write(b' ')
    with pytest.raises(ValueError, match='manifest checksum'):
        load_indexes(database, root)


def test_empty_partitions_are_explicitly_skipped(tmp_path, corpus):
    batch, sha = normalize_manifest(ROOT / 'data/manifests/raw-normalizers-v1.json')
    from backend.normalization import Batch
    only_cve = Batch(tuple(d for d in batch.documents if d.source_type == 'cve'))
    database = tmp_path / 'only-cve.sqlite3'
    with CorpusStore(database) as store:
        store.ingest(only_cve, sha)
        persist_chunks(store, Tokenizer())
    root = tmp_path / 'only-indexes'
    build_indexes(database, root, tmp_path / 'only-embeddings', encoder=Encoder())
    loaded = load_indexes(database, root)
    assert loaded.manifest['partitions']['attack']['indexes']['flat'] == {'status': 'skipped', 'reason': 'Empty source partition'}
    with pytest.raises(ValueError, match='Empty source partition'):
        loaded.search(loaded.vectors[:1], partition='attack')


@pytest.mark.parametrize('mismatch', ['metric', 'dimension', 'count'])
def test_native_structure_rejected_even_with_fresh_file_checksum(bundle, mismatch):
    database, root, loaded, _ = bundle
    if mismatch == 'metric':
        bad = faiss.IndexFlatL2(384)
        bad.add(loaded.vectors)
    elif mismatch == 'dimension':
        bad = faiss.IndexFlatIP(383)
        bad.add(loaded.vectors[:, :383].copy())
    else:
        bad = faiss.IndexFlatIP(384)
        bad.add(loaded.vectors[:-1])
    path = loaded.directory / 'all-flat.faiss'
    faiss.write_index(bad, str(path))
    loaded.manifest['files']['all-flat.faiss'] = inventory(path)
    refresh_manifest(root, loaded)
    with pytest.raises(ValueError, match='type/dimension/count/metric'):
        load_indexes(database, root)


def test_validation_report_uses_actual_reload_and_partition_checks(bundle):
    database, root, loaded, _ = bundle
    report = verify_indexes(database, root)
    assert report['reload_search_verified'] and report['reconstructed_vectors_match']
    assert report['count'] == len(loaded.rows)
    assert report['indexes_verified'] == len(loaded.indexes)
    assert report['index_vectors_verified'] == sum(i.ntotal for i in loaded.indexes.values())
    assert report['partitions']['all']['indexes']['ivf']['status'] == 'skipped'


def test_modified_active_model_assets_fail_before_native_loading(bundle, monkeypatch):
    import backend.vector_artifacts as artifacts
    database, root, _, _ = bundle
    def changed_assets():
        raise ValueError('Embedding asset mismatch: model.safetensors')
    monkeypatch.setattr(artifacts, 'verify_assets', changed_assets)
    monkeypatch.setattr(faiss, 'read_index', lambda *_: pytest.fail('Native loader reached mismatched model assets'))
    with pytest.raises(ValueError, match='Embedding asset mismatch'):
        load_indexes(database, root)
