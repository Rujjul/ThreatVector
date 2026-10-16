"""Real FAISS filter adversaries and deterministic query-model mocks."""
import itertools
from types import SimpleNamespace

import pytest

faiss = pytest.importorskip('faiss', reason='Install requirements-index.lock for retrieval checks')
import numpy as np

from backend.indexes import IndexBundle, IndexConfig, PARTITIONS, build_indexes, make_index, partition_rows
from backend.retrieval import RetrievalService, SOURCE_TYPES, filtered_search


@pytest.fixture(scope='module', params=('flat', 'ivf', 'hnsw'))
def controlled_bundle(request, tmp_path_factory):
    """Enough vectors for real standard IVF, with CVEs hiding every other type."""
    rows, matrix = [], []
    rng = np.random.default_rng(42)
    for source, count, score in [('cve',2496,.97), ('attack',2496,.7), ('incident',22,.3)]:
        x = rng.normal(size=(count,384)).astype(np.float32)
        rest = x[:, 1:]
        rest /= np.linalg.norm(rest, axis=1, keepdims=True)
        x[:, 0] = score - np.arange(count) * .00001
        rest *= np.sqrt(1 - x[:, :1] ** 2)
        matrix.append(x)
        rows.extend({'chunk_id':f'synthetic:{source}:{i:04}', 'source_type':source} for i in range(count))
    x = np.ascontiguousarray(np.concatenate(matrix))
    indexes, manifest = {}, {'partitions': {}}
    strategy = request.param
    for partition, mapping in partition_rows(rows).items():
        indexes[(partition, strategy)] = make_index(strategy, x[mapping].copy(), IndexConfig(), partition=partition)
        manifest['partitions'][partition] = {'rows': mapping, 'indexes': {strategy: {'status':'ready'}}}
    return IndexBundle(tmp_path_factory.mktemp('retrieval'), manifest, x, rows, indexes), strategy


def query_vector():
    q = np.zeros((1,384), dtype=np.float32)
    q[0,0] = 1
    return q


def test_partition_search_recovers_results_missing_from_global_top_k(controlled_bundle, monkeypatch):
    bundle, strategy = controlled_bundle
    global_hits = bundle.search(query_vector(), strategy, 'all', 10)
    assert not [h for h in global_hits if 'incident' in h['chunk_id']]
    calls = []
    original = bundle.search
    def tracked(q, strategy, partition, top_k):
        calls.append(partition)
        assert partition != 'all', 'Filtered request incorrectly searched the global index'
        return original(q, strategy, partition, top_k)
    monkeypatch.setattr(bundle, 'search', tracked)
    hits = filtered_search(bundle, query_vector(), strategy=strategy, source_types=['incident'])
    assert calls == ['incident'] and len(hits) == 10
    assert all('incident' in h['chunk_id'] for h in hits)


def test_all_source_subsets_merge_local_candidates_and_comparable_scores(controlled_bundle):
    bundle, strategy = controlled_bundle
    for size in range(4):
        for selected in itertools.combinations(SOURCE_TYPES, size):
            candidates = [h for p in selected for h in bundle.search(query_vector(), strategy, p, 10)]
            expected = sorted(candidates, key=lambda h:(-h['score'],h['chunk_id']))[:10]
            actual = filtered_search(bundle, query_vector(), strategy=strategy, source_types=list(selected))
            assert actual == expected
            if strategy == 'flat':
                allowed = [i for i,r in enumerate(bundle.rows) if r['source_type'] in selected]
                brute = sorted(allowed, key=lambda i:(-float(bundle.vectors[i,0]),bundle.rows[i]['chunk_id']))[:10]
                assert [h['chunk_id'] for h in actual] == [bundle.rows[i]['chunk_id'] for i in brute]
    full = filtered_search(bundle, query_vector(), strategy=strategy)
    assert full == sorted(bundle.search(query_vector(),strategy,'all',10), key=lambda h:(-h['score'],h['chunk_id']))


def tiny_bundle():
    rows = [{'chunk_id':'z', 'source_type':'cve'}, {'chunk_id':'a','source_type':'incident'}]
    calls = []
    def search(q, strategy, partition, top_k):
        calls.append(partition)
        return [{'chunk_id':'z','score':.4}, {'chunk_id':'z','score':.5}] if partition == 'cve' else [{'chunk_id':'a','score':.5}]
    parts = {p:{'rows':ids, 'indexes':{'flat':{'status':'ready'}}} for p,ids in partition_rows(rows).items()}
    bundle = SimpleNamespace(rows=rows, manifest={'partitions':parts},
                             indexes={(p,'flat'):object() for p in PARTITIONS}, search=search)
    return bundle, calls


def test_duplicate_filters_and_hits_ties_and_global_cap():
    bundle, calls = tiny_bundle()
    result = filtered_search(bundle, query_vector(), source_types=['incident','cve','incident'])
    assert calls == ['cve','incident']
    assert result == [{'chunk_id':'a','score':.5},{'chunk_id':'z','score':.5}]
    assert len(filtered_search(bundle, query_vector(), source_types=['cve','incident'], top_k=1)) == 1


@pytest.mark.parametrize('kwargs', [{'source_types':['bad']},{'source_types':'cve'},{'source_types':[None]},
                                  {'top_k':0},{'top_k':51},{'top_k':True},{'strategy':'bad'}])
def test_invalid_requests_fail_before_search(kwargs):
    bundle, calls = tiny_bundle()
    with pytest.raises(ValueError):
        filtered_search(bundle, query_vector(), **kwargs)
    assert not calls


def test_empty_and_unavailable_partitions_and_bad_membership(monkeypatch):
    bundle, calls = tiny_bundle()
    assert filtered_search(bundle, query_vector(), source_types=[]) == []
    assert filtered_search(bundle, query_vector(), source_types=['attack']) == []
    assert not calls
    bundle.indexes.pop(('incident','flat'))
    bundle.manifest['partitions']['incident']['indexes']['flat'] = {'status':'skipped','reason':'test unavailable'}
    with pytest.raises(ValueError, match='unavailable'):
        filtered_search(bundle, query_vector(), source_types=['cve','incident'])
    assert not calls, 'Unavailable partition must fail before any partial search'
    monkeypatch.setattr(bundle,'search',lambda *_:[{'chunk_id':'a','score':.5}])
    with pytest.raises(ValueError, match='partition membership'):
        filtered_search(bundle, query_vector(), source_types=['cve'])


@pytest.fixture
def service(tmp_path, monkeypatch):
    import backend.vector_artifacts as artifacts
    from backend.chunking import persist_chunks
    from backend.ingestion import ROOT, normalize_manifest
    from backend.storage import CorpusStore
    from backend.tests.test_chunking import Tokenizer
    from backend.tests.test_indexes import Encoder
    monkeypatch.setattr(artifacts,'verify_assets',lambda:None)
    db = tmp_path / 'db'
    batch, sha = normalize_manifest(ROOT / 'data/manifests/raw-normalizers-v1.json')
    with CorpusStore(db) as store:
        store.ingest(batch,sha)
        persist_chunks(store,Tokenizer())
    directory = tmp_path / 'indexes'
    build_indexes(db,directory,tmp_path/'embeddings',encoder=Encoder())
    model = SimpleNamespace(tokenizer=SimpleNamespace(encode=lambda text,**_:list(range(len(text.split())+2))),max_seq_length=256)
    loaded = RetrievalService.from_database(db,directory,model_factory=lambda:model)
    model.calls = []
    def encode(texts, **kwargs):
        model.calls.append(texts)
        assert kwargs['normalize_embeddings'] and kwargs['convert_to_numpy']
        return loaded.bundle.vectors[:1].copy()
    model.encode = encode
    return loaded, model


def test_text_query_embeds_once_and_returns_traceable_filtered_evidence(service):
    loaded, model = service
    result = loaded.search('vulnerable application',source_types=['incident','attack'],top_k=50)
    assert model.calls == [['vulnerable application']]
    assert result['partitions_searched'] == ['attack','incident']
    assert result['source_types'] == ['attack','incident']
    assert result['evidence'] and all(e['source_type'] in ('attack','incident') for e in result['evidence'])
    for e in result['evidence']:
        doc = loaded.documents[e['document_id']]
        section = next(s for s in doc.sections if s.id == e['section_id'])
        assert e['text'] == section.text[e['char_start']:e['char_end']]
        assert e['url'] == doc.url and e['publication_date'] == doc.publication_date
        assert e['source_snapshot_sha256'] == section.source_snapshot_sha256
    assert result['retrieval_ms'] >= 0 and result['embedding_ms'] >= 0


def test_empty_selection_skips_model_and_invalid_text_or_long_tokens_rejected(service):
    loaded, model = service
    assert loaded.search('valid query',source_types=[])['evidence'] == []
    assert not model.calls and loaded.model is None
    for bad in ('', ' \t', 'x'*2001, None):
        with pytest.raises(ValueError):
            loaded.search(bad)
    with pytest.raises(ValueError, match='token limit'):
        loaded.search('x '*300)
    assert not model.calls


def test_unavailable_ivf_never_silently_falls_back(service):
    loaded, model = service
    with pytest.raises(ValueError, match='ivf unavailable for cve'):
        loaded.search('query',source_types=['cve','incident'],strategy='ivf')
    assert not model.calls and loaded.model is None


def test_worker_adapter_lifecycle_and_invalid_embeddings(service):
    loaded, _ = service
    closed = []
    adapter = SimpleNamespace(encode_query=lambda _:loaded.bundle.vectors[:1].copy(),close=lambda:closed.append(True))
    loaded.model_factory = lambda:adapter
    with loaded:
        assert loaded.search('query',source_types=['incident'])['evidence']
    assert closed == [True] and loaded.model is None
    loaded.model_factory = lambda:SimpleNamespace(encode_query=lambda _:np.zeros((1,384),dtype=np.float32))
    with pytest.raises(ValueError,match='unit-normalized'):
        loaded.search('query')
