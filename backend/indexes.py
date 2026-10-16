"""FAISS strategies and immutable, validated local artifact generations."""
import json
import os
import platform
import re
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import faiss
import numpy as np

from .vector_artifacts import (DIMENSION, SEED, build_vectors, check_file, current_chunks,
                               file_hash, inventory, validate_vectors, write_json)

STRATEGIES = ('flat', 'ivf', 'hnsw')
PARTITIONS = ('all', 'cve', 'attack', 'incident')


@dataclass(frozen=True)
class IndexConfig:
    nlist: int = 64
    nprobe: int = 4
    m: int = 16
    ef_construction: int = 200
    ef_search: int = 64
    seed: int = SEED
    threads: int = 1

    def validate(self):
        if (any(type(v) is not int for v in asdict(self).values())
                or self.nlist not in (64, 128, 256) or not 1 <= self.nprobe <= self.nlist
                or self.m not in (16, 32) or self.ef_construction != 200
                or self.ef_search not in (16, 64, 128) or self.seed != SEED or self.threads != 1):
            raise ValueError('Unsupported FAISS parameters; see BUILD.md')


@contextmanager
def one_thread():
    previous = faiss.omp_get_max_threads()
    faiss.omp_set_num_threads(1)
    try:
        yield
    finally:
        faiss.omp_set_num_threads(previous)


def partition_rows(rows):
    return {name: [i for i, r in enumerate(rows) if name == 'all' or r['source_type'] == name]
            for name in PARTITIONS}


def training_rows(count, config):
    return np.sort(np.random.default_rng(config.seed).choice(count, min(100_000, count), replace=False))


def training_parameters(config):
    return {'seed': config.seed, 'iterations': 25, 'minimum_per_centroid': 39,
            'maximum_sample': 100_000, 'sampling': 'numpy-default_rng-sorted-choice'}


def ivf_configuration(partition, config, *, incident_single_list=True):
    if partition not in PARTITIONS:
        raise ValueError('Unknown source partition')
    reduced = partition == 'incident' and incident_single_list
    return {'nlist': 1 if reduced else config.nlist,
            'nprobe': 1 if reduced else config.nprobe,
            'minimum_per_centroid': 1 if reduced else 39,
            'profile': 'incident_single_list' if reduced else 'standard',
            'standard_benchmark_eligible': not reduced,
            'comparison_group': 'incident_retrieval_only' if reduced else 'standard_ivf'}


def skip_reason(strategy, count, config, *, partition='all', incident_single_list=True):
    if count == 0:
        return 'Empty source partition'
    settings = ivf_configuration(partition, config, incident_single_list=incident_single_list)
    minimum = settings['minimum_per_centroid'] * settings['nlist']
    if strategy == 'ivf' and min(count, 100_000) < minimum:
        return f"Undertrained IVF: {min(count, 100_000)} training vectors; need at least {minimum} ({settings['minimum_per_centroid']} per centroid)"
    return None


def make_index(strategy, vectors, config, *, partition='all'):
    config.validate()
    validate_vectors(vectors, len(vectors))
    if strategy not in STRATEGIES:
        raise ValueError('Unknown index strategy')
    settings = ivf_configuration(partition, config)
    reason = skip_reason(strategy, len(vectors), config, partition=partition)
    if reason:
        raise ValueError(reason)
    with one_thread():
        if strategy == 'flat':
            index = faiss.IndexFlatIP(DIMENSION)
        elif strategy == 'ivf':
            index = faiss.IndexIVFFlat(faiss.IndexFlatIP(DIMENSION), DIMENSION, settings['nlist'], faiss.METRIC_INNER_PRODUCT)
            index.cp.seed = config.seed
            index.cp.niter = 25
            index.cp.min_points_per_centroid = settings['minimum_per_centroid']
            index.cp.max_points_per_centroid = 100_000
            index.train(vectors[training_rows(len(vectors), config)])
            index.nprobe = settings['nprobe']
        else:
            index = faiss.IndexHNSWFlat(DIMENSION, config.m, faiss.METRIC_INNER_PRODUCT)
            index.hnsw.efConstruction = config.ef_construction
            index.hnsw.efSearch = config.ef_search
            index.hnsw.rng = faiss.RandomGenerator(config.seed)
        index.add(vectors)
    return index


def validate_index(index, strategy, vectors, config, *, partition='all', incident_single_list=True):
    expected_types = {'flat': faiss.IndexFlatIP, 'ivf': faiss.IndexIVFFlat, 'hnsw': faiss.IndexHNSWFlat}
    if (type(index) is not expected_types[strategy] or index.d != DIMENSION
            or index.ntotal != len(vectors) or index.metric_type != faiss.METRIC_INNER_PRODUCT
            or not index.is_trained):
        raise ValueError(f'FAISS type/dimension/count/metric mismatch: {strategy}')
    if strategy == 'ivf':
        settings = ivf_configuration(partition, config, incident_single_list=incident_single_list)
        # FAISS does not serialize ClusteringParameters (cp); seed/niter are
        # build provenance in the manifest, not reloadable search parameters.
        if (index.nlist != settings['nlist'] or index.nprobe != settings['nprobe']
                or index.quantizer.metric_type != faiss.METRIC_INNER_PRODUCT
                or type(faiss.downcast_index(index.quantizer)) is not faiss.IndexFlatIP
                or index.quantizer.d != DIMENSION
                or index.quantizer.ntotal != settings['nlist']):
            raise ValueError('IVF parameter mismatch')
    if strategy == 'hnsw':
        if (index.hnsw.nb_neighbors(1) != config.m or index.hnsw.nb_neighbors(0) != 2 * config.m
                or type(faiss.downcast_index(index.storage)) is not faiss.IndexFlatIP
                or index.hnsw.efConstruction != config.ef_construction or index.hnsw.efSearch != config.ef_search):
            raise ValueError('HNSW parameter mismatch')
    if not np.array_equal(index.reconstruct_n(0, len(vectors)), vectors):
        raise ValueError(f'Index vectors/order do not match frozen embeddings: {strategy}')


class IndexBundle:
    def __init__(self, directory, manifest, vectors, rows, indexes):
        self.directory, self.manifest, self.vectors, self.rows, self.indexes = directory, manifest, vectors, rows, indexes

    def benchmark_index(self, strategy, partition='all'):
        """Gate standard comparisons; the incident exception is retrieval-only."""
        if strategy not in STRATEGIES or partition not in PARTITIONS:
            raise ValueError('Invalid strategy or partition')
        entry = self.manifest['partitions'][partition]['indexes'][strategy]
        if strategy == 'ivf' and entry.get('ivf_configuration', {}).get('standard_benchmark_eligible') is False:
            raise ValueError('Incident single-list IVF is excluded from standard benchmark comparisons')
        if (partition, strategy) not in self.indexes:
            raise ValueError(entry['reason'])
        return self.indexes[(partition, strategy)]

    def search(self, query_vector, strategy='flat', partition='all', top_k=10):
        """Low-level vector search; text/identifier retrieval remains separate."""
        if strategy not in STRATEGIES or partition not in PARTITIONS or type(top_k) is not int or not 1 <= top_k <= 50:
            raise ValueError('Invalid strategy, partition or top_k')
        validate_vectors(query_vector, 1)
        key = (partition, strategy)
        if key not in self.indexes:
            raise ValueError(self.manifest['partitions'][partition]['indexes'][strategy]['reason'])
        with one_thread():
            scores, labels = self.indexes[key].search(query_vector, top_k)
        mapping = self.manifest['partitions'][partition]['rows']
        return [{'chunk_id': self.rows[mapping[int(label)]]['chunk_id'], 'score': float(score)}
                for score, label in zip(scores[0], labels[0]) if label >= 0]


def load_directory(directory, context, manifest_sha256):
    """Validate all checksums before native deserialization. Local artifacts only."""
    directory = Path(directory)
    if directory.is_symlink() or (directory / 'manifest.json').is_symlink() or file_hash(directory / 'manifest.json') != manifest_sha256:
        raise ValueError('Index manifest checksum mismatch')
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    if (manifest.get('schema_version') not in (1, 2) or manifest.get('identity') != context.identity
            or manifest.get('faiss_version') != faiss.__version__ or manifest.get('metric') != 'inner_product'
            or manifest.get('count') != len(context.rows)):
        raise ValueError('Index manifest does not match active corpus/embedder/runtime')
    config = IndexConfig(**manifest['config'])
    config.validate()
    reduced_incident = manifest['schema_version'] == 2
    if manifest.get('ivf_training') != training_parameters(config):
        raise ValueError('IVF training provenance mismatch')
    partitions = partition_rows(context.rows)
    if set(manifest['partitions']) != set(PARTITIONS):
        raise ValueError('Source partition mismatch')
    expected_files = {'vectors.npy', 'rows.json'}
    for partition, mapping in partitions.items():
        item = manifest['partitions'][partition]
        if item['rows'] != mapping or set(item['indexes']) != set(STRATEGIES):
            raise ValueError('Partition row mapping or strategy mismatch')
        for strategy in STRATEGIES:
            entry = item['indexes'][strategy]
            reason = skip_reason(strategy, len(mapping), config, partition=partition, incident_single_list=reduced_incident)
            if reduced_incident and strategy == 'ivf' and not reason:
                if entry.get('ivf_configuration') != ivf_configuration(partition, config):
                    raise ValueError('IVF partition configuration/comparison group mismatch')
            if reason:
                if entry != {'status': 'skipped', 'reason': reason}:
                    raise ValueError('Incorrect skipped-index declaration')
            else:
                filename = f'{partition}-{strategy}.faiss'
                if (entry.get('status') != 'ready' or entry.get('file') != filename
                        or entry.get('training_vectors') != (min(100_000, len(mapping)) if strategy == 'ivf' else 0)):
                    raise ValueError('Missing index or invalid filename')
                expected_files.add(filename)
    if set(manifest['files']) != expected_files:
        raise ValueError('Index file inventory mismatch')
    if manifest.get('embedding_files') != {n: manifest['files'][n] for n in ('vectors.npy', 'rows.json')}:
        raise ValueError('Embedding/index snapshot mismatch')
    # Complete checksum pass precedes np.load and especially faiss.read_index.
    for name in expected_files:
        check_file(directory, name, manifest['files'][name])
    rows = json.loads((directory / 'rows.json').read_bytes())
    if rows != list(context.rows):
        raise ValueError('Index chunk-ID mapping mismatch')
    vectors = np.load(directory / 'vectors.npy', allow_pickle=False)
    validate_vectors(vectors, len(rows))
    indexes = {}
    for partition, mapping in partitions.items():
        subset = np.ascontiguousarray(vectors[mapping])
        for strategy in STRATEGIES:
            entry = manifest['partitions'][partition]['indexes'][strategy]
            if entry['status'] == 'ready':
                index = faiss.read_index(str(directory / entry['file']))
                validate_index(index, strategy, subset, config, partition=partition, incident_single_list=reduced_incident)
                indexes[(partition, strategy)] = index
    return IndexBundle(directory, manifest, vectors, rows, indexes)


def load_indexes(database, root='data/indexes'):
    context = current_chunks(database)
    root = Path(root)
    pointer = json.loads((root / 'active.json').read_bytes())
    generation = pointer['generation']
    if not isinstance(generation, str) or not re.fullmatch(r'[a-f0-9]{32}', generation):
        raise ValueError('Invalid active generation path')
    directory = root / generation
    if directory.resolve().parent != root.resolve():
        raise ValueError('Generation escapes artifact directory')
    return load_directory(directory, context, pointer['manifest_sha256'])


def build_indexes(database, root='data/indexes', embedding_root='data/embeddings', config=IndexConfig(), *, encoder=None):
    config.validate()
    context = current_chunks(database)
    start = perf_counter()
    _, vectors, vector_manifest = build_vectors(context, embedding_root, encoder=encoder)
    embedding_seconds = perf_counter() - start
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    generation = uuid.uuid4().hex
    directory = root / generation
    directory.mkdir()
    np.save(directory / 'vectors.npy', vectors, allow_pickle=False)
    write_json(directory / 'rows.json', list(context.rows))
    manifest = {'schema_version': 2, 'identity': context.identity, 'faiss_version': faiss.__version__,
                'metric': 'inner_product', 'count': len(vectors), 'config': asdict(config),
                'created_at': datetime.now(timezone.utc).isoformat(), 'partitions': {},
                'ivf_training': training_parameters(config),
                'embedding_files': vector_manifest['files'], 'embedding_prepare_seconds': embedding_seconds,
                'files': {name: inventory(directory / name) for name in ('vectors.npy', 'rows.json')}}
    probes = {}
    for partition, mapping in partition_rows(context.rows).items():
        subset = np.ascontiguousarray(vectors[mapping])
        item = {'rows': mapping, 'indexes': {}}
        manifest['partitions'][partition] = item
        for strategy in STRATEGIES:
            reason = skip_reason(strategy, len(mapping), config, partition=partition)
            if reason:
                item['indexes'][strategy] = {'status': 'skipped', 'reason': reason}
                continue
            start = perf_counter()
            index = make_index(strategy, subset, config, partition=partition)
            filename = f'{partition}-{strategy}.faiss'
            faiss.write_index(index, str(directory / filename))
            item['indexes'][strategy] = {'status': 'ready', 'file': filename,
                                         'build_seconds': perf_counter() - start,
                                         'training_vectors': min(100_000, len(subset)) if strategy == 'ivf' else 0}
            if strategy == 'ivf':
                item['indexes'][strategy]['ivf_configuration'] = ivf_configuration(partition, config)
            manifest['files'][filename] = inventory(directory / filename)
            with one_thread():
                probes[(partition, strategy)] = index.search(subset[:min(3, len(subset))], min(10, len(subset)))
    write_json(directory / 'manifest.json', manifest)
    sha = file_hash(directory / 'manifest.json')
    bundle = load_directory(directory, context, sha)
    for (partition, strategy), (scores, labels) in probes.items():
        subset = vectors[manifest['partitions'][partition]['rows']]
        with one_thread():
            restored_scores, restored_labels = bundle.indexes[(partition, strategy)].search(subset[:min(3, len(subset))], min(10, len(subset)))
        if not np.array_equal(labels, restored_labels) or not np.allclose(scores, restored_scores, atol=1e-6, rtol=0):
            raise ValueError('Index search changed after persistence')
    # Corpus may have changed during embedding; do not publish stale artifacts.
    if current_chunks(database).identity != context.identity:
        raise ValueError('Corpus/embedder changed during index build')
    pointer = root / ('.active-' + uuid.uuid4().hex + '.json')
    write_json(pointer, {'generation': generation, 'manifest_sha256': sha})
    os.replace(pointer, root / 'active.json')
    return {'generation': generation, 'manifest_sha256': sha, 'corpus_sha256': context.identity['corpus_sha256'],
            'chunk_sha256': context.identity['chunk_sha256'], 'count': len(vectors),
            'indexes_ready': len(bundle.indexes), 'reload_search_verified': True,
            'partitions': {p: {s: e['status'] for s, e in v['indexes'].items()} for p, v in manifest['partitions'].items()}}


def verify_indexes(database, root='data/indexes'):
    bundle = load_indexes(database, root)
    count = 0
    for (partition, strategy), index in bundle.indexes.items():
        mapping = bundle.manifest['partitions'][partition]['rows']
        query = bundle.vectors[mapping[:1]].copy()
        first = bundle.search(query, strategy, partition)
        if not first or first != bundle.search(query, strategy, partition):
            raise ValueError('Repeated search is unstable')
        allowed = {bundle.rows[i]['chunk_id'] for i in mapping}
        if any(hit['chunk_id'] not in allowed or not np.isfinite(hit['score']) for hit in first):
            raise ValueError('Search row mapping or finite-score validation failed')
        entry = bundle.manifest['partitions'][partition]['indexes'][strategy]
        restored = faiss.read_index(str(bundle.directory / entry['file']))
        with one_thread():
            scores, labels = index.search(query, min(10, len(mapping)))
            new_scores, new_labels = restored.search(query, min(10, len(mapping)))
        if not np.array_equal(labels, new_labels) or not np.allclose(scores, new_scores, atol=1e-6, rtol=0):
            raise ValueError('Reload changed search results')
        count += index.ntotal
    manifest = bundle.manifest
    incident_verified = False
    incident_entry = manifest['partitions']['incident']['indexes']['ivf']
    if incident_entry.get('ivf_configuration', {}).get('profile') == 'incident_single_list':
        mapping = manifest['partitions']['incident']['rows']
        queries = bundle.vectors[mapping].copy()
        with one_thread():
            scores, labels = bundle.indexes[('incident', 'ivf')].search(queries, len(mapping))
            flat_scores, flat_labels = bundle.indexes[('incident', 'flat')].search(queries, len(mapping))
        # Compare per-ID scores, allowing equally scored rows to change rank.
        if (not np.array_equal(np.sort(labels, axis=1), np.sort(flat_labels, axis=1))
                or not np.allclose(np.take_along_axis(scores, np.argsort(labels, axis=1), axis=1),
                                   np.take_along_axis(flat_scores, np.argsort(flat_labels, axis=1), axis=1), atol=1e-6, rtol=0)):
            raise ValueError('Incident single-list IVF disagrees with exhaustive Flat search')
        try:
            bundle.benchmark_index('ivf', 'incident')
        except ValueError:
            incident_verified = True
        else:
            raise ValueError('Incident IVF was admitted to standard benchmarks')
    return {'verified_at': datetime.now(timezone.utc).isoformat(),
            'manifest_sha256': file_hash(bundle.directory / 'manifest.json'),
            'identity': manifest['identity'], 'faiss_version': faiss.__version__,
            'platform': platform.platform(), 'config': manifest['config'],
            'metric': manifest['metric'], 'count': len(bundle.rows),
            'indexes_verified': len(bundle.indexes), 'index_vectors_verified': count,
            'file_checksums_verified': True, 'source_row_mapping_verified': True,
            'reconstructed_vectors_match': True, 'repeated_search_verified': True, 'reload_search_verified': True,
            'incident_single_list_flat_equivalence_verified': incident_verified,
            'incident_standard_benchmark_exclusion_verified': incident_verified,
            'embedding_prepare_seconds': manifest['embedding_prepare_seconds'],
            'partitions': {p: {'count': len(v['rows']), 'indexes': v['indexes']}
                           for p, v in manifest['partitions'].items()},
            'scope': 'Artifact integrity, strategy compatibility and persistence validation; not ANN recall, relevance, latency or memory benchmarks'}
