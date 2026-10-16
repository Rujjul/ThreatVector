"""Partition-first semantic retrieval. Identifier/correlation logic stays separate."""
import json
from copy import deepcopy
from dataclasses import asdict
from time import perf_counter

import numpy as np

from .indexes import PARTITIONS, STRATEGIES, IndexValidationError, load_indexes
from .query_embedding import QueryEncoder
from .storage import CorpusStore, corpus_hash
from .vector_artifacts import validate_vectors
from .retrieval_contract import DEFAULT_TOP_K, validate_top_k

SOURCE_TYPES = PARTITIONS[1:]


def search_partitions(bundle, source_types, strategy, top_k):
    validate_top_k(top_k)
    if strategy not in STRATEGIES:
        raise ValueError('Invalid index or top_k (must be 1–50)')
    if source_types is None:
        requested = ('all',)
    else:
        if not isinstance(source_types, (list, tuple)) or any(type(s) is not str or s not in SOURCE_TYPES for s in source_types):
            raise ValueError('source_types must be a list of cve, attack or incident')
        requested = tuple(s for s in SOURCE_TYPES if s in source_types)
    nonempty = []
    for partition in requested:
        if not bundle.manifest['partitions'][partition]['rows']:
            continue
        entry = bundle.manifest['partitions'][partition]['indexes'].get(strategy, {})
        if (partition, strategy) not in bundle.indexes or entry.get('status') != 'ready':
            reason = entry.get('reason', 'Missing or incomplete selected index')
            raise IndexValidationError(f'{strategy} unavailable for {partition}: {reason}')
        nonempty.append(partition)
    return tuple(nonempty)


def filtered_search(bundle, query_vector, *, source_types=None, strategy='flat', top_k=DEFAULT_TOP_K):
    """Fetch k from each selected partition, merge raw IP scores, deduplicate IDs.

    None selects the full index; [] explicitly selects nothing. No global search
    is performed for explicit filters, including an explicit list of all types.
    """
    partitions = search_partitions(bundle, source_types, strategy, top_k)
    validate_vectors(query_vector, 1)
    row_by_id = {r['chunk_id']: r for r in bundle.rows}
    candidates = {}
    for partition in partitions:
        for hit in bundle.search(query_vector, strategy, partition, top_k):
            row = row_by_id.get(hit['chunk_id'])
            if row is None or (partition != 'all' and row['source_type'] != partition) or not np.isfinite(hit['score']):
                raise ValueError('Index returned invalid partition membership or score')
            old = candidates.get(hit['chunk_id'])
            if old is None or hit['score'] > old['score']:
                candidates[hit['chunk_id']] = {'chunk_id': hit['chunk_id'], 'score': float(hit['score'])}
    return sorted(candidates.values(), key=lambda h: (-h['score'], h['chunk_id']))[:top_k]


class RetrievalService:
    """Immutable evidence snapshot paired with one validated index generation."""
    def __init__(self, bundle, documents, chunks, *, model_factory=None):
        documents, chunks = tuple(documents), deepcopy(list(chunks))
        self.bundle = bundle
        self.documents = {d.id: d for d in documents}
        self.chunks = {c['id']: c for c in chunks}
        self.rows = {r['chunk_id']: r for r in bundle.rows}
        if (len(self.documents) != len(documents) or len(self.chunks) != len(chunks)
                or len(self.rows) != len(bundle.rows) or set(self.rows) != set(self.chunks)):
            raise ValueError('Incomplete or duplicate evidence snapshot')
        for chunk_id, row in self.rows.items():
            chunk = self.chunks[chunk_id]
            doc = self.documents.get(row['document_id'])
            section = next((s for s in doc.sections if s.id == row['section_id']), None) if doc else None
            if (doc is None or not doc.active or section is None or chunk['document_id'] != doc.id
                    or chunk['section_id'] != section.id or row['source_type'] != doc.source_type
                    or not 0 <= chunk['char_start'] < chunk['char_end'] <= len(section.text)
                    or chunk['text'] != section.text[chunk['char_start']:chunk['char_end']]):
                raise ValueError('Mismatched evidence metadata or source offsets')
        self.model_factory = model_factory or QueryEncoder
        self.model = None

    @classmethod
    def from_database(cls, database, directory='data/indexes', *, model_factory=None):
        from .chunking import Chunk, chunk_hash
        bundle = load_indexes(database, directory)
        with CorpusStore(database) as store:
            store.connection.execute('BEGIN')
            batch = store.load()
            chunks = [json.loads(r[0]) for r in store.connection.execute(
                "SELECT payload FROM chunk_details ORDER BY json_extract(payload,'$.document_id'), json_extract(payload,'$.ordinal')")]
            if (corpus_hash(batch) != bundle.manifest['identity']['corpus_sha256']
                    or chunk_hash(tuple(Chunk(**c) for c in chunks)) != bundle.manifest['identity']['chunk_sha256']):
                raise ValueError('Corpus changed while loading retrieval evidence')
        return cls(bundle, batch.documents, chunks, model_factory=model_factory)

    def close(self):
        if self.model is not None and hasattr(self.model, 'close'):
            self.model.close()
        self.model = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def search(self, query, *, source_types=None, strategy='flat', top_k=DEFAULT_TOP_K):
        if not isinstance(query, str) or not query.strip() or len(query) > 2000:
            raise ValueError('Query must be nonblank and at most 2,000 characters')
        partitions = search_partitions(self.bundle, source_types, strategy, top_k)
        embedding_start = perf_counter()
        if partitions:
            if self.model is None:
                self.model = self.model_factory()
            if hasattr(self.model, 'encode_query'):
                vector = self.model.encode_query(query)
            else:
                # In-process deterministic model doubles for automated tests.
                if len(self.model.tokenizer.encode(query, truncation=False)) > self.model.max_seq_length:
                    raise ValueError('Query exceeds the embedding model token limit; shorten the question')
                vector = self.model.encode([query], batch_size=1, normalize_embeddings=True,
                                           convert_to_numpy=True, show_progress_bar=False)
            validate_vectors(vector, 1)
        embedding_ms = (perf_counter() - embedding_start) * 1000 if partitions else 0.0
        start = perf_counter()
        hits = filtered_search(self.bundle, vector, source_types=source_types, strategy=strategy, top_k=top_k) if partitions else []
        evidence = []
        for hit in hits:
            row = self.rows[hit['chunk_id']]
            chunk = self.chunks[hit['chunk_id']]
            document = self.documents[row['document_id']]
            section = next(s for s in document.sections if s.id == chunk['section_id'])
            evidence.append({'chunk_id': hit['chunk_id'], 'document_id': document.id,
                             'source_type': document.source_type, 'source_id': document.source_id,
                             'title': document.title, 'text': chunk['text'], 'url': document.url,
                             'publication_date': document.publication_date, 'score': hit['score'],
                             'section_id': section.id, 'char_start': chunk['char_start'], 'char_end': chunk['char_end'],
                             'source_locator': section.source_locator, 'source_snapshot_sha256': section.source_snapshot_sha256,
                             'attribution': document.attribution, 'source_modified_at': document.source_modified_at,
                             'provenance': [asdict(p) for p in document.provenance],
                             'reuse_review_id': document.reuse_review_id, 'decision_category': document.decision_category,
                             'text_kind': section.text_kind, 'upstream_locator': deepcopy(section.upstream_locator),
                             'token_start': chunk['token_start'], 'token_end': chunk['token_end'],
                             'content_sha256': chunk['content_sha256'], 'tokenizer_revision': chunk['tokenizer_revision']})
        return {'evidence': evidence, 'index': strategy, 'partitions_searched': list(partitions),
                'source_types': None if source_types is None else [s for s in SOURCE_TYPES if s in source_types],
                'embedding_ms': embedding_ms, 'retrieval_ms': (perf_counter() - start) * 1000,
                'corpus_sha256': self.bundle.manifest['identity']['corpus_sha256'],
                'chunk_sha256': self.bundle.manifest['identity']['chunk_sha256'],
                'model_revision': self.bundle.manifest['identity']['model_revision']}
