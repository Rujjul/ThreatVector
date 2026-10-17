"""Bounded one-hop source relationships, separate from query similarity."""
from copy import deepcopy
from dataclasses import asdict

from .storage import CorpusStore, corpus_hash


class CorrelationService:
    def __init__(self, retrieval, batch):
        if corpus_hash(batch) != retrieval.bundle.manifest['identity']['corpus_sha256']:
            raise ValueError('Correlation corpus does not match retrieval snapshot')
        self.retrieval = retrieval
        self.relationships = tuple(sorted(batch.relationships, key=lambda r:r.id))

    @classmethod
    def from_retrieval(cls, retrieval):
        retrieval.validate_current()
        with CorpusStore(retrieval.database) as store:
            return cls(retrieval, store.load())

    def search(self, query, *, source_types=None, strategy='flat', top_k=10,
               max_relationships=50, max_support_chunks=50):
        result = self.retrieval.search(query, source_types=source_types, strategy=strategy, top_k=top_k)
        return self.expand(result, max_relationships=max_relationships, max_support_chunks=max_support_chunks)

    def expand(self, result, *, max_relationships=50, max_support_chunks=50):
        for value in (max_relationships, max_support_chunks):
            if type(value) is not int or not 1 <= value <= 50:
                raise ValueError('Correlation bounds must be integers from 1 to 50')
        for key in ('corpus_sha256', 'chunk_sha256', 'model_revision'):
            if result[key] != self.retrieval.bundle.manifest['identity'][key]:
                raise ValueError('Correlation retrieval identity mismatch')
        docs, chunks = self.retrieval.documents, self.retrieval.chunks
        allowed = set(result['source_types'] if result['source_types'] is not None else ('cve','attack','incident'))
        seeds, associations = set(), []
        for hit in result['evidence']:
            chunk = chunks.get(hit['chunk_id'])
            if chunk is None or chunk['document_id'] != hit['document_id'] or chunk['text'] != hit['text']:
                raise ValueError('Correlation evidence mismatch')
            if docs[chunk['document_id']].source_type not in allowed:
                raise ValueError('Correlation source filter mismatch')
            seeds.add(chunk['document_id'])
            if hit['match_type'] == 'semantic':
                associations.append({'document_id':hit['document_id'], 'chunk_id':hit['chunk_id'],
                                     'score':hit['score'], 'inferred':True,
                                     'basis':'query_semantic_similarity',
                                     'meaning':'Similarity is not evidence of exploitation or a source relationship.'})
        relations, support, seen = [], [], set()
        eligible = []
        for rel in self.relationships:
            endpoints = (rel.source_document_id, rel.target_document_id)
            if (not seeds.intersection(endpoints) or not rel.active or not rel.resolved
                    or not rel.assertion_active or rel.inferred or not rel.provenance
                    or rel.support not in ('explicit_stix_relationship','explicit_identifier_occurrence','caller_reviewed_source_annotation')
                    or not all(d in docs and docs[d].active and docs[d].source_type in allowed for d in endpoints)):
                continue
            if rel.evidence_document_id is not None:
                doc = docs.get(rel.evidence_document_id)
                if doc is None or not doc.active or doc.source_type not in allowed:
                    continue
                if rel.evidence_section_id not in {s.id for s in doc.sections}:
                    raise ValueError('Relationship supporting section mismatch')
            eligible.append(rel)
        for rel in eligible[:max_relationships]:
            candidates = sorted((c for c in chunks.values()
                                 if c['document_id'] == rel.evidence_document_id
                                 and c['section_id'] == rel.evidence_section_id), key=lambda c:(c['ordinal'],c['id']))
            ids = []
            for chunk in candidates:
                if chunk['id'] not in seen and len(support) < max_support_chunks:
                    doc = docs[chunk['document_id']]
                    section = next(s for s in doc.sections if s.id == chunk['section_id'])
                    support.append({**deepcopy(chunk), 'chunk_id':chunk['id'], 'source_type':doc.source_type,
                                    'source_id':doc.source_id, 'title':doc.title, 'url':doc.url,
                                    'publication_date':doc.publication_date, 'score':None,
                                    'match_type':'explicit_relationship_support',
                                    'source_locator':section.source_locator,
                                    'source_snapshot_sha256':section.source_snapshot_sha256,
                                    'attribution':doc.attribution, 'provenance':[asdict(p) for p in doc.provenance],
                                    'source_modified_at':doc.source_modified_at, 'reuse_review_id':doc.reuse_review_id,
                                    'decision_category':doc.decision_category, 'text_kind':section.text_kind,
                                    'upstream_locator':deepcopy(section.upstream_locator)})
                    seen.add(chunk['id'])
                if chunk['id'] in seen:
                    ids.append(chunk['id'])
            relations.append({**asdict(rel), 'inferred':False, 'supporting_chunk_ids':ids,
                              'support_kind':'section_chunks' if ids else 'source_relationship_record',
                              'support_chunks_truncated':len(ids)<len(candidates)})
        return {**deepcopy(result), 'source_supported_relationships':relations,
                'inferred_semantic_associations':associations, 'supporting_evidence':support,
                'relationships_truncated':len(eligible)>max_relationships,
                'expansion_depth':1}
