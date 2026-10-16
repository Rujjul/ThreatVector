"""Bounded real-corpus functional filter checks, separate from quality evaluation."""
import itertools
from datetime import datetime, timezone

import numpy as np

from .cli import DEFAULT_DATABASE
from .indexes import STRATEGIES
from .retrieval import SOURCE_TYPES, RetrievalService, filtered_search
from .vector_artifacts import file_hash, write_json


def verify(database=DEFAULT_DATABASE, directory='data/indexes'):
    cases = 0
    with RetrievalService.from_database(database, directory) as service:
        bundle = service.bundle
        # Stored CVE vector is a reproducible functional probe, not a labeled
        # natural-language relevance query. No vectors are regenerated.
        cve_row = bundle.manifest['partitions']['cve']['rows'][0]
        query = bundle.vectors[cve_row:cve_row+1].copy()
        subsets = [list(s) for n in range(4) for s in itertools.combinations(SOURCE_TYPES,n)]
        for strategy in STRATEGIES:
            for selected in [None] + subsets:
                hits = filtered_search(bundle,query,source_types=selected,strategy=strategy,top_k=10)
                partitions = ['all'] if selected is None else selected
                candidates = [h for p in partitions for h in bundle.search(query,strategy,p,10)]
                expected = sorted(candidates,key=lambda h:(-h['score'],h['chunk_id']))[:10]
                if hits != expected:
                    raise ValueError('Partition merge disagrees with independent candidate union')
                allowed = [i for i,r in enumerate(bundle.rows) if selected is None or r['source_type'] in selected]
                if selected is not None and any(service.rows[h['chunk_id']]['source_type'] not in selected for h in hits):
                    raise ValueError('Filter leaked a source type')
                if strategy == 'flat' and allowed:
                    scores = bundle.vectors[allowed] @ query[0]
                    expected_scores = np.sort(scores)[::-1][:10]
                    if not np.allclose([h['score'] for h in hits],expected_scores,atol=1e-6,rtol=0):
                        raise ValueError('Filtered Flat results disagree with exhaustive subset search')
                cases += 1
        global_hits = filtered_search(bundle,query,top_k=10)
        naive = [h for h in global_hits if service.rows[h['chunk_id']]['source_type']=='incident']
        correct = filtered_search(bundle,query,source_types=['incident'],top_k=10)
        if not len(correct) > len(naive):
            raise ValueError('Functional probe did not demonstrate post-filter starvation')
        # One live query is encoded once per strategy in the same persistent
        # worker; this is a bounded compatibility/traceability check only.
        text_checks = []
        for strategy in STRATEGIES:
            result = service.search('Remote code execution in internet-facing applications',
                                    source_types=['attack','incident'],strategy=strategy,top_k=5)
            if not result['evidence'] or any(e['source_type'] not in ('attack','incident') for e in result['evidence']):
                raise ValueError('Text-query filter check failed')
            for e in result['evidence']:
                document = service.documents[e['document_id']]
                section = next(s for s in document.sections if s.id == e['section_id'])
                if (e['text'] != section.text[e['char_start']:e['char_end']]
                        or e['url'] != document.url
                        or e['source_snapshot_sha256'] != section.source_snapshot_sha256):
                    raise ValueError('Text evidence source traceability check failed')
            text_checks.append({'index':strategy,'result_count':len(result['evidence']),
                                'partitions_searched':result['partitions_searched']})
        return {'verified_at':datetime.now(timezone.utc).isoformat(),
                'index_manifest_sha256':file_hash(bundle.directory/'manifest.json'),
                'corpus_sha256':bundle.manifest['identity']['corpus_sha256'],
                'chunk_sha256':bundle.manifest['identity']['chunk_sha256'],
                'model_revision':bundle.manifest['identity']['model_revision'],
                'filter_cases_verified':cases,'flat_exhaustive_subset_scores_verified':True,
                'text_evidence_source_offsets_verified':True,
                'naive_incident_count_from_global_top_10':len(naive),
                'partition_incident_count':len(correct),'query_probe_chunk_id':bundle.rows[cve_row]['chunk_id'],
                'text_query_checks':text_checks,
                'scope':'Functional partition/merge/source-traceability checks, not relevance, ANN recall or latency benchmarks'}


if __name__ == '__main__':
    import json
    report = verify()
    write_json('data/manifests/filtered-retrieval-validation-v1.json',report)
    print(json.dumps(report,indent=2))
