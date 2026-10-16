"""Bounded live safeguards check; artifact rejection probes never modify active files."""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from .cli import DEFAULT_DATABASE
from .indexes import STRATEGIES, IndexValidationError, load_directory
from .retrieval import RetrievalService, filtered_search
from .vector_artifacts import file_hash, write_json


def verify(database=DEFAULT_DATABASE, directory='data/indexes'):
    cases = []
    with RetrievalService.from_database(database,directory) as service:
        query = 'Remote code execution in internet-facing applications'
        service.search(query)  # One actual default query, followed by score checks.
        vector = service.model.encode_query(query)
        for strategy in STRATEGIES:
            for top_k in (10,50):
                kwargs = {} if top_k==10 else {'top_k':top_k}
                result = service.search(query,strategy=strategy,**kwargs)
                expected = {h['chunk_id']:h['score'] for h in filtered_search(service.bundle,vector,strategy=strategy,top_k=top_k)}
                hits = result['evidence']
                if len(hits)!=len({e['chunk_id'] for e in hits}) or len(hits)!=top_k:
                    raise ValueError('Default/maximum cap or deduplication check failed')
                for e in hits:
                    d = service.documents[e['document_id']]
                    c = service.chunks[e['chunk_id']]
                    s = next(s for s in d.sections if s.id==e['section_id'])
                    if (e['score']!=expected[e['chunk_id']] or e['text']!=s.text[e['char_start']:e['char_end']]
                            or e['source_id']!=d.source_id or e['url']!=d.url or e['publication_date']!=d.publication_date
                            or e['source_modified_at']!=d.source_modified_at or e['attribution']!=d.attribution
                            or e['provenance']!=[asdict(p) for p in d.provenance]
                            or e['upstream_locator']!=s.upstream_locator
                            or any(e[key]!=c[key] for key in ('token_start','token_end','content_sha256','tokenizer_revision'))):
                        raise ValueError('Evidence metadata, offsets, score or provenance changed')
                cases.append({'index':strategy,'top_k':top_k,'result_count':len(hits)})
        for bad in (0,51,True,None,10.5):
            try:
                service.search(query,top_k=bad)
            except ValueError:
                pass
            else:
                raise ValueError('Invalid top_k was accepted')
        # Only trusted project manifests are copied into isolated probe folders.
        rejected = []
        context = SimpleNamespace(identity=service.bundle.manifest['identity'],rows=service.bundle.rows)
        for kind in ('mismatched_corpus','incomplete_strategy','missing_artifact_files'):
            with TemporaryDirectory(prefix='safeguard-probe-',dir='data') as probe:
                probe = Path(probe).resolve()
                if probe.parent != Path('data').resolve():
                    raise ValueError('Probe directory escaped workspace data')
                manifest = deepcopy(service.bundle.manifest)
                if kind=='mismatched_corpus':
                    manifest['identity']['corpus_sha256'] = 'synthetic-invalid-hash'
                elif kind=='incomplete_strategy':
                    manifest['partitions']['all']['indexes'].pop('hnsw')
                write_json(probe/'manifest.json',manifest)
                try:
                    load_directory(probe,context,file_hash(probe/'manifest.json'))
                except IndexValidationError:
                    rejected.append(kind)
                else:
                    raise ValueError('Invalid/incomplete artifact probe was accepted')
        return {'verified_at':datetime.now(timezone.utc).isoformat(),
                'index_manifest_sha256':file_hash(service.bundle.directory/'manifest.json'),
                'corpus_sha256':service.bundle.manifest['identity']['corpus_sha256'],
                'chunk_sha256':service.bundle.manifest['identity']['chunk_sha256'],
                'default_top_k':10,'max_top_k':50,'result_cases':cases,
                'unique_chunk_ids_verified':True,'raw_scores_preserved':True,
                'evidence_metadata_and_provenance_preserved':True,'invalid_top_k_rejected':True,
                'artifact_rejection_probes':rejected,
                'scope':'Retrieval safeguards and artifact rejection checks, not relevance or performance benchmarks'}


if __name__=='__main__':
    import json
    report = verify()
    write_json('data/manifests/retrieval-safeguards-validation-v1.json',report)
    print(json.dumps(report,indent=2))
