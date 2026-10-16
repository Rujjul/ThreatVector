"""Bounded localhost HTTP acceptance checks against existing Phase-2 artifacts."""
import json
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

import uvicorn

from .main import create_app
from .indexes import verify_indexes
from .cli import DEFAULT_DATABASE
from .vector_artifacts import write_json


def verify():
    artifacts = verify_indexes(DEFAULT_DATABASE)
    application = create_app()
    listener = socket.socket()
    listener.bind(('127.0.0.1',0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(application,host='127.0.0.1',port=port,log_level='warning'))
    thread = threading.Thread(target=lambda:server.run(sockets=[listener]),daemon=True)
    thread.start()
    deadline = time.monotonic()+20
    while not server.started and thread.is_alive() and time.monotonic()<deadline:
        time.sleep(.05)
    if not server.started:
        server.should_exit = True
        listener.close()
        raise RuntimeError('Local search API did not start')
    opener = build_opener(ProxyHandler({}))
    cases = [
        ('semantic',{'query':'remote code execution'},200),
        ('cve',{'query':'cve-2021-44228'},200),
        ('subtechnique',{'query':'T1059.001','source_types':['attack'],'index':'hnsw'},200),
        ('multi_identifier',{'query':'CVE-2021-44228 T1190','source_types':['cve','attack'],'index':'ivf'},200),
        ('missing_identifier',{'query':'CVE-2099-999999','source_types':['cve']},200),
        ('filtered_identifier',{'query':'CVE-2021-44228','source_types':['incident']},200),
        ('empty',{'query':'T1190','source_types':[]},200),
        ('duplicate_id_cap',{'query':'t1059.001 T1059.001','top_k':1},200),
        ('maximum',{'query':'remote code execution','source_types':['attack','incident'],'top_k':50},200),
        ('bad_cap',{'query':'q','top_k':51},422),
        ('bad_source',{'query':'q','source_types':['private']},422),
        ('blank',{'query':' \n'},422),
        ('bad_index',{'query':'q','index':'other'},422),
        ('extra_field',{'query':'q','database':'other.db'},422),
        ('token_limit',{'query':'x '*300},422)]
    results = []
    try:
        for name,body,expected in cases:
            request = Request(f'http://127.0.0.1:{port}/search',data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
            try:
                response = opener.open(request,timeout=90)
            except HTTPError as exc:
                response = exc
            with response:
                status, payload = response.status,json.loads(response.read())
            if status!=expected:
                raise ValueError(f'HTTP check {name} returned {status}, expected {expected}: {payload}')
            if status==200:
                evidence = payload['evidence']
                if len(evidence)>body.get('top_k',10) or len(evidence)!=len({e['chunk_id'] for e in evidence}):
                    raise ValueError('HTTP cap/deduplication failed')
                if 'source_types' in body and any(e['source_type'] not in body['source_types'] for e in evidence):
                    raise ValueError('HTTP source filter failed')
                if name in ('cve','subtechnique','multi_identifier','duplicate_id_cap'):
                    if not evidence or evidence[0]['match_type']!='exact_identifier' or any(s['status']!='matched' for s in payload['identifier_lookup']):
                        raise ValueError('HTTP exact identifier priority failed')
                if name=='missing_identifier' and payload['identifier_lookup'][0]['status']!='not_found':
                    raise ValueError('Unknown ID was not distinguished')
                if name=='filtered_identifier' and payload['identifier_lookup'][0]['status']!='filtered_out':
                    raise ValueError('Identifier lookup bypassed a source filter')
                if name=='empty' and evidence:
                    raise ValueError('Empty selection returned evidence')
                if name=='maximum' and len(evidence)!=50:
                    raise ValueError('50-result search failed')
                for e in evidence:
                    service = application.state.retrieval
                    doc = service.documents[e['document_id']]
                    section = next(s for s in doc.sections if s.id==e['section_id'])
                    if e['text']!=section.text[e['char_start']:e['char_end']] or e['url']!=doc.url:
                        raise ValueError('HTTP evidence lost source traceability')
                results.append({'case':name,'status':status,'results':len(evidence),
                                'identifier_lookup':payload['identifier_lookup'],'partitions_searched':payload['partitions_searched']})
            else:
                results.append({'case':name,'status':status})
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        listener.close()
        if thread.is_alive():
            raise RuntimeError('Local search API did not shut down cleanly')
    return {'verified_at':datetime.now(timezone.utc).isoformat(),
            'index_manifest_sha256':artifacts['manifest_sha256'],
            'corpus_sha256':artifacts['identity']['corpus_sha256'],
            'chunk_sha256':artifacts['identity']['chunk_sha256'],
            'model_revision':artifacts['identity']['model_revision'],
            'indexes_verified':artifacts['indexes_verified'],'indexed_vectors_verified':artifacts['index_vectors_verified'],
            'index_reload_stable':artifacts['reload_search_verified'],'http_cases':results,
            'evidence_traceability_verified':True,'clean_shutdown':True,
            'scope':'Phase-2 functional HTTP/artifact acceptance only; no later phases, relevance or performance benchmarks'}


if __name__=='__main__':
    report = verify()
    write_json('data/manifests/phase2-acceptance-v1.json',report)
    print(json.dumps(report,indent=2))
