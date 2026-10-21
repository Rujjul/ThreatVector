from backend.main import create_app
from backend.tests.asgi_client import requests
from backend.tests.test_retrieval import service


def test_readiness_real_counts_and_matching_document_chunks(service):
    retrieval,_=service
    status,health=requests(create_app(lambda:retrieval),[None],path='/health',method='GET')[0]
    assert status==200 and health['corpus_ready'] and health['indexes_ready']
    status,corpus=requests(create_app(lambda:retrieval),[None],path='/corpus',method='GET')[0]
    assert status==200 and sum(corpus['source_counts'].values())==len(retrieval.documents)
    status,doc=requests(create_app(lambda:retrieval),[None],path='/documents/nvd:CVE-2021-44228',method='GET')[0]
    assert status==200 and doc['chunks']
    assert all(c['document_id']==doc['document_id'] and c['text']==retrieval.chunks[c['chunk_id']]['text'] for c in doc['chunks'])
    assert requests(create_app(lambda:retrieval),[None],path='/documents/unknown',method='GET')[0][0]==404


def test_not_ready_does_not_leak_error_or_claim_foundation_success():
    def fail(): raise ValueError('private file')
    _,body=requests(create_app(fail),[None],path='/health',method='GET')[0]
    assert body['status']=='not_ready' and not body['corpus_ready'] and 'private file' not in str(body)
