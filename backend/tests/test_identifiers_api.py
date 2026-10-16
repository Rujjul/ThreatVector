"""Deterministic hybrid ranking and actual ASGI /search route checks."""
import pytest
pytest.importorskip('faiss')
from backend.identifiers import extract_identifiers
from backend.main import create_app
from backend.tests.asgi_client import requests
from backend.tests.test_retrieval import service


@pytest.mark.parametrize('query,expected', [
    ('Explain cve-2021-44228 and T1190.',('CVE-2021-44228','T1190')),
    ('T1059.001, ta0001 DS0001 M1047 G0016 S0002 C0001',('T1059.001','TA0001','DS0001','M1047','G0016','S0002','C0001')),
    ('CVE-2021-44228 cve-2021-44228',('CVE-2021-44228',)),
    ('XCVE-2021-44228 T1190X T1059.0019 T1190.1234 CVE-2021-123',()),
    ('(T1190) [CVE-2021-45046]',('T1190','CVE-2021-45046'))])
def test_identifier_boundaries_and_case(query,expected):
    assert extract_identifiers(query)==expected


def test_exact_ids_rank_first_and_semantic_supplements_deduplicate(service):
    loaded,_ = service
    response = loaded.search('Explain t1190 and cve-2021-44228',top_k=50)
    assert {s['status'] for s in response['identifier_lookup']}=={'matched'}
    hits = response['evidence']
    assert hits[0]['document_id']=='attack:T1190'
    assert hits[1]['document_id']=='nvd:CVE-2021-44228'
    assert hits[0]['match_type']==hits[1]['match_type']=='exact_identifier'
    assert hits[0]['matched_identifiers']==['T1190']
    assert any(h['match_type']=='semantic' for h in hits)
    assert len(hits)==len({h['chunk_id'] for h in hits})
    short = loaded.search('T1190 CVE-2021-44228',top_k=1)
    assert len(short['evidence'])==1 and short['evidence'][0]['document_id']=='attack:T1190'


def test_lookup_respects_filters_unknowns_inactive_and_no_aliases(service):
    loaded,_ = service
    result = loaded.search('CVE-2021-44228 T1190 CVE-2099-999999',source_types=['incident'])
    assert all(s['status']=='filtered_out' for s in result['identifier_lookup'])
    assert all(e['source_type']=='incident' and e['match_type']=='semantic' for e in result['evidence'])
    unknown = loaded.search('CVE-2099-999999')
    assert unknown['identifier_lookup'][0]['status']=='not_found'
    assert all(e['match_type']=='semantic' for e in unknown['evidence'])
    empty = loaded.search('T1190',source_types=[])
    assert empty['evidence']==[] and empty['identifier_lookup'][0]['status']=='filtered_out'
    # Legacy mitigation references must not masquerade as canonical techniques.
    assert all(e['document_id']=='attack:T1190' for e in loaded.search('T1190')['evidence'] if e['match_type']=='exact_identifier')


def test_inactive_and_missing_evidence_lookup_states(service):
    from dataclasses import replace
    from backend.identifiers import lookup_identifiers
    loaded,_ = service
    docs = dict(loaded.documents)
    docs['attack:T1190'] = replace(docs['attack:T1190'],active=False)
    _, statuses = lookup_identifiers('T1190',docs,loaded.chunks,None)
    assert statuses[0]['status']=='inactive'
    docs['attack:T1190'] = replace(docs['attack:T1190'],active=True)
    _, statuses = lookup_identifiers('T1190',docs,{},None)
    assert statuses[0]['status']=='no_retrievable_evidence'


def test_api_search_defaults_filters_rankings_and_cleanup(service):
    loaded,_ = service
    validations=[]
    loaded.validate_current=lambda:validations.append(True)
    app=create_app(lambda:loaded)
    results=requests(app,[{'query':'T1190 CVE-2021-44228'},
                          {'query':'CVE-2021-44228','source_types':['incident','attack'],'index':'flat','top_k':50},
                          {'query':'query','source_types':[]}])
    assert all(status==200 for status,_ in results)
    assert results[0][1]['evidence'][0]['document_id']=='attack:T1190'
    assert all(e['source_type'] in ('attack','incident') for e in results[1][1]['evidence'])
    assert results[2][1]['evidence']==[]
    assert len(validations)==2 and app.state.retrieval is None and loaded.model is None


@pytest.mark.parametrize('body',[{}, {'query':''},{'query':' \n'},{'query':'x'*2001},{'query':1},
                                 {'query':'q','top_k':51},{'query':'q','top_k':True},
                                 {'query':'q','top_k':'10'},{'query':'q','index':'bad'},
                                 {'query':'q','source_types':['bad']},{'query':'q','source_types':'cve'},
                                 {'query':'q','database':'private.db'}])
def test_api_bad_requests_never_load_artifacts(body):
    def fail():
        pytest.fail('Invalid request loaded artifacts')
    assert requests(create_app(fail),[body])[0][0]==422


def test_api_artifact_mismatch_missing_dependencies_and_worker_failure(service):
    from backend.indexes import IndexValidationError
    for error in (IndexValidationError('wrong corpus'),FileNotFoundError('missing index'),ImportError('faiss missing')):
        def fail(error=error):
            raise error
        status,body=requests(create_app(fail),[{'query':'query'}])[0]
        assert status==503 and 'evidence' not in body
    loaded,_=service
    loaded.model_factory=lambda:(_ for _ in ()).throw(RuntimeError('worker died'))
    assert requests(create_app(lambda:loaded),[{'query':'query'}])[0][0]==503


def test_api_rejects_changed_artifacts_after_cached_service(service):
    from backend.indexes import IndexValidationError
    loaded,_=service
    loaded.validate_current=lambda:(_ for _ in ()).throw(IndexValidationError('changed artifacts'))
    statuses=[s for s,_ in requests(create_app(lambda:loaded),[{'query':'query'},{'query':'query'}])]
    assert statuses==[200,503]


@pytest.mark.parametrize('identifier', ['T1059','T1059.001','M1051'])
def test_canonical_attack_entity_lookup_and_measured_exact_scores(service,identifier):
    loaded,_=service
    result=loaded.search(identifier,source_types=['attack'],top_k=3)
    first=result['evidence'][0]
    assert first['document_id']=='attack:'+identifier and first['match_type']=='exact_identifier'
    assert first['score']==float(loaded.bundle.vectors[loaded.vector_rows[first['chunk_id']]] @ loaded.bundle.vectors[0])


def test_http_rejects_real_artifact_removed_after_first_request(service):
    loaded,_=service
    original=loaded.search
    def search_then_remove(*args,**kwargs):
        result=original(*args,**kwargs)
        (loaded.bundle.directory/'all-flat.faiss').unlink()
        return result
    loaded.search=search_then_remove
    result=requests(create_app(lambda:loaded),[{'query':'query'},{'query':'query'}])
    assert [status for status,_ in result]==[200,503]
    assert 'evidence' not in result[1][1]


def test_api_model_token_budget_rejects_without_silent_truncation(service):
    loaded,model=service
    status,_=requests(create_app(lambda:loaded),[{'query':'x '*300}])[0]
    assert status==422 and not model.calls


def test_api_invalid_embedding_fails_closed_as_service_error(service):
    import numpy as np
    from types import SimpleNamespace
    loaded,_=service
    loaded.model_factory=lambda:SimpleNamespace(encode_query=lambda _:np.zeros((1,384),dtype=np.float32))
    status,body=requests(create_app(lambda:loaded),[{'query':'query'}])[0]
    assert status==503 and 'evidence' not in body
