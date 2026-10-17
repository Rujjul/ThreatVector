"""Deterministic correlation and provider boundary checks; no live requests."""
from dataclasses import replace
from urllib.error import HTTPError, URLError
import pytest
from backend.correlation import CorrelationService
from backend.provider import OpenAICompatibleProvider, ProviderConfig, NoRedirect
from backend.storage import CorpusStore
from backend.tests.test_retrieval import service


def correlation(service):
    retrieval, _ = service
    with CorpusStore(retrieval.database) as store:
        batch = store.load()
    return CorrelationService(retrieval,batch), batch


def test_explicit_expansion_separate_from_similarity(service):
    svc, batch = correlation(service)
    result = svc.search('CVE-2021-44228',top_k=1)
    assert result['source_supported_relationships']
    assert result['supporting_evidence']
    assert result['inferred_semantic_associations'] == []
    for rel in result['source_supported_relationships']:
        assert not rel['inferred'] and rel['supporting_chunk_ids']
        assert rel['relationship_type'] in ('mentions_identifier','reports_exploitation_of')
    for hit in result['supporting_evidence']:
        assert hit['score'] is None
        assert hit['text'] == svc.retrieval.chunks[hit['chunk_id']]['text']
    semantic = svc.search('vulnerable application',top_k=3)
    assert semantic['inferred_semantic_associations']
    assert all(a['inferred'] and 'not evidence of exploitation' in a['meaning'] for a in semantic['inferred_semantic_associations'])
    assert len({e['chunk_id'] for e in result['supporting_evidence']}) == len(result['supporting_evidence'])


def test_filters_limits_and_no_transitive_expansion(service):
    svc, _ = correlation(service)
    assert svc.search('CVE-2021-44228',source_types=['cve'],top_k=1)['source_supported_relationships'] == []
    assert svc.search('T1190',source_types=[])['supporting_evidence'] == []
    result = svc.search('CVE-2021-44228',top_k=1,max_relationships=1,max_support_chunks=1)
    assert len(result['source_supported_relationships']) == 1
    assert len(result['supporting_evidence']) <= 1
    assert result['relationships_truncated'] and result['expansion_depth'] == 1
    for value in (0,51,True,'2'):
        with pytest.raises(ValueError):
            svc.search('T1190',max_relationships=value)


def test_inactive_unresolved_inferred_relationships_never_promoted(service):
    svc, _ = correlation(service)
    result = svc.retrieval.search('CVE-2021-44228',top_k=1)
    original = svc.relationships
    for changes in ({'active':False},{'resolved':False},{'inferred':True},{'assertion_active':False}):
        svc.relationships = tuple(replace(r,**changes) for r in original)
        assert svc.expand(result)['source_supported_relationships'] == []


def test_stix_record_support_is_not_fabricated_chunk_support(service):
    svc, _ = correlation(service)
    result = svc.search('T1190',top_k=1)
    stix = [r for r in result['source_supported_relationships'] if r['support']=='explicit_stix_relationship']
    assert stix
    assert all(r['support_kind']=='source_relationship_record' and r['supporting_chunk_ids']==[] and r['provenance'] for r in stix)


def test_correlation_rejects_stale_or_forged_evidence(service):
    svc, batch = correlation(service)
    with pytest.raises(ValueError):
        CorrelationService(svc.retrieval,replace(batch,relationships=()))
    result = svc.retrieval.search('T1190',top_k=1)
    result['corpus_sha256'] = 'bad'
    with pytest.raises(ValueError): svc.expand(result)
    result = svc.retrieval.search('T1190',top_k=1)
    result['evidence'][0]['text'] = 'forged'
    with pytest.raises(ValueError): svc.expand(result)


CONFIG = ProviderConfig('https://provider.invalid/v1/chat/completions','test-model','test-secret')
MESSAGES = [{'role':'system','content':'Return JSON.'},{'role':'user','content':'untrusted text'}]
SCHEMA = {'type':'object','properties':{},'additionalProperties':False}


def test_provider_payload_and_secret_boundary():
    def transport(request,timeout):
        import json
        body = json.loads(request.data)
        assert request.full_url == CONFIG.endpoint and timeout == 60
        assert request.get_header('Authorization') == 'Bearer test-secret'
        assert body['response_format']['json_schema']['schema'] == SCHEMA
        assert body['messages'] == MESSAGES and 'tools' not in body
        assert 'api_key' not in body and 'test-secret' not in repr(CONFIG)
        return {'choices':[{'finish_reason':'stop','message':{'content':'{}'}}]}
    assert OpenAICompatibleProvider(CONFIG,transport=transport).generate(MESSAGES,SCHEMA).content == '{}'
    assert NoRedirect().redirect_request(None,None,None,None,None,None) is None


@pytest.mark.parametrize('config,status',[(ProviderConfig(),'missing_credentials'),(ProviderConfig(api_key='secret'),'not_configured')])
def test_missing_config_never_calls_transport(config,status):
    def forbidden(*_): raise AssertionError('Network attempted')
    assert OpenAICompatibleProvider(config,transport=forbidden).generate(MESSAGES,SCHEMA).status == status


@pytest.mark.parametrize('error,status',[(TimeoutError('secret'),'timeout'),(URLError(TimeoutError()),'timeout'),(URLError('secret'),'provider_error'),(HTTPError('https://secret',401,'secret',{},None),'provider_error')])
def test_provider_errors_are_sanitized(error,status):
    def fail(*_): raise error
    result = OpenAICompatibleProvider(CONFIG,transport=fail).generate(MESSAGES,SCHEMA)
    assert result.status == status and result.content is None
    assert 'secret' not in repr(result)


@pytest.mark.parametrize('response',[{}, {'choices':[]},{'choices':[{'finish_reason':'length','message':{'content':'partial'}}]}, {'choices':[{'finish_reason':'stop','message':{'content':None}}]}, {'choices':[{'finish_reason':'stop','message':{'content':'{}','tool_calls':[{}]}}]}])
def test_malformed_provider_response(response):
    assert OpenAICompatibleProvider(CONFIG,transport=lambda *_:response).generate(MESSAGES,SCHEMA).status == 'invalid_response'


def test_refusal_and_explicit_json_object_mode():
    def transport(request,_):
        import json
        assert json.loads(request.data)['response_format'] == {'type':'json_object'}
        return {'choices':[{'finish_reason':'stop','message':{'refusal':'no'}}]}
    assert OpenAICompatibleProvider(replace(CONFIG,schema_mode='json_object'),transport=transport).generate(MESSAGES,SCHEMA).status == 'refused'


@pytest.mark.parametrize('changes',[{'timeout':0},{'timeout':float('nan')},{'timeout':True},{'endpoint':'http://remote.example/v1/chat/completions'},{'endpoint':'https://key:secret@provider.invalid'},{'endpoint':'https://provider.invalid?key=secret'},{'schema_mode':'unknown'}])
def test_invalid_provider_configuration(changes):
    with pytest.raises(ValueError): replace(CONFIG,**changes)


def test_server_environment(monkeypatch):
    monkeypatch.setenv('THREATVECTOR_PROVIDER_KEY','server-secret')
    monkeypatch.setenv('THREATVECTOR_PROVIDER_TIMEOUT','12')
    cfg = ProviderConfig.from_environment()
    assert cfg.api_key == 'server-secret' and cfg.timeout == 12
    assert 'server-secret' not in repr(cfg)


def test_provider_failure_preserves_correlation_access(service):
    svc, _ = correlation(service)
    before = svc.search('CVE-2021-44228',top_k=1)
    def timeout(*_): raise TimeoutError('not exposed')
    assert OpenAICompatibleProvider(CONFIG,transport=timeout).generate(MESSAGES,SCHEMA).status == 'timeout'
    after = svc.search('CVE-2021-44228',top_k=1)
    assert before['evidence'] == after['evidence']
    assert before['source_supported_relationships'] == after['source_supported_relationships']


def test_transport_enforces_size_json_and_no_redirect(monkeypatch):
    import backend.provider as provider
    from contextlib import nullcontext
    from types import SimpleNamespace
    for payload in (b'not-json', b'x'*2_000_001):
        monkeypatch.setattr(provider,'build_opener',lambda *_:SimpleNamespace(
            open=lambda *args,**kwargs:nullcontext(SimpleNamespace(read=lambda _:payload))))
        assert OpenAICompatibleProvider(CONFIG).generate(MESSAGES,SCHEMA).status == 'invalid_response'
    malformed = {'choices':[{'message':[]}]}
    assert OpenAICompatibleProvider(CONFIG,transport=lambda *_:malformed).generate(MESSAGES,SCHEMA).status == 'invalid_response'
