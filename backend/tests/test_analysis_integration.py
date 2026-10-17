"""Actual stored fixture correlation/retrieval with deterministic generation."""
import json
from backend.analysis import AnalysisService
from backend.correlation import CorrelationService
from backend.provider import ProviderResult
from backend.tests.test_retrieval import service


def test_real_fixture_pipeline_validates_citations_and_preserves_search(service):
    retrieval,_ = service
    correlation = CorrelationService.from_retrieval(retrieval)
    class Extractor:
        def generate(self,messages,schema):
            payload=json.loads(messages[1]['content'])
            chunk=payload['untrusted_evidence'][0]
            assert chunk['match_type']=='exact_identifier'
            return ProviderResult('ok',json.dumps(dict(status='ok',claims=[dict(
                text=chunk['text'],citation_chunk_ids=[chunk['chunk_id']],inferred=False)],
                mitigations=[],related_entities=[],uncertainty=['limited_evidence'],conflicts=[])))
    response=AnalysisService(correlation,Extractor()).analyze('CVE-2021-44228',top_k=1)
    assert response['status']=='ok' and response['source_supported_relationships']
    for claim in response['claims']:
        chunk=retrieval.chunks[claim['citation_chunk_ids'][0]]
        assert claim['text']==chunk['text']
    assert len(response['context_chunk_ids'])<=8
    assert retrieval.search('CVE-2021-44228',top_k=1)['evidence']
