import json
import pytest
from backend.relevance import choose_threshold,load_policy
from backend.analysis import AnalysisService
from backend.tests.test_analysis import case,valid,Provider


def test_threshold_tunes_only_binary_support_and_prefers_fewer_false_accepts():
    result=choose_threshold([{'score':.8,'supported':True},{'score':.7,'supported':True},{'score':.6,'supported':False}])
    assert result['threshold']==.7 and result['tuning_f1']==1
    with pytest.raises(ValueError): choose_threshold([{'score':.8,'supported':True}])


def test_policy_identity_and_type_validation(tmp_path):
    identity={'corpus_sha256':'a','chunk_sha256':'b','model_revision':'c'}
    report={'version':1,'split':'tuning','question_count':30,'threshold':.6,'identity':identity}
    path=tmp_path/'policy.json';path.write_text(json.dumps(report))
    assert load_policy(identity,path)['threshold']==.6
    for key,value in [('split','held_out'),('threshold',True),('threshold',float('nan')),('version',True),('question_count',True),('identity',{})]:
        changed={**report,key:value};path.write_text(json.dumps(changed))
        assert load_policy(identity,path) is None


def test_semantic_generation_uses_frozen_threshold_without_label_input(case,monkeypatch):
    correlation,result=case
    result['evidence']=[result['evidence'][1]]
    result['supporting_evidence']=[]
    monkeypatch.setattr('backend.analysis.load_policy',lambda _: {'threshold':.6})
    output=valid(case);output['claims'][0].update(text=result['evidence'][0]['text'],citation_chunk_ids=['t'])
    provider=Provider(output)
    response=AnalysisService(correlation,provider).analyze('PowerShell execution')
    assert response['status']=='ok' and response['relevance']['calibrated']
    assert 'relevant_document_ids' not in str(provider.calls)
    monkeypatch.setattr('backend.analysis.load_policy',lambda _: {'threshold':.9})
    response=AnalysisService(correlation,provider).analyze('unrelated')
    assert response['status']=='insufficient_evidence' and len(provider.calls)==1
