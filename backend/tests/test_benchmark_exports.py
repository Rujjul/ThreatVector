from copy import deepcopy
import json
from backend.benchmark_exports import load_runs
from backend.tests.asgi_client import requests
from backend.main import create_app


def saved():
    return {'run_id':'fixture','corpus_hash':'a'*64,'query_set_hash':'b'*64,'model_revision':'c'*40,'seed':42,'threads':1,
            'hardware':'fixture CPU','versions':{'python':'test'},'metrics':[dict(index=s,ann_recall_at_10=1.,
            relevance_recall_at_10=.5,mrr=.25,p50_ms=.1,p95_ms=.2,build_seconds=.3,serialized_bytes=100,peak_process_bytes=1000)
            for s in ('flat','ivf','hnsw')]}


def test_saved_benchmarks_are_loaded_without_running_experiments(tmp_path):
    raw=saved();(tmp_path/'benchmark-v1.json').write_text(json.dumps(raw))
    status,body=requests(create_app(benchmark_directory=tmp_path),[None],path='/benchmarks',method='GET')[0]
    assert status==200 and body['runs']==[raw] and body['errors']==[]


def test_corrupt_and_nonfinite_measurements_are_not_presented_as_results(tmp_path):
    path=tmp_path/'benchmark-v1.json'
    for change in ('nan','bad_hash','negative','duplicate'):
        raw=deepcopy(saved())
        if change=='nan': raw['metrics'][0]['p95_ms']=float('nan')
        elif change=='bad_hash': raw['corpus_hash']='unknown'
        elif change=='negative': raw['metrics'][0]['peak_process_bytes']=-1
        else: raw['metrics'][1]['index']='flat'
        path.write_text(json.dumps(raw))
        result=load_runs(tmp_path)
        assert result['runs']==[] and result['errors']
