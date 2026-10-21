import json
from dataclasses import asdict
import pytest
from backend.evaluation import document_metrics,aggregate,configurations,worker


def test_document_recall_and_rr_use_unique_documents_and_exclude_unsupported():
    assert document_metrics(['x','x','b','a'],['a','b'])==(1,1/2)
    assert document_metrics(['x'],[])==(None,None)
    assert document_metrics(['x'],['a'])==(0,0)


def test_ann_and_document_metrics_are_separate_with_unsupported_cases():
    rows=[{'document_id':str(i)} for i in range(60)]
    questions=[{'id':'p','relevant_document_ids':['1']},{'id':'u','relevant_document_ids':[]}]
    labels=[list(range(50)),list(range(50))]
    result=aggregate({'labels':labels,'scores':[[.8]*50,[.4]*50]},questions,labels,rows)
    assert result['ann_recall_at_10']==1 and result['relevance_recall_at_10']==1 and result['mrr']==.5
    assert result['positive_cases']==1 and result['unsupported_cases']==[{'id':'u','top_score':.4}]


def test_standard_sweeps_exclude_incident_single_list():
    pytest.importorskip('faiss')
    configs=configurations()
    assert len(configs)==19
    assert {c.nlist for s,c in configs if s=='ivf'}=={64,128,256}
    assert {c.nprobe for s,c in configs if s=='ivf'}=={1,4,16,32}
    assert len([c for s,c in configs if s=='hnsw'])==6


def test_worker_measures_real_flat_persistence_and_memory(tmp_path):
    pytest.importorskip('faiss')
    import numpy as np
    from backend.indexes import IndexConfig
    rng=np.random.default_rng(42);x=rng.normal(size=(64,384)).astype('float32');x/=np.linalg.norm(x,axis=1,keepdims=True)
    vectors=tmp_path/'x.npy';queries=tmp_path/'q.npy';np.save(vectors,x);np.save(queries,x[:2])
    output=tmp_path/'report.json';spec=tmp_path/'spec.json'
    spec.write_text(json.dumps({'vectors':str(vectors),'queries':str(queries),'config':asdict(IndexConfig()),'strategy':'flat','configuration_id':'flat','output':str(output)}))
    worker(spec)
    report=json.loads(output.read_bytes())
    assert report['reload_stable'] and report['labels'][0][0]==0 and report['labels'][1][0]==1
    assert report['peak_process_bytes']>0 and report['serialized_bytes']>0 and report['build_seconds']>=0
    assert len(report['query_ms'])==2 and all(len(v)==5 for v in report['query_ms'])


def test_full_report_assembly_keeps_metrics_list_and_exports_csv(tmp_path,monkeypatch):
    pytest.importorskip('faiss')
    import numpy as np
    from types import SimpleNamespace as NS
    from backend.indexes import IndexConfig
    from backend.evaluation import run
    monkeypatch.chdir(tmp_path)
    Path=__import__('pathlib').Path
    Path('evaluation').mkdir();Path('data/manifests').mkdir(parents=True)
    for filename,split in [('tuning','tuning'),('held-out','held_out')]:
        questions=[{'id':f'{filename}-{i}','question':f'{filename} question {i}','supported':True,
                    'relevant_document_ids':['doc:0'],'review':{'source_content_sha256':'source'}} for i in range(30)]
        Path(f'evaluation/{filename}.json').write_text(json.dumps({'split':split,'corpus_sha256':'a'*64,'questions':questions}))
    rng=np.random.default_rng(42);vectors=rng.normal(size=(64,384)).astype('float32');vectors/=np.linalg.norm(vectors,axis=1,keepdims=True)
    identity={'corpus_sha256':'a'*64,'chunk_sha256':'b'*64,'model_revision':'c'*40}
    class Retrieval:
        documents={'doc:0':NS(active=True,content_sha256='source')}
        bundle=NS(manifest={'identity':identity},manifest_sha256='d'*64,vectors=vectors,rows=[{'document_id':f'doc:{i}'} for i in range(64)])
        def __enter__(self): return self
        def __exit__(self,*_): pass
    class Encoder:
        def encode_query(self,_): return vectors[:1]
        def close(self): pass
    monkeypatch.setattr('backend.retrieval.RetrievalService.from_database',lambda *_:Retrieval())
    monkeypatch.setattr('backend.query_embedding.QueryEncoder',Encoder)
    monkeypatch.setattr('backend.evaluation.configurations',lambda:[('flat',IndexConfig())])
    monkeypatch.setattr('backend.evaluation.subprocess.run',lambda args,**_:worker(args[-1]))
    result=run(sweep=False)
    assert isinstance(result['metrics'],list) and len(result['metrics'])==1
    assert result['metrics'][0]['ann_recall_at_10']==1
    assert result['metrics'][0]['relevance_recall_at_10']==1
    import csv
    with Path('data/manifests/benchmark-v1.csv').open() as f:
        exported=list(csv.DictReader(f))
    assert len(exported)==1 and exported[0]['index']=='flat'


def test_ann_recall_uses_k10_not_larger_document_candidate_search():
    rows=[{'document_id':str(i)} for i in range(60)]
    raw={'labels':[list(range(50))],'ann_labels':[list(range(10,20))],'scores':[[.8]*50]}
    result=aggregate(raw,[{'id':'q','relevant_document_ids':['1']}],[list(range(10))],rows)
    assert result['ann_recall_at_10']==0 and result['relevance_recall_at_10']==1
