"""Isolated, measured FAISS comparisons; no provider or identifier-assisted input."""
import argparse
from contextlib import closing
from dataclasses import asdict
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from time import perf_counter


def document_metrics(ranked, relevant):
    unique=list(dict.fromkeys(ranked))[:10]
    if not relevant:
        return None,None
    return len(set(unique)&set(relevant))/len(set(relevant)), next((1/(i+1) for i,d in enumerate(unique) if d in relevant),0.0)


def configurations():
    from .indexes import IndexConfig
    return [('flat',IndexConfig())]+[
        ('ivf',IndexConfig(nlist=n,nprobe=p)) for n in (64,128,256) for p in (1,4,16,32)
    ]+ [('hnsw',IndexConfig(m=m,ef_search=e)) for m in (16,32) for e in (16,64,128)]


def peak_memory():
    if os.name=='nt':
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)]+[(n,ctypes.c_size_t) for n in (
                'PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
                'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
        counters=Counters();counters.cb=ctypes.sizeof(counters)
        kernel=ctypes.windll.kernel32;psapi=ctypes.windll.psapi
        kernel.GetCurrentProcess.restype=wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
        handle=kernel.GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(handle,ctypes.byref(counters),counters.cb):
            raise RuntimeError('Peak memory measurement unavailable')
        return int(counters.PeakWorkingSetSize)
    import resource
    value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform=='darwin' else value*1024)


def worker(spec_path):
    import faiss
    import numpy as np
    from .indexes import IndexConfig,make_index
    spec=json.loads(Path(spec_path).read_bytes())
    faiss.omp_set_num_threads(1)
    vectors=np.load(spec['vectors'],allow_pickle=False)
    queries=np.load(spec['queries'],allow_pickle=False)
    config=IndexConfig(**spec['config'])
    start=perf_counter(); index=make_index(spec['strategy'],vectors,config,partition='all')
    if index is None:
        raise ValueError('Undertrained or unavailable standard comparison')
    build_seconds=perf_counter()-start
    serialized=np.asarray(faiss.serialize_index(index));size=int(serialized.nbytes)
    reloaded=faiss.deserialize_index(serialized)
    before=index.search(queries,10)[1];after=reloaded.search(queries,10)[1]
    if not np.array_equal(before,after):
        raise ValueError('Benchmark persistence changed results')
    # One warm-up and five timed passes; query embedding/load/build excluded.
    index.search(queries,10)
    durations=[];query_ms=[[] for _ in queries]
    for _ in range(5):
        for i,query in enumerate(queries):
            start=perf_counter(); index.search(query.reshape(1,-1),10)
            elapsed=(perf_counter()-start)*1000
            durations.append(elapsed);query_ms[i].append(elapsed)
    scores,labels=index.search(queries,50)
    report={'index':spec['strategy'],'configuration':spec['config'],
            'configuration_id':spec['configuration_id'],'build_seconds':build_seconds,
            'serialized_bytes':size,'peak_process_bytes':peak_memory(),'memory_scope':'isolated process peak, including imports/vectors/build/search',
            'p50_ms':float(np.percentile(durations,50)),'p95_ms':float(np.percentile(durations,95)),
            'passes':5,'warmup_passes':1,'k_timed':10,'relevance_candidates':50,
            'labels':labels.tolist(),'ann_labels':before.tolist(),'scores':scores.tolist(),'reload_stable':True}
    report['query_ms']=query_ms
    Path(spec['output']).write_text(json.dumps(report)+'\n',encoding='utf-8')


def aggregate(raw, questions, baseline, rows):
    import numpy as np
    recalls=[];rrs=[];ann=[];unsupported=[]
    for i,q in enumerate(questions):
        labels=raw['labels'][i]
        ann_labels=raw.get('ann_labels',raw['labels'])[i]
        ann.append(len(set(ann_labels[:10])&set(baseline[i][:10]))/10)
        recall,rr=document_metrics([rows[j]['document_id'] for j in labels if j>=0],q['relevant_document_ids'])
        if recall is not None:
            recalls.append(recall);rrs.append(rr)
        else:
            unsupported.append({'id':q['id'],'top_score':raw['scores'][i][0]})
    return {'ann_recall_at_10':float(np.mean(ann)),
            'relevance_recall_at_10':float(np.mean(recalls)) if recalls else None,
            'mrr':float(np.mean(rrs)) if rrs else None,'positive_cases':len(recalls),'unsupported_cases':unsupported}


def run(database='data/corpus-v2.sqlite3',output='data/manifests/benchmark-v1.json',*,sweep=True):
    import numpy as np
    import faiss
    from .retrieval import RetrievalService
    from .query_embedding import QueryEncoder
    tuning_raw=Path('evaluation/tuning.json').read_bytes();held_raw=Path('evaluation/held-out.json').read_bytes()
    tuning=json.loads(tuning_raw);held=json.loads(held_raw)
    if tuning['split']!='tuning' or held['split']!='held_out' or any(len(d['questions'])!=30 for d in (tuning,held)):
        raise ValueError('Expected frozen 30/30 splits')
    if {q['question'] for q in tuning['questions']}&{q['question'] for q in held['questions']}:
        raise ValueError('Question leakage between splits')
    with RetrievalService.from_database(database) as retrieval:
        identity=retrieval.bundle.manifest['identity']
        if any(d['corpus_sha256']!=identity['corpus_sha256'] for d in (tuning,held)):
            raise ValueError('Evaluation corpus mismatch')
        for dataset in (tuning,held):
            if len({q['id'] for q in dataset['questions']})!=30:
                raise ValueError('Duplicate evaluation identities')
            for q in dataset['questions']:
                if type(q['supported']) is not bool or q['supported']!=bool(q['relevant_document_ids']):
                    raise ValueError('Invalid support labels')
                for doc_id in q['relevant_document_ids']:
                    doc=retrieval.documents.get(doc_id)
                    if doc is None or not doc.active or q['review']['source_content_sha256']!=doc.content_sha256:
                        raise ValueError('Relevance judgment source mismatch')
        rows=retrieval.bundle.rows
        questions=tuning['questions']+held['questions']
        start=perf_counter()
        with closing(QueryEncoder()) as encoder:
            queries=np.concatenate([encoder.encode_query(q['question']) for q in questions])
        embedding_seconds=perf_counter()-start
        cache=Path('data/benchmark-cache');cache.mkdir(parents=True,exist_ok=True)
        np.save(cache/'queries.npy',queries,allow_pickle=False)
        np.save(cache/'vectors.npy',retrieval.bundle.vectors,allow_pickle=False)
    specs=configurations()
    if not sweep:
        specs=[(s,c) for s,c in specs if (s=='flat' or s=='ivf' and c.nlist==64 and c.nprobe==4 or s=='hnsw' and c.m==16 and c.ef_search==64)]
    measured=[]
    for number,(strategy,config) in enumerate(specs):
        config_id=f'{strategy}-n{config.nlist}-p{config.nprobe}-m{config.m}-ef{config.ef_search}'
        result_path=cache/f'{number}-result.json';spec_path=cache/f'{number}-spec.json'
        spec={'vectors':str(cache/'vectors.npy'),'queries':str(cache/'queries.npy'),'strategy':strategy,
              'config':asdict(config),'configuration_id':config_id,'output':str(result_path)}
        spec_path.write_text(json.dumps(spec),encoding='utf-8')
        print(f'Benchmark {number+1}/{len(specs)}: {config_id}',flush=True)
        subprocess.run([sys.executable,'-m','backend.evaluation','--worker',str(spec_path)],check=True,timeout=1200)
        measured.append(json.loads(result_path.read_bytes()))
    baseline=measured[0]['ann_labels']
    metrics=[];sweeps=[]
    for raw in measured:
        tuning_metrics=aggregate({**raw,'labels':raw['labels'][:30],'ann_labels':raw['ann_labels'][:30],'scores':raw['scores'][:30]},tuning['questions'],baseline[:30],rows)
        held_metrics=aggregate({**raw,'labels':raw['labels'][30:],'ann_labels':raw['ann_labels'][30:],'scores':raw['scores'][30:]},held['questions'],baseline[30:],rows)
        for split_metrics,times in ((tuning_metrics,raw['query_ms'][:30]),(held_metrics,raw['query_ms'][30:])):
            split_metrics.update(p50_ms=float(np.percentile(times,50)),p95_ms=float(np.percentile(times,95)))
        item={k:v for k,v in raw.items() if k not in ('labels','ann_labels','scores','query_ms')}
        item.update(held_metrics);item['tuning_metrics']=tuning_metrics
        sweeps.append(item)
        c=raw['configuration'];s=raw['index']
        if s=='flat' or s=='ivf' and c['nlist']==64 and c['nprobe']==4 or s=='hnsw' and c['m']==16 and c['ef_search']==64:
            metrics.append(item)
    report={'run_id':datetime.now(timezone.utc).strftime('faiss-%Y%m%dT%H%M%SZ'),
            'corpus_hash':identity['corpus_sha256'],'chunk_hash':identity['chunk_sha256'],
            'query_set_hash':hashlib.sha256(tuning_raw+held_raw).hexdigest(),'tuning_hash':hashlib.sha256(tuning_raw).hexdigest(),
            'held_out_hash':hashlib.sha256(held_raw).hexdigest(),'model_revision':identity['model_revision'],'seed':42,'threads':1,
            'hardware':platform.platform()+' / '+platform.processor()+' / logical CPUs '+str(os.cpu_count()),
            'versions':{'python':platform.python_version(),'faiss':faiss.__version__,'numpy':np.__version__},
            'query_embedding_seconds':embedding_seconds,'metrics':metrics,'sweep_metrics':sweeps,
            'embedding_identity':identity,'source_index_manifest_sha256':retrieval.bundle.manifest_sha256,
            'comparison_scope':'Full-corpus pure vector ANN; no identifiers, source filtering or incident-only IVF exception',
            'relevance_scope':'Agent-reviewed target document labels, not exhaustive relevance or independent human review',
            'selection':'Default baseline configurations fixed before held-out evaluation; all sweeps reported, no held-out tuning',
            'build_parameters_sweep_complete':sweep}
    Path(output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    import csv
    columns=['index','configuration_id','ann_recall_at_10','relevance_recall_at_10','mrr','p50_ms','p95_ms','build_seconds','serialized_bytes','peak_process_bytes']
    with Path(output).with_suffix('.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=columns);writer.writeheader()
        writer.writerows({k:m[k] for k in columns} for m in sweeps)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--baseline-only',action='store_true');args=parser.parse_args()
    if args.worker:
        worker(args.worker)
    else:
        report=run(sweep=not args.baseline_only);print(json.dumps({'run_id':report['run_id'],'configurations':len(report['sweep_metrics'])}))
