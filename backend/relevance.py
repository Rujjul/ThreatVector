"""Tuning-only relevance calibration, bound to an immutable artifact identity."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path

POLICY = Path('data/manifests/relevance-policy-v1.json')
IDENTITY_KEYS = ('corpus_sha256','chunk_sha256','model_revision')


def choose_threshold(observations):
    if not observations or {o['supported'] for o in observations}!={False,True}:
        raise ValueError('Calibration needs positive and unsupported tuning cases')
    candidates=sorted({o['score'] for o in observations})
    candidates.append(math.nextafter(max(candidates),math.inf))
    rows=[]
    for threshold in candidates:
        tp=sum(o['supported'] and o['score']>=threshold for o in observations)
        fp=sum(not o['supported'] and o['score']>=threshold for o in observations)
        fn=sum(o['supported'] and o['score']<threshold for o in observations)
        f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0
        rows.append((f1,-fp,threshold,tp,fp,fn))
    f1,_,threshold,tp,fp,fn=max(rows)
    return {'threshold':threshold,'tuning_f1':f1,'true_positive':tp,'false_positive':fp,'false_negative':fn}


def load_policy(identity, path=POLICY):
    try:
        policy=json.loads(Path(path).read_bytes())
        threshold=policy['threshold']
        if (type(policy['version']) is not int or policy['version']!=1 or policy['split']!='tuning'
                or type(policy['question_count']) is not int or policy['question_count']!=30
                or type(threshold) not in (float,int) or not math.isfinite(threshold) or not -1<=threshold<=1
                or policy['identity']!={k:identity[k] for k in IDENTITY_KEYS}):
            return None
        return policy
    except (OSError,ValueError,KeyError,TypeError):
        return None


def calibrate(database='data/corpus-v2.sqlite3',questions='evaluation/tuning.json',output=POLICY):
    from .retrieval import RetrievalService
    raw=Path(questions).read_bytes(); dataset=json.loads(raw)
    if dataset['split']!='tuning' or len(dataset['questions'])!=30:
        raise ValueError('Only the 30-question tuning split may calibrate relevance')
    with RetrievalService.from_database(database) as retrieval:
        identity=retrieval.bundle.manifest['identity']
        if dataset['corpus_sha256']!=identity['corpus_sha256']:
            raise ValueError('Question corpus mismatch')
        observations=[]
        for q in dataset['questions']:
            response=retrieval.search(q['question'],top_k=10)
            # Scores only: identifier boosting/partition filters never calibrate
            # the semantic threshold. Use actual local query embeddings and Flat.
            vector=retrieval.model.encode_query(q['question'])
            hits=retrieval.bundle.search(vector,'flat','all',10)
            observations.append({'id':q['id'],'supported':q['supported'],'score':hits[0]['score'],
                                 'target_in_top10':any(retrieval.chunks[h['chunk_id']]['document_id'] in q['relevant_document_ids'] for h in hits)})
        report={'version':1,'split':'tuning','question_count':30,
                'identity':{k:identity[k] for k in IDENTITY_KEYS},'query_set_sha256':hashlib.sha256(raw).hexdigest(),
                'verified_at':datetime.now(timezone.utc).isoformat(),**choose_threshold(observations),
                'observations':observations,'review_method':'agent_source_inspection; not independent human review',
                'scope':'Binary tuning support heuristic, not calibrated probability or held-out quality claim'}
    Path(output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report


if __name__=='__main__':
    print(json.dumps(calibrate(),indent=2))
