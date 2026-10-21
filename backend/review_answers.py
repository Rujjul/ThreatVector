"""Record actual evidence-only delivery attempts when provider validation is deferred."""
import json
from pathlib import Path
from datetime import datetime,timezone
from backend.analysis import AnalysisService
from backend.correlation import CorrelationService
from backend.retrieval import RetrievalService
from backend.provider import ProviderResult


class DeferredProvider:
    def generate(self,*_): return ProviderResult('missing_credentials')


def record():
    questions=json.loads(Path('evaluation/held-out.json').read_bytes())['questions']
    selected=questions[:6]+questions[6:10]+questions[14:16]+questions[16:20]+questions[26:30]
    reviews=[]
    with RetrievalService.from_database('data/corpus-v2.sqlite3') as retrieval:
        service=AnalysisService(CorrelationService.from_retrieval(retrieval),DeferredProvider())
        for question in selected:
            result=service.analyze(question['question'])
            assert result['claims']==result['mitigations']==result['related_entities']==[]
            assert all(e['text']==retrieval.chunks[e['chunk_id']]['text'] for e in result['evidence'])
            reviews.append({'question_id':question['id'],'category':question['category'],'question':question['question'],
                'status':result['status'],'error':result['generation']['error'],'evidence_chunks':len(result['evidence']),
                'traceability_check':True,'evidence_support':None,'technique_accuracy':None,'mitigation_relevance':None,
                'review_status':'pending_generated_answer','notes':'No generated answer: provider deferred by user; no quality score assigned.'})
    report={'verified_at':datetime.now(timezone.utc).isoformat(),'attempts':reviews,'rated_answers':0,
            'reviewer':'Codex; traceability check only, not independent human answer review',
            'status':'incomplete_provider_deferred','scope':'20 held-out evidence-only attempts; actual generated-answer assessment remains unperformed'}
    Path('data/manifests/answer-review-v1.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'attempts':len(reviews),'rated_answers':0,'status':report['status']}))


if __name__=='__main__': record()
