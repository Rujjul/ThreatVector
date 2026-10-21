"""Local retrieval and evidence-preserving analysis HTTP application."""
import os
import sqlite3
import threading
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator
from .retrieval_contract import DEFAULT_TOP_K, MAX_TOP_K


class SearchRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')
    query: StrictStr = Field(min_length=1,max_length=2000)
    index: Literal['flat','ivf','hnsw'] = 'flat'
    source_types: list[Literal['cve','attack','incident']] | None = None
    top_k: StrictInt = Field(default=DEFAULT_TOP_K,ge=1,le=MAX_TOP_K)

    @field_validator('query')
    @classmethod
    def nonblank(cls,value):
        if not value.strip():
            raise ValueError('Query must be nonblank')
        return value


def default_service():
    from .retrieval import RetrievalService
    return RetrievalService.from_database(os.environ.get('THREATVECTOR_DATABASE','data/corpus-v2.sqlite3'),
                                         os.environ.get('THREATVECTOR_INDEX_DIRECTORY','data/indexes'))


def create_app(service_factory=None, *, provider=None, benchmark_directory='data/manifests'):
    lock = threading.RLock()
    @asynccontextmanager
    async def lifespan(app):
        yield
        with lock:
            if app.state.retrieval is not None:
                app.state.retrieval.close()
                app.state.retrieval = None
    application = FastAPI(title='ThreatVector',version='0.2.0',lifespan=lifespan)
    application.state.retrieval = None
    application.add_middleware(CORSMiddleware,allow_origins=['http://127.0.0.1:5173','http://localhost:5173'],
                              allow_methods=['GET','POST'],allow_headers=['Content-Type'])

    def execute(request, *, analyze=False):
        # Serialize lazy initialization and worker use; never create duplicate
        # workers on concurrent first requests. Validate artifacts before reuse.
        with lock:
            try:
                if application.state.retrieval is None:
                    application.state.retrieval = (service_factory or default_service)()
                else:
                    application.state.retrieval.validate_current()
            except (ValueError,OSError,ImportError,RuntimeError,sqlite3.Error) as exc:
                if application.state.retrieval is not None:
                    application.state.retrieval.close()
                    application.state.retrieval = None
                raise HTTPException(503,'Search unavailable: verify the corpus and index artifacts, then retry.') from exc
            try:
                if analyze:
                    from .analysis import AnalysisService
                    from .correlation import CorrelationService
                    correlation = CorrelationService.from_retrieval(application.state.retrieval)
                    return AnalysisService(correlation,provider).analyze(request.query,strategy=request.index,
                                                                        source_types=request.source_types,top_k=request.top_k)
                return application.state.retrieval.search(request.query,strategy=request.index,
                                                          source_types=request.source_types,top_k=request.top_k)
            except ValueError as exc:
                from .indexes import IndexValidationError
                if isinstance(exc,IndexValidationError):
                    raise HTTPException(503,'Selected search index is unavailable or invalid.') from exc
                if str(exc).startswith('Query '):
                    raise HTTPException(422,str(exc)) from exc
                application.state.retrieval.close()
                application.state.retrieval = None
                raise HTTPException(503,'Search failed validation; verify local retrieval artifacts.') from exc
            except (RuntimeError,OSError) as exc:
                application.state.retrieval.close()
                application.state.retrieval = None
                raise HTTPException(503,'Local query embedding failed; retry the search.') from exc

    @application.post('/search')
    def search(request: SearchRequest):
        return execute(request)

    @application.post('/analyze')
    def analyze(request: SearchRequest):
        return execute(request,analyze=True)

    def snapshot():
        try:
            if application.state.retrieval is None:
                application.state.retrieval=(service_factory or default_service)()
            else:
                application.state.retrieval.validate_current()
            return application.state.retrieval
        except (ValueError,OSError,ImportError,RuntimeError,sqlite3.Error) as exc:
            if application.state.retrieval is not None:
                application.state.retrieval.close()
                application.state.retrieval=None
            raise HTTPException(503,'Local corpus/index artifacts are unavailable or invalid.') from exc

    @application.get('/health')
    def readiness():
        with lock:
            try:
                snapshot()
                ready=True
            except HTTPException:
                ready=False
            from .provider import ProviderConfig
            try:
                config=ProviderConfig.from_environment()
                configured=bool(config.api_key.strip() and config.model.strip() and config.endpoint.strip())
            except ValueError:
                configured=False
            return {'status':'ready' if ready and configured else 'retrieval_ready' if ready else 'not_ready',
                    'corpus_ready':ready,'indexes_ready':ready,'provider_configured':configured}

    @application.get('/corpus')
    def corpus_metadata():
        with lock:
            service=snapshot()
            return {'source_counts':{source:sum(d.source_type==source for d in service.documents.values())
                                     for source in ('cve','attack','incident')},
                    'active_document_count':sum(d.active for d in service.documents.values()),
                    'chunk_count':len(service.chunks),'snapshot_id':service.bundle.manifest['identity']['corpus_sha256'],
                    'active_artifacts':{'generation':service.bundle.directory.name,
                                        'manifest_sha256':service.bundle.manifest_sha256,
                                        'identity':service.bundle.manifest['identity']}}

    @application.get('/documents/{document_id:path}')
    def document_detail(document_id: str):
        with lock:
            service=snapshot()
            doc=service.documents.get(document_id)
            if doc is None:
                raise HTTPException(404,'Document not found')
            chunks=[]
            for chunk in sorted(service.chunks.values(),key=lambda c:c['ordinal']):
                if chunk['document_id']!=doc.id:
                    continue
                chunks.append({**chunk,'chunk_id':chunk['id'],'title':doc.title,'source_type':doc.source_type,
                               'source_id':doc.source_id,'url':doc.url,'publication_date':doc.publication_date,
                               'score':None,'match_type':'document_context'})
            return {'document_id':doc.id,'source_id':doc.source_id,'title':doc.title,'active':doc.active,
                    'url':doc.url,'publication_date':doc.publication_date,'chunks':chunks}

    @application.get('/benchmarks')
    def saved_benchmarks():
        from .benchmark_exports import load_runs
        return load_runs(benchmark_directory)
    return application

app = create_app()
