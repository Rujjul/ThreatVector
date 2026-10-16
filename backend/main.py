"""Local search API; analysis/generation and other later-phase routes stay absent."""
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


def create_app(service_factory=None):
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

    @application.post('/search')
    def search(request: SearchRequest):
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

    application.add_api_route('/health',health,methods=['GET'])
    application.add_api_route('/corpus',corpus,methods=['GET'])
    application.add_api_route('/benchmarks',benchmarks,methods=['GET'])
    return application

def health():
    return {"status": "foundation_only", "corpus_ready": False, "indexes_ready": False, "provider_configured": False}

def corpus():
    return {"source_counts": {"cve": 0, "attack": 0, "incident": 0}, "snapshot_id": None, "active_artifacts": None}

def benchmarks():
    return {"runs": []}


app = create_app()
