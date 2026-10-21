"""Validate saved measurements; never benchmark in an HTTP request."""
import json
from pathlib import Path
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator


class Metric(BaseModel):
    model_config=ConfigDict(strict=True,extra='allow',allow_inf_nan=False)
    index: Literal['flat','ivf','hnsw']
    ann_recall_at_10: float=Field(ge=0,le=1)
    relevance_recall_at_10: float=Field(ge=0,le=1)
    mrr: float=Field(ge=0,le=1)
    p50_ms: float=Field(ge=0)
    p95_ms: float=Field(ge=0)
    build_seconds: float=Field(ge=0)
    serialized_bytes: int=Field(gt=0)
    peak_process_bytes: int=Field(gt=0)

    @model_validator(mode='after')
    def percentiles(self):
        if self.p95_ms<self.p50_ms:
            raise ValueError('Invalid percentiles')
        return self


class Export(BaseModel):
    model_config=ConfigDict(strict=True,extra='allow')
    run_id: str=Field(min_length=1)
    corpus_hash: str=Field(pattern=r'^[0-9a-f]{64}$')
    query_set_hash: str=Field(pattern=r'^[0-9a-f]{64}$')
    model_revision: str=Field(pattern=r'^[0-9a-f]{40}$')
    seed: Literal[42]
    threads: Literal[1]
    hardware: str=Field(min_length=1)
    versions: dict[str,str]
    metrics: list[Metric]=Field(min_length=3,max_length=3)

    @model_validator(mode='after')
    def strategies(self):
        if {m.index for m in self.metrics}!={'flat','ivf','hnsw'}:
            raise ValueError('Missing baseline strategy')
        return self


def load_runs(directory='data/manifests'):
    runs=[];errors=[]
    for path in sorted(Path(directory).glob('benchmark-v*.json')):
        try:
            raw=json.loads(path.read_bytes())
            Export.model_validate(raw)
            runs.append(raw)
        except (OSError,ValueError,TypeError):
            errors.append('A saved benchmark failed validation and was omitted.')
    return {'runs':runs,'errors':errors}
