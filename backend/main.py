"""Local foundation only. Retrieval and analysis are not implemented yet."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ThreatVector", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"], allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

@app.get("/health")
def health():
    return {"status": "foundation_only", "corpus_ready": False, "indexes_ready": False, "provider_configured": False}

@app.get("/corpus")
def corpus():
    return {"source_counts": {"cve": 0, "attack": 0, "incident": 0}, "snapshot_id": None, "active_artifacts": None}

@app.get("/benchmarks")
def benchmarks():
    return {"runs": []}
