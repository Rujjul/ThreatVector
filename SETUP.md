# Windows setup and verification

Verified baseline: Python 3.10.11 x64, Node 24.19.0, local CPU MiniLM revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, FAISS 1.10.0. Use Python 3.10 for the pinned optional stack, and Node 22.12 or later. Run backend commands from the repository root so relative artifact paths resolve consistently.

## Dependencies

```powershell
.\scripts\setup.ps1 -WithRetrieval
```

This creates `.venv` if absent, installs pinned backend/dev dependencies, installs CPU Torch before the complete retrieval lock, checks package consistency, then installs the frontend lock. Omitting `-WithRetrieval` supports the basic/demo/normalizer environment; live search needs the optional stack. It does not download corpus/model assets or contact a hosted model automatically.

Equivalent backend steps:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu
.\.venv\Scripts\python.exe -m pip install -r backend/requirements-index.lock
.\.venv\Scripts\python.exe -m pip check
```

## Evidence and artifacts

A fresh clone can verify the attributed seed immediately:

```powershell
.\.venv\Scripts\python.exe data/fixtures/verify_fixture.py
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/raw-normalizers-v1.json --database data/fixture.sqlite3 --reviewed-annotations --check-idempotence
```

The complete frozen corpus requires restoring the archived `data/raw/full-v1` bytes referenced by the committed full-v2 manifest. See [CORPUS.md](backend/CORPUS.md) for bounded acquisition and exact replay. Live upstream pages/feed bytes may change; hash rejection must not be bypassed or relabeled as the old snapshot. CISA material stays project-authored summaries, Microsoft candidates stay metadata/links only, and the other reviewed rights decisions remain in force. No raw corpus downloads are silently committed.

```powershell
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/full-corpus-v2.json --database data/corpus-v2.sqlite3 --reviewed-annotations --check-idempotence
.\.venv\Scripts\python.exe -m backend.prepare_embedding
.\.venv\Scripts\python.exe -m backend.cli chunk
.\.venv\Scripts\python.exe -m backend.cli build-indexes
.\.venv\Scripts\python.exe -m backend.cli validate-indexes
```

`prepare_embedding` downloads only the eleven locked model assets and checks bytes/hashes. All subsequent model loads are offline. Existing valid chunks/embedding caches may be reused; mismatched generations fail closed. A corpus revision needs its own manifests/database and re-evaluation, not copied old calibration/benchmark identities. See [CHUNKING.md](backend/CHUNKING.md) and [INDEXES.md](backend/INDEXES.md).

## Start and inspect

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173, enter the workspace, choose Live, and ask `CVE-2021-44228` or `T1059.001`. Inspect sources and explicit versus inferred associations; do not interpret similarity as exploitation. `/health` reports retrieval readiness independently of provider configuration. Document detail resolves stable document IDs to source chunks. Empty source selection returns no evidence at the API; the UI asks for at least one source.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/corpus
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/search -ContentType application/json -Body '{"query":"CVE-2021-44228 T1190","index":"flat","source_types":["cve","attack"],"top_k":10}'
```

Server paths can be configured with `THREATVECTOR_DATABASE` and `THREATVECTOR_INDEX_DIRECTORY`; requests cannot select local filesystem paths. Bind to localhost; only the local frontend origins are allowed by default.

## Provider and verification boundaries

Set endpoint/model/key/timeout in the **backend process environment**, using the names in [provider.env.example](backend/provider.env.example). No environment file is automatically loaded. Do not put provider secrets in `VITE_` settings, browser code, fixtures, reports or Git. The user chose to defer provider configuration; evidence-only mode remains functional. A later paid smoke should be explicitly bounded to one request with at most one repair (two calls), recorded separately from mocks, and followed by actual answer review.

```powershell
.\scripts\check.ps1
.\.venv\Scripts\python.exe -m backend.verify_phase2 --output data/manifests/local-search-check.json
.\.venv\Scripts\python.exe -m backend.evaluation
```

The test helper stops on failures. The real HTTP/artifact check uses existing corpus/model bytes and no hosted provider. Evaluation embeds questions before timing, isolates standard index configurations and writes measured JSON/CSV. Reproducing timings on another machine need not match the saved measurements. The frozen policy uses tuning only; held-out labels never enter vector retrieval. Windows async loopback restrictions may need runner permission even for ASGI tests; browser access across runner boundaries is a separate validation gap.
