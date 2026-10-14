# ThreatVector

ThreatVector focuses on semantic vulnerability correlation, hybrid identifier/semantic retrieval, evidence-grounded explanations, and FAISS Flat/IVF/HNSW indexing. Public incident reports serve as supporting evidence. Generic log monitoring, incident dashboards, alert feeds, and SIEM workflows are excluded. The UI demonstrates these concepts; the retrieval and FAISS backend remain unimplemented.

React/TypeScript demo landing page and local investigation frontend. The interactive demo uses explicitly fictional content. Live mode calls the local API; it never silently substitutes demo content. There are no measured benchmark runs yet.

## Windows setup

Use Node 22.12+ (verified runtime: Node 24.19.0) and Python 3.10+ (verified: 3.10.11).

```powershell
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173. Choose **Explore the demo**, run a question, and select a citation or evidence card. Try `unsupported weather question` for the empty state. Disable source checkboxes to inspect filtering. The landing page, investigation workspace, and benchmark view adapt to mobile widths.

Optional backend foundation, from the repository root in a second terminal:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The foundation serves `/health`, `/corpus`, and an empty `/benchmarks`. It does **not** implement retrieval, ingestion, generation, or document storage. Live investigations correctly show failures until those phases exist.

## Frontend verification

```powershell
cd frontend
npm run build
npm test
```

Dependencies are pinned in `package.json` and `package-lock.json`. Backend installed dependency versions are recorded in `backend/requirements.lock`. Fonts optionally load from Google Fonts; fallback system fonts work offline. No hosted provider calls occur in this demo.

## Integration contract

`frontend/src/api.ts` defines the proposed JSON field shapes for the BUILD.md endpoints. `/analyze` returns `status`, `claims`, `mitigations`, `related_entities`, `uncertainty`, `evidence`, and `timing`. Claims and mitigations use `text`, `citation_chunk_ids`, and an optional `inferred` flag. Evidence includes chunk/document IDs, source metadata, excerpt text, and similarity score. Missing dates, identifiers, URLs, and scores are explicit `null` values. `/search` returns `evidence` and `retrieval_ms`. `/documents/{id}` returns `chunks` plus stored metadata. `/benchmarks` returns `{ runs: [...] }` with the benchmark shape in `api.ts`.

Citation membership is checked before rendering live analysis; the backend must still validate ATT&CK identifiers, source support, and provider outputs. When analysis fails, the frontend separately tries retrieval. Evidence text is rendered as plain React text, and source links allow only HTTP(S). API credentials must stay server-side. `VITE_API_BASE_URL` is a public service address only.

The benchmark UI renders saved values, quality/latency/memory charts, a metric table, and reproducibility metadata. Real exports, tuning/held-out evaluation, and live provider validation remain future work. See `Progress.md` for verified status.
