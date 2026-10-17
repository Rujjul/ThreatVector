# ThreatVector

ThreatVector focuses on semantic vulnerability correlation, hybrid identifier/semantic retrieval, evidence-grounded explanations, and FAISS Flat/IVF/HNSW indexing. Public incident reports serve as supporting evidence. Generic log monitoring, incident dashboards, alert feeds, and SIEM workflows are excluded. The local backend supports verified semantic and exact-identifier retrieval through the CLI and `POST /search`; complete live frontend integration remains incomplete.

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

The HTTP foundation serves `/health`, placeholder `/corpus`, and an empty `/benchmarks`. SQLite storage and ingestion now exist through the separate CLI; these routes are not wired to the database. `POST /search` now serves real local retrieval after the optional model/index setup below; analysis and complete live investigations remain later work.

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

## Reviewed seed evidence

The [attributed seed corpus](data/fixtures/README.md) contains six source-backed documents across NVD, pinned MITRE ATT&CK and CISA reports. It uses original factual summaries, explicit supported relationships and unsupported cases. The [source/reuse review](data/fixtures/SOURCE_REVIEW.md) records decisions and unresolved report-text permissions. Verify the frozen fixture without downloading anything:

```powershell
python data/fixtures/verify_fixture.py
```

The browser demo remains synthetic. Seed data can now be normalized and ingested through the CLI; raw downloads stay ignored. Fixture hashes and upstream provenance are recorded under `data/manifests/`.

The source manifest's revision-2 decisions use four explicit reuse categories and include reviewed Microsoft/NCSC candidates. The [NVD access-policy review](data/fixtures/NVD_API_POLICY.md) now verifies bulk/API limits, key handling and attribution. Current CISA policy pages were found and read, but worldwide full-report rights remain unestablished; project-authored factual summaries remain the approved representation. Microsoft articles remain links/metadata only. No candidate text has been added to the seed corpus.

## Normalizers and raw-format fixtures

[Source normalizers](backend/normalization/README.md) handle NVD API 2.0 responses, pinned STIX bundles and approved incident summaries. [Raw fixtures](data/fixtures/raw_normalizers/README.md) retain source format, hashes and notices. Adapters remain pure; the separate ingestion service persists their output without retrieval, indexing or providers.

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend/requirements-dev.lock
.\.venv\Scripts\python.exe -m pytest
python data/fixtures/verify_fixture.py
```

Normalization preserves provenance, rejects conflicting revisions, retains inactive/unresolved records and separates identifier mentions from reviewed stronger annotations. Policy comes from trusted project configuration. Source text cannot authorize itself, enable reviewed annotations or trigger tools.

## SQLite and the full corpus

The [corpus guide](backend/CORPUS.md) documents SQLite imports, acquisition, frozen manifests and offline verification. Current corpus v2 contains **10,000 CVEs, 2,239 ATT&CK records and 20 incident summaries**, preserving every nonstructural entity and all 20,411 STIX relationships from pinned Enterprise 17.1 with resolved STIX endpoints. Full replay changed zero rows; source-pointer/SQL checks are saved in `data/manifests/full-corpus-validation-v2.json`. Downloads/databases stay outside Git; exact replay requires archived bytes. The [phase-1 acceptance matrix](backend/PHASE1_ACCEPTANCE.md) records completion and retained corpus boundaries. Frozen v1 artifacts remain available.

```powershell
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/full-corpus-v2.json --database data/corpus-v2.sqlite3 --reviewed-annotations --check-idempotence
.\.venv\Scripts\python.exe -m backend.cli inspect
```

The historical CVE sample includes inactive records. Incident evidence uses original factual summaries; CISA prose is not redistributed. [Tokenizer-aware chunking and pinned MiniLM setup](backend/CHUNKING.md) provides local chunk construction and model verification. [FAISS setup and persistence](backend/INDEXES.md) covers shared CPU embeddings, Flat/IVF/HNSW strategies, source partitions, atomic generations and validation. [Filtered retrieval](backend/RETRIEVAL.md) supports local natural-language searches over the full corpus or selected source partitions through the CLI. Exact CVE/ATT&CK lookup and `POST /search` are verified. The [Phase 2 acceptance matrix](backend/PHASE2_ACCEPTANCE.md) records 196 passing backend tests and 15 local HTTP cases; complete frontend integration remains later work.

## Phase 3 foundations

[Correlation and provider services](backend/CORRELATION_PROVIDER.md) expand explicit source relationships and keep semantic associations separate. The configurable provider adapter keeps endpoint/model/key/timeout server-side and supports missing credentials, timeout and upstream errors. Automated checks use deterministic mocks; no live provider calls were made. Generation, grounding validation and `/analyze` remain incomplete.
