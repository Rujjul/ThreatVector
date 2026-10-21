# ThreatVector

A local React/TypeScript and FastAPI application for semantic vulnerability retrieval, exact CVE/ATT&CK lookup, explicit source correlation and inspectable evidence. It compares FAISS Flat, IVF and HNSW over the same embeddings. Generic log monitoring, incident dashboards, authentication, private ingestion and cloud hosting are outside scope.

The current local corpus contains **10,000 CVEs, 2,239 ATT&CK records and 20 attributed incident summaries**, with **13,150 chunks** and 12 validated indexes. Generated corpora, weights, databases and native indexes are intentionally outside Git. A fresh clone can run the synthetic demo and attributed fixtures; reproducing the full frozen snapshot requires the archived source bytes described in [CORPUS.md](backend/CORPUS.md).

## Run the demo

Use Node 22.12+ (verified 24.19.0). Vite 7.3.7 and Vitest 4.1.11 are pinned with the verified lockfile.

```powershell
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173 and choose **Explore the demo**. Demo evidence is fictional and unscored. Live mode never silently replaces API failures with demo content.

## Run real local retrieval

Use Windows x64 / Python 3.10 (verified 3.10.11). From the repository root:

```powershell
.\scripts\setup.ps1 -WithRetrieval
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Prepare/restore corpus, model and indexes using [SETUP.md](SETUP.md), then start the frontend in a second terminal and select **Live**. Examples: `CVE-2021-44228`, `T1059.001`, or a question about exploitation of public-facing applications. Select sources and Flat/IVF/HNSW, inspect an evidence card or citation, and close the detail dialog with Escape.

The API implements `/health`, `/corpus`, `POST /search`, `POST /analyze`, `/documents/{id}` and `/benchmarks`. Readiness checks actual artifacts. Search filters query selected partitions before merging. Default top_k is 10, maximum 50. Evidence retains source/provenance/offsets and raw scores; similarity never proves exploitation.

Provider settings remain server-side: see [provider.env.example](backend/provider.env.example). No key is required for evidence-only operation. Explanations use conservative excerpt grounding, at most eight context chunks, strict citations/active identifiers, explicit inference, one repair attempt and evidence-only fallback. No tools or secrets enter prompts; recognized injection attempts are withheld from generation while their source evidence remains inspectable. See [ANALYSIS.md](backend/ANALYSIS.md) for limits. Arbitrary paraphrase entailment and universal injection detection are not claimed.

## Measured evaluation

Sixty source-reviewed questions have distinct 30/30 tuning/held-out splits. Review is explicitly agent source inspection, not independent human assessment. A frozen tuning-only relevance policy is bound to corpus/chunk/model identities.

[RESULTS.md](evaluation/RESULTS.md) documents the **19 measured standard configurations**, hardware, one-thread protocol, build/search/serialization/memory scope and limitations. [JSON](data/manifests/benchmark-v1.json) and [CSV](data/manifests/benchmark-v1.csv) values match the saved API output. ANN recall@10 and document relevance are separate; the incident-only nlist=1 IVF exception is excluded. The frontend displays saved default baseline values, not invented or recomputed benchmarks.

```powershell
.\.venv\Scripts\python.exe -m backend.evaluation
```

The user deferred live provider use. [Twenty evidence-only attempts](data/manifests/answer-review-v1.json) have **zero rated generated answers**; [actual answer assessment](evaluation/ANSWER_REVIEW.md) and live smoke remain open. Browser/mobile visual checks are also open because the runner's in-app browser could not reach its loopback servers. These limitations prevent claiming every project acceptance criterion complete.

## Verify

```powershell
.\scripts\check.ps1
```

The test suites use deterministic provider mocks and actual native FAISS fixtures. Setup, artifact verification, sample requests, evidence rights and remaining delivery checks are documented in [SETUP.md](SETUP.md), [DELIVERY.md](DELIVERY.md), [Progress.md](Progress.md) and the phase acceptance records. The [dependency verification](frontend/DEPENDENCIES.md) records the pinned security updates and registry audit scope.
