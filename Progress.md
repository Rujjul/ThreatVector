# ThreatVector progress

Last updated: 2026-10-15 (Asia/Calcutta).

## Current state

2026-10-15 focus clarification: semantic vulnerability correlation, hybrid exact-identifier/semantic retrieval, evidence-grounded explanations, and FAISS indexing are the core product. Generic log monitoring and incident dashboards are explicitly excluded. Historical reports remain supporting evidence. Landing/workspace copy now emphasizes this focus; backend implementation status is unchanged.

Implemented the requested React/TypeScript demo landing page and frontend workspace. The responsive interface includes investigation controls, filters, index selection, citations, evidence detail, uncertainty, mitigations, retrieval fallback on analysis failure, and saved benchmark charts/tables. Demo content is explicitly fictional and unscored. Live mode never substitutes demo content for API failures.

A minimal FastAPI foundation serves health, empty corpus metadata, and empty benchmark runs. Corpus ingestion, retrieval, generation, and document storage are not implemented. User instructions authorized frontend work ahead of phases 1–3; BUILD.md records this adjustment. Demo success does not complete phase 4.

## Phase tracker

| Phase | Status | Completed | Remaining |
| --- | --- | --- | --- |
| Planning | Complete | Requirements, build guide, agent instructions, updated progress | Keep aligned with scope. |
| 0 — Foundation | Complete | React/Vite/TypeScript, FastAPI health, dependency pins/locks, configuration, ignore rules, README | Separate clean-machine installation during delivery. |
| 1 — Corpus | Not started | None; fictional examples are not corpus fixtures | Source/reuse review, fixtures, manifests, imports, SQLite, full corpus. |
| 2 — Retrieval | Not started | Frontend request shapes only | Chunking, embeddings, indexes, artifact validation, identifier/filter cases. |
| 3 — Analysis | Not started | Frontend citation guard and failure fallback only | Server correlation, provider adapter, grounding validation, mocked cases. |
| 4 — Interface | In progress | Landing, investigation, evidence drawer, benchmark views; demo browser workflow; live health; loading/empty/failure states; six passing frontend tests | Real API workflow, document retrieval, provider fallback, chart-to-export verification and mobile visual QA. |
| 5 — Evaluation | Not started | No invented metrics displayed | Reviewed questions, actual benchmark exports, answer reviews. |
| 6 — Delivery | In progress | Windows setup and frontend integration documentation | Clean setup, real end-to-end checks, final backend tests, live-provider record. |

## Validation record

- Focus clarification update: frontend type/production build and all six tests passed after copy changes; `git diff --check` passed. No retrieval behavior or backend capability was added by this update.

- Runtime observed: Node 24.19.0, npm 11.17.0, Python 3.10.11 on Windows.
- `npm run build`: TypeScript and production Vite build passed. Final chart chunk 330.29 kB and app chunk 211.16 kB; no final chunk warning.
- `npm test`: six tests passed in two files. Covers citation navigation/Escape dismissal, source filtering, unsupported empty state, live failure without demo substitution, empty benchmark view, invalid citations, and safe URL schemes.
- Backend imports and foundation function checks passed. Source counts are zero and saved runs empty.
- Running `/health` HTTP check passed. Browser at default allowed frontend origin displayed `Foundation only · data unavailable`.
- Desktop browser: landing rendered, synthetic investigation showed three cards, citation opened matching `demo-cve-01` drawer with explicitly absent metadata. Workspace screenshot saved as `frontend-preview.jpg`.
- Restricted network initially blocked downloads; permitted installation succeeded. An overlapping retry caused incomplete generated packages; stopped original install and repaired packages. Final build and tests passed afterward.
- No paid provider calls, ingestion, FAISS checks, real benchmarks, manual answer review, or mobile visual checks performed.

## Remaining limitations

- Proposed response shapes are in `frontend/src/api.ts` and README.md. Actual backend integration remains unverified.
- `/analyze`, `/search`, and `/documents/{id}` do not exist yet. Live investigation displays an API failure; live benchmarks are empty.
- No public corpus or attributed fixture exists. Source snapshot compatibility and incident reuse terms are unchecked.
- Embedding revision, FAISS compatibility, relevance thresholds, tuning/held-out labels, performance and answer quality remain unverified.
- Frontend validates citation membership only. Server must validate ATT&CK IDs and grounding; semantic support requires manual review.
- Optional Google Fonts loads fall back to system fonts offline.
- Separate clean Windows installation, mobile visual verification, real saved benchmark rendering and production browser verification remain open.
- Authentication, private ingestion, cloud hosting, scheduled refreshes and fine-tuning remain excluded.

## Next work

Continue phase 1 with public-source/reuse review, attributed fixtures, SQLite and ingestion. Complete retrieval and analysis before marking the live interface complete. Compare charts with actual exports during evaluation.

## Milestone log

| Date | Milestone | Evidence |
| --- | --- | --- |
| 2026-10-14 | Planning documents | Documentation only. |
| 2026-10-15 | User requested frontend-first delivery | Scope adjustment in BUILD.md. |
| 2026-10-15 | Foundation and React frontend delivered | Type/build and six tests passed; HTTP health and desktop demo browser checks passed. Live retrieval/evaluation incomplete. |
