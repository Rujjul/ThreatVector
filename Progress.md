# ThreatVector progress

Last updated: 2026-10-15 (Asia/Calcutta).

## Current state

2026-10-15 focus clarification: semantic vulnerability correlation, hybrid exact-identifier/semantic retrieval, evidence-grounded explanations, and FAISS indexing are the core product. Generic log monitoring and incident dashboards are explicitly excluded. Historical reports remain supporting evidence. Landing/workspace copy now emphasizes this focus; backend implementation status is unchanged.

Implemented the requested React/TypeScript demo landing page and frontend workspace. The responsive interface includes investigation controls, filters, index selection, citations, evidence detail, uncertainty, mitigations, retrieval fallback on analysis failure, and saved benchmark charts/tables. Demo content is explicitly fictional and unscored. Live mode never substitutes demo content for API failures.

A minimal FastAPI foundation serves health, empty corpus metadata, and empty benchmark runs. Corpus ingestion, retrieval, generation, and document storage are not implemented. User instructions authorized frontend work ahead of phases 1–3; BUILD.md records this adjustment. Demo success does not complete phase 4.

Source/fixture-only milestone: added six attributed source-backed documents (two NVD CVEs, two MITRE ATT&CK techniques and two CISA advisories), eight original-summary evidence sections, five explicit relationships and two unsupported cases. Added frozen fixture/source-review manifests and retained the pinned MITRE license. Raw downloads are ignored; fixture data are not wired into the application. Review scope remains limited: original CISA report-text redistribution is not cleared, and full NVD API policy content could not be verified from the JavaScript-shell response.

## Phase tracker

| Phase | Status | Completed | Remaining |
| --- | --- | --- | --- |
| Planning | Complete | Requirements, build guide, agent instructions, updated progress | Keep aligned with scope. |
| 0 — Foundation | Complete | React/Vite/TypeScript, FastAPI health, dependency pins/locks, configuration, ignore rules, README | Separate clean-machine installation during delivery. |
| 1 — Corpus | In progress | Six attributed summary fixtures; limited source/reuse review; pinned ATT&CK 17.1; provenance/hashes; explicit relationships and unsupported cases; offline integrity checks | Full report-text permissions where needed, bulk API policy review, raw normalizer fixtures, normalizers, SQLite, ingestion/idempotence checks and full target corpus. |
| 2 — Retrieval | Not started | Frontend request shapes only | Chunking, embeddings, indexes, artifact validation, identifier/filter cases. |
| 3 — Analysis | Not started | Frontend citation guard and failure fallback only | Server correlation, provider adapter, grounding validation, mocked cases. |
| 4 — Interface | In progress | Landing, investigation, evidence drawer, benchmark views; demo browser workflow; live health; loading/empty/failure states; six passing frontend tests | Real API workflow, document retrieval, provider fallback, chart-to-export verification and mobile visual QA. |
| 5 — Evaluation | Not started | No invented metrics displayed | Reviewed questions, actual benchmark exports, answer reviews. |
| 6 — Delivery | In progress | Windows setup and frontend integration documentation | Clean setup, real end-to-end checks, final backend tests, live-provider record. |

## Validation record

- Fixture integrity: `python data/fixtures/verify_fixture.py` passed for six documents/eight sections/five relationships/two unsupported cases. `--check-local-sources` also passed against downloaded source bytes, selected NVD/STIX object hashes and source locators. No network calls in verification.
- Isolated-copy checks: a clean fixture-only copy passed without raw downloads; changed corpus bytes were rejected; an unsupported incident-to-CVE-2021-45046 edge was rejected even after recomputing its artifact hash. Repository fixture files were not changed by these negative checks. Fixture bytes are protected from Git line-ending conversion through scoped `.gitattributes` rules.
- Source availability: two individual NVD API responses, ATT&CK release-17.1 tag/commit/bundle/license, and both official CISA PDFs downloaded successfully with measured SHA-256. CISA website-policy URL returned HTTP 403; NVD developer-policy HTTP 200 contained a JavaScript shell. Neither was treated as verified policy content.
- Evidence review: CISA AA22-320A pages 1–2 and AA22-174A page 1 read; AA22-320A page 2 and AA22-174A page 1 visually inspected. Publication dates, TLP labels, CVE mention and report-specific T1190/T1059.001 labels verified. Full extracted PDFs did not mention 45046; that finding is bounded to these reports.
- No ingestion, indexes, embeddings, frontend changes, live provider calls or performance/quality claims added in the fixture/source-review milestone. The whole target corpus and phase-1 exit criteria remain incomplete.

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
- Small attributed factual-summary fixtures now exist. Full target corpus, raw normalizer fixtures and ingestion compatibility remain open. Original CISA text is not cleared for redistribution; Microsoft candidate reports remain link-only. Full NVD bulk-access policy review is pending.
- Embedding revision, FAISS compatibility, relevance thresholds, tuning/held-out labels, performance and answer quality remain unverified.
- Frontend validates citation membership only. Server must validate ATT&CK IDs and grounding; semantic support requires manual review.
- Optional Google Fonts loads fall back to system fonts offline.
- Separate clean Windows installation, mobile visual verification, real saved benchmark rendering and production browser verification remain open.
- Authentication, private ingestion, cloud hosting, scheduled refreshes and fine-tuning remain excluded.

## Next work

Current user scope ends at small fixtures and source/reuse review. Future phase-1 work is raw normalizer fixtures, SQLite and ingestion/idempotence, broader report reuse review and the full target corpus. Complete retrieval and analysis before marking the live interface complete. Compare charts with actual exports during evaluation.

## Milestone log

| Date | Milestone | Evidence |
| --- | --- | --- |
| 2026-10-14 | Planning documents | Documentation only. |
| 2026-10-15 | User requested frontend-first delivery | Scope adjustment in BUILD.md. |
| 2026-10-15 | Foundation and React frontend delivered | Type/build and six tests passed; HTTP health and desktop demo browser checks passed. Live retrieval/evaluation incomplete. |
| 2026-10-15 | Attributed fixture corpus and limited source/reuse review | Six documents, eight sections, five explicit relationships, two unsupported cases; frozen provenance/hashes and offline checks. No ingestion or app integration. |
