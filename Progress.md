# ThreatVector progress

Last updated: 2026-10-14 (Asia/Calcutta).

## Current state

Project planning documentation has been created. Application implementation has not started. The workspace was empty before these four documents were added. No application, dataset, index, benchmark result, or hosted-provider verification exists yet.

## Phase tracker

| Phase | Status | Completed | Remaining |
| --- | --- | --- | --- |
| Planning documentation | Complete | AGENTS.md, Requirements.md, BUILD.md, Progress.md | Keep aligned with approved changes. |
| 0 — Foundation | Not started | None | Scaffold React/FastAPI, configuration, locks, README, health endpoint, baseline checks. |
| 1 — Corpus | Not started | None | Source manifests, reuse review, fixtures, imports, SQLite records, full corpus. |
| 2 — Retrieval | Not started | None | Chunking, local embeddings, all three indexes, artifact validation, ID/filter retrieval. |
| 3 — Analysis | Not started | None | Correlation, provider adapter, grounding/citation validation, failure handling. |
| 4 — Interface | Not started | None | Investigation, evidence detail, benchmarks, loading/empty/error states. |
| 5 — Evaluation | Not started | None | 60 reviewed questions, real benchmark runs, exports, 20-answer review. |
| 6 — Delivery | Not started | None | Windows setup verification, end-to-end checks, final documentation, live-provider smoke test. |

## Next work

Start phase 0 using `BUILD.md`. Establish runnable backend and frontend foundations, lock compatible dependencies, and verify the health endpoint and frontend build before updating its status.

## Limitations and unresolved dependencies

| Item | Current impact | Resolution / verification |
| --- | --- | --- |
| No implementation | Nothing can run yet. | Complete the implementation phases and their exit criteria. |
| No downloaded corpus | Source coverage and import feasibility are unverified. | Verify NVD/ATT&CK sources, choose deterministic snapshots, curate 20 reports, and record manifests. |
| Incident reuse terms unchecked | Report text cannot yet be assumed redistributable. | Review terms; commit only permitted attributed fixtures and manifests. |
| Runtime/dependency compatibility unverified | Windows installation and FAISS availability are not confirmed. | Verify a compatible Python/Node stack and lock versions during phase 0. |
| No configured hosted provider | Live analysis cannot be exercised yet. | Configure server-side endpoint, model, and credentials, then record a bounded smoke test. |
| No relevance labels or threshold calibration | Retrieval relevance and abstention quality are unknown. | Review the question set, tune only on the tuning split, and freeze before held-out runs. |
| No measured performance | Accuracy, latency, memory, and ANN benefits are unknown. | Run the specified benchmark protocol and retain actual exports. |
| General-purpose embeddings | Security-specific terminology may retrieve poorly. | Measure held-out relevance and report observed weaknesses. |
| Incomplete source relationships | Semantic similarity cannot establish exploitation or causality. | Preserve explicit evidence and label inferred associations. |
| Citation checks validate identity only | A valid citation may still fail to support a claim. | Perform the documented manual answer review. |
| Local single-user design | Shared hosting and private-data controls are outside v1. | Change scope explicitly before adding those capabilities. |

## Validation record

- Documentation creation: complete; checked that all four files exist and their phase references align.
- Application tests, frontend checks, ingestion checks, benchmarks, and live-provider tests: not run; implementation does not exist yet.

## Update rules

After each milestone, update the date, phase status, completed/remaining work, limitations, and validation evidence. Use `Not started`, `In progress`, `Blocked`, or `Complete`. Record a blocker's cause and next action. Do not equate code written with behavior verified, or fixture success with full-corpus completion.

## Milestone log

| Date | Milestone | Evidence |
| --- | --- | --- |
| 2026-10-14 | Agreed plan documented in four project Markdown files | Documentation only; no implementation claimed. |
