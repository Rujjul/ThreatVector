# Delivery acceptance — 2026-10-21

The implementation covers semantic and exact-identifier retrieval, source partition filtering, explicit correlation, guarded analysis, evidence detail and saved FAISS evaluation. Full project acceptance remains open for the checks explicitly deferred by the user.

| Phase | Decision | Evidence / outstanding acceptance |
| --- | --- | --- |
| 0 Foundation | Complete | Pinned dependencies, working HTTP APIs, frontend type/build checks; no credentials committed. |
| 1 Corpus | Complete locally | 12,259 documents, 20,432 relationships; zero-write replay and source/SQL checks in `data/manifests/delivery-corpus-check-v1.json`. Full archived bytes remain outside Git. |
| 2 Retrieval | Complete | 15 real HTTP cases, 12 indexes and 78,900 reconstructed vector instances; reload/traceability in `data/manifests/delivery-search-v1.json`. Existing artifacts reused. |
| 3 Analysis | Functional criteria complete | `backend/PHASE3_ACCEPTANCE.md`; deterministic grounded/unsupported/conflicting/injection/error tests, frozen tuning-only relevance and actual HTTP evidence-only/document traceability in `interface-http-v1.json`. |
| 4 Interface | Implemented; visual acceptance open | Nine frontend tests and production build pass. Browser/mobile workflow remains unverified; user elected to continue with this open. |
| 5 Evaluation | Measured runs delivered; answer assessment open | 19 actual standard configurations with JSON/CSV/API equality; `evaluation/RESULTS.md`. Sixty agent-source-reviewed questions are not independent human review. Twenty evidence-only attempts contain zero rated generated answers. |
| 6 Delivery | Setup and checks delivered; final acceptance open | Fresh Python/frontend dependency installs verified on this host; setup helper and final check helper run. Separate pristine Windows machine, live provider and browser end-to-end demonstration are not claimed. |

## Reproduction and verification

Follow [SETUP.md](SETUP.md). Fresh Python installation passed 303 backend tests in 103.25 seconds. A separately installed frontend source copy passed nine tests and the production build; patched frontend tooling reports zero npm audit findings at the recorded date. The root setup helper also completed dependency installation and consistency checks. The final root check helper passed 303 backend tests in 88.02 seconds, nine frontend tests and production build, dependency consistency and backend compilation. Archived local model assets loaded successfully in the clean Python environment, producing a normalized 384-dimensional query vector; weights were not downloaded again.

The clean-environment search acceptance retry passed all 15 cases with clean shutdown. Its first attempt, run concurrently with other checks, timed out and is not counted as passing. The successful report records actual corpus/chunk/model/index identities. The analysis/document HTTP record checks matching source excerpts with a deliberately unavailable mocked provider; it is not a live-provider smoke test.

## Deferred checks

The user explicitly deferred configuring a provider and elected to leave browser verification open. No hosted requests were made. For final acceptance, verify Live mode → CVE-2021-44228 → matching evidence detail → Escape, including mobile layout and saved benchmark rendering. Configure provider settings server-side, then perform an explicitly bounded live smoke and the 20-answer rubric assessment. Do not expose credentials or treat evidence-only attempts as rated generated answers.

The project definition of done is not fully satisfied until these outstanding checks have actual evidence. Source truth, general paraphrase entailment, universal injection detection and performance on other hardware are not certified by the current tests.
