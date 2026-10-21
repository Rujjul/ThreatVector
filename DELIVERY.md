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


## Remaining-validation attempt — 2026-10-21

This attempt does **not** close Phases 4–6. No application code or saved benchmark values were changed.

### Command and action record

- Read `AGENTS.md`, `Requirements.md`, `BUILD.md`, `Progress.md`, `DELIVERY.md`, `SETUP.md`; inspected `backend/provider.env.example`, `backend/main.py`, `backend/review_answers.py`, `backend/benchmark_exports.py`, `frontend/vite.config.ts` and `frontend/src/App.tsx`. Read computer-use skill, guidance, confirmations and API reference. `git status --short` initially clean.
- Provider presence check: PowerShell `[Environment]::GetEnvironmentVariable(name,'Process'/'User')` reported only booleans for `THREATVECTOR_PROVIDER_ENDPOINT`, `MODEL`, `KEY`, `TIMEOUT`; all absent. Recheck of endpoint/model/key remained absent. No values or credentials printed. User said they would configure the server environment; configuration completion has not been confirmed. No live request made. Smoke budget proposed: one analysis, at most two calls; subsequent 20-answer assessment at most 40 calls. Both remain blocked pending usable server-side configuration. Existing 20 deferred attempts remain zero rated generated answers; no scores assigned or old report overwritten.
- Started `.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000` (session 32882): no startup-ready output observed during this attempt. Started `npm run dev -- --host 127.0.0.1` in frontend (51463): Vite reported ready at 127.0.0.1:5173. `Get-NetTCPConnection -State Listen -LocalPort 8000,5173` returned no listener rows in this runner. `Invoke-WebRequest http://127.0.0.1:5173 -TimeoutSec 10 -UseBasicParsing` failed with HttpClient timeout, including with approved local-network execution. No firewall/security settings changed.
- Browser connector `createBrowserTab('chrome', local URL)` reported Chrome unavailable. Isolated `createBrowserTab('iab','http://127.0.0.1:5173',{visible:true})` failed `net::ERR_CONNECTION_TIMED_OUT`. These are failed reachability attempts, not app workflow passes.
- Native computer-use initialization and `list_apps` found Chrome. Selected returned Chrome window, observed accessibility state, attempted new-tab navigation. The window was on an unrelated page; no local ThreatVector page was reached. Automatic approval review rejected screenshot capture because private unrelated content could be exposed. No screenshot taken. A later separate-tab action reported user physical Escape: Computer Use stopped; no further browser automation performed. Unrelated page contents are omitted from this record.
- Desktop/mobile search, analysis, citation/card navigation, source-link opening, loading, empty and failure states remain **browser-unverified**. Prior automated checks are not a substitute. No responsive/mobile screenshot, rendered chart tooltip or real source-link navigation is claimed.
- Benchmark verification: inline Python loaded JSON/CSV with `json`, `csv`, `Path`; compared numeric fields by configuration ID, first three baselines then all `sweep_metrics`; all **19 CSV rows exactly equal** the JSON values. `backend.benchmark_exports.load_runs()` returned the identical saved report with no errors. Source inspection confirms Recharts reads `run.metrics` directly with `p95_ms`, `ann_recall_at_10`, `peak_process_bytes`. Browser chart rendering remains incomplete. Initial discovery checked alternate configuration keys (none present); subsequent explicit `sweep_metrics` check covered all 19. No new benchmark run or changed metric claimed.
- `.\scripts\check.ps1` passed: **303 backend tests in 84.86s**, **9 frontend tests in 8.59s**, TypeScript/production build (9.43s), `pip check` (no broken requirements), `compileall -q backend`, and `git diff --check`. Native retrieval dependencies verified installed. Provider tests are deterministic mocks.
- `npm audit --json` in frontend passed: **0 vulnerabilities** across reported severities at this check. This is registry advisory coverage, not a universal security guarantee.
- `Get-Command ssh,vmrun,VBoxManage -ErrorAction SilentlyContinue` found only ssh; combined lookup exit 1 reflected absent VM tools. No separate Windows host/VM credentials or target were supplied. No independent clean-machine setup performed; same-host fresh-environment results remain historical evidence only. Do not infer an available clean Windows guest from Docker or ssh installation.

### Outstanding acceptance

Provider smoke, 20 actual generated-answer assessments, real desktop/mobile browser workflow (including saved chart rendering), and separate pristine Windows installation remain explicitly incomplete. User interruption ended Computer Use; provider configuration is pending. No generated answer, browser evidence or score has been invented. Required automated suites passed before the documentation-only validation commit.

Cleanup: sent Ctrl-C only to this attempt's backend/frontend sessions (32882/51463); both terminated with exit 1 after interruption. Final whitespace check passed. No user-owned services stopped.
