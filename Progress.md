# ThreatVector progress

Last updated: 2026-10-15 (Asia/Calcutta).

## Current state

2026-10-15 focus clarification: semantic vulnerability correlation, hybrid exact-identifier/semantic retrieval, evidence-grounded explanations, and FAISS indexing are the core product. Generic log monitoring and incident dashboards are explicitly excluded. Historical reports remain supporting evidence. Landing/workspace copy now emphasizes this focus; backend implementation status is unchanged.

Implemented the requested React/TypeScript demo landing page and frontend workspace. The responsive interface includes investigation controls, filters, index selection, citations, evidence detail, uncertainty, mitigations, retrieval fallback on analysis failure, and saved benchmark charts/tables. Demo content is explicitly fictional and unscored. Live mode never substitutes demo content for API failures.

A minimal FastAPI foundation serves health, empty corpus metadata, and empty benchmark runs. Corpus ingestion, retrieval, generation, and document storage are not implemented. User instructions authorized frontend work ahead of phases 1–3; BUILD.md records this adjustment. Demo success does not complete phase 4.

Raw-fixture/normalizer milestone: four source-shaped inputs now cover two exact NVD API responses, an object-preserving pinned STIX subset (including a real deprecated legacy mitigation and two relationships), and a project-authored incident-summary manifest. NIST/CVE notices accompany the original NVD text; the pinned MITRE notice is retained. Pure adapters in `backend/normalization/` preserve metadata, hashes and evidence references; deduplicate repeated content; retain inactive/unresolved evidence with explicit issues; and reject conflicting identities or disallowed source representations. Identifier occurrences remain mentions; stronger incident annotations require a trusted caller's explicit review setting. The existing six-document summary seed is unchanged in content; raw normalization produces nine documents/ten relationships in memory. No database import, provider calls, retrieval or UI wiring was added.

Source/fixture-only milestone: added six attributed source-backed documents (two NVD CVEs, two MITRE ATT&CK techniques and two CISA advisories), eight original-summary evidence sections, five explicit relationships and two unsupported cases. Added frozen fixture/source-review manifests and retained the pinned MITRE license. Raw downloads are ignored; fixture data are not wired into the application.

Policy follow-up: the NVD JavaScript-shell gap is resolved through rendered Getting Started, key Terms of Use, expanded workflows, feed guidance and CVE license pages. CISA's old URL is Page Not Found; current Terms of Use and Intellectual Property Policy were found through live Site Links and reviewed. Their access gap is resolved, while worldwide original CISA report-text permission is not established: final project decision is original factual summaries only, without claiming permission for verbatim excerpts. The source manifest revision 2 records eight decisions across all four requested categories, with actual policy-evidence timestamps/hashes. Two Microsoft candidates are metadata/link-only; the NCSC-authored IRGC article is eligible under OGL v3.0; its separate linked AA22-257A advisory is excluded pending independent review. Candidate text was not added to the corpus.

## Phase tracker

The two requested review tasks are **Complete for the named sources and current project scope**:

| Review task | Status | Final outcome |
| --- | --- | --- |
| CISA and named incident-report reuse decisions | Complete | CISA AA22-320A/AA22-174A: original factual summaries only, no verbatim text; Microsoft HAFNIUM/Log4j: metadata and links only; NCSC-authored IRGC article: OGL v3.0 text with conditions; separately linked AA22-257A: excluded. These are final project admission decisions, not a claim of blanket worldwide CISA permission. |
| NVD API/bulk usage-policy review | Complete | Rendered official policies verified; request/key/proxy limits, pagination, feed META hashes, attribution, modified-content rules and applicable reuse notices documented. No bulk import or API-key registration performed. |

The remaining rights questions matter only if a later scope change seeks broader representations than these decisions permit. They do not keep the two completed review tasks open. Broader report curation and implementation remain separate phase-1 work.

| Phase | Status | Completed | Remaining |
| --- | --- | --- | --- |
| Planning | Complete | Requirements, build guide, agent instructions, updated progress | Keep aligned with scope. |
| 0 — Foundation | Complete | React/Vite/TypeScript, FastAPI health, dependency pins/locks, configuration, ignore rules, README | Separate clean-machine installation during delivery. |
| 1 — Corpus | In progress | Summary seed and raw normalizer fixtures; pure NVD/STIX/incident-manifest adapters; 37 offline tests; NVD API/bulk review and final named-source reuse decisions; pinned ATT&CK; provenance/relationships/negative cases; integrity checks | SQLite, acquisition/ingestion CLI, database idempotence/update policy, broader 20-report curation and full target corpus; additional rights if expanding CISA/Microsoft representations. |
| 2 — Retrieval | Not started | Frontend request shapes only | Chunking, embeddings, indexes, artifact validation, identifier/filter cases. |
| 3 — Analysis | Not started | Frontend citation guard and failure fallback only | Server correlation, provider adapter, grounding validation, mocked cases. |
| 4 — Interface | In progress | Landing, investigation, evidence drawer, benchmark views; demo browser workflow; live health; loading/empty/failure states; six passing frontend tests | Real API workflow, document retrieval, provider fallback, chart-to-export verification and mobile visual QA. |
| 5 — Evaluation | Not started | No invented metrics displayed | Reviewed questions, actual benchmark exports, answer reviews. |
| 6 — Delivery | In progress | Windows setup and frontend integration documentation | Clean setup, real end-to-end checks, final backend tests, live-provider record. |

## Validation record

- Normalizers: `.venv/Scripts/python.exe -m pytest` passed **37 tests**, covering raw hashes, metadata and missing values, repeated snapshots/duplicates, conflicting revisions, STIX active/inactive/legacy records and relationship persistence, unresolved targets, source-locator replay after reordered snapshots, malformed JSON/IDs/dates/URLs/flags, untrusted text, source-policy restrictions and caller-reviewed annotation boundaries. Full fixture slice: nine documents (eight active), ten explicit relationships; repeated normalization/merge did not duplicate them. This is normalization repeatability, not database idempotence.
- Compatibility: Python 3.10.11; pytest 8.4.2 and its installed dependencies pinned in `backend/requirements-dev.lock`; production dependency lock unchanged. `compileall` and `pip check` passed. No frontend checks rerun because frontend code did not change.
- Additional local, offline pinned-full-STIX replay: 2,091 normalized documents, 20,411 relationships and 1,705 active documents. Explicit diagnostics: 224 legacy external identifiers, four missing descriptions, 2,116 unresolved relationships and 148 unsupported object types. Unsupported types/endpoints remain a documented limitation; this is not a full-corpus ingestion or retrieval validation. No new download, data publication or database write occurred in this replay.

- Policy follow-up: read official rendered NVD Getting Started, API-key Terms of Use (without accepting/submitting the form), expanded API workflows, Data Feeds and CVE license. Verified request limits, shared-key/proxy guidance, pagination, modification windows, attribution/modified-content rules and feed META semantics. Downloaded/read NIST licensing, Microsoft permission policy, NCSC terms/article, OGL v3.0 and 17 USC 105. Current Microsoft terms were followed from the actual HAFNIUM article footer. No full-text override was found on the two reviewed Microsoft candidates.
- Current CISA Terms of Use and Intellectual Property Policy read in the browser after locating live Site Links. Reuse decisions distinguish policy access resolved from worldwide full-report permission unestablished. Historical inaccessible/shell-only downloads remain historical rather than being relabeled as successful policy reads.
- Revision-2 fixture and local-source checks passed, including the new policy-evidence hashes, four-category classification consistency and separate ThreatVector summary authorship. Artifact/corpus hashes refreshed after the reviewed metadata/documentation changes; source section text and relationships remain unchanged.
- Isolated-copy policy checks rejected a metadata-only candidate marked as admitted, an invented policy-evidence reference and a project summary misattributed to NVD, even after test artifact hashes were refreshed. `git diff --check` passed. No application build was rerun because this milestone changes source review, fixture metadata and the offline integrity checker only.

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
- Summary and raw-format fixtures plus pure source normalizers now exist. Full target corpus, database/persistent update behavior and acquisition/ingestion compatibility remain open. STIX object types outside the documented supported set produce diagnostics; missing endpoints remain explicit inactive relationships. NVD bulk/API policy review is complete for the named routes. CISA worldwide original-text rights remain unestablished; project use remains original summaries. Microsoft candidates remain metadata/link-only; linked AA22-257A stays excluded. NCSC article eligibility does not extend to that joint advisory or logos/third-party images.
- Embedding revision, FAISS compatibility, relevance thresholds, tuning/held-out labels, performance and answer quality remain unverified.
- Frontend validates citation membership only. Server must validate ATT&CK IDs and grounding; semantic support requires manual review.
- Optional Google Fonts loads fall back to system fonts offline.
- Separate clean Windows installation, mobile visual verification, real saved benchmark rendering and production browser verification remain open.
- Authentication, private ingestion, cloud hosting, scheduled refreshes and fine-tuning remain excluded.

## Next work

Current user scope covers raw normalizer fixtures and pure normalizers, now implemented and tested. Next phase-1 work is SQLite, deterministic acquisition/ingestion CLI, persistent deduplication/update/idempotence tests, broader report curation and the full target corpus. Complete retrieval and analysis before marking the live interface complete. Compare charts with actual exports during evaluation.

## Milestone log

| Date | Milestone | Evidence |
| --- | --- | --- |
| 2026-10-14 | Planning documents | Documentation only. |
| 2026-10-15 | User requested frontend-first delivery | Scope adjustment in BUILD.md. |
| 2026-10-15 | Foundation and React frontend delivered | Type/build and six tests passed; HTTP health and desktop demo browser checks passed. Live retrieval/evaluation incomplete. |
| 2026-10-15 | Attributed fixture corpus and limited source/reuse review | Six documents, eight sections, five explicit relationships, two unsupported cases; frozen provenance/hashes and offline checks. No ingestion or app integration. |
| 2026-10-15 | Policy gaps revisited; final named-source decisions recorded | Rendered NVD bulk/API policy review completed; current CISA policies read; eight reuse decisions across four categories; Microsoft/NCSC candidates reviewed; integrity checks passed. No ingestion or corpus expansion. |
| 2026-10-15 | Raw source fixtures and pure normalizers | Four raw-format inputs with attribution/notices and a frozen manifest; NVD/STIX/incident adapters; 37 passing tests; additional offline pinned-bundle compatibility replay. SQLite/ingestion and full corpus remain incomplete. |
