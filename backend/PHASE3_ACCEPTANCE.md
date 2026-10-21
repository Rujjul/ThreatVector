# Phase 3 acceptance

Functional status: complete after the recorded full-suite verification in Progress.md. Live-provider and answer-quality evaluation are not implied.

| Deliverable / exit criterion | Evidence |
| --- | --- |
| Correlation service | Snapshot-bound, bounded one-hop explicit relationships; source support separate from inferred query similarity. Correlation tests and `correlation-validation-v1.json`. |
| Provider adapter | Server-only endpoint/model/key/timeout; no tools or prompt secrets; deterministic timeout/refusal/error/credential tests. |
| Structured output, citations and grounding | Strict schema; eight deduplicated chunks; exact excerpts, active entities, sent-context citations; one repair then evidence-only fallback. Analysis, safety and fixture pipeline tests; `analysis-validation-v1.json`. |
| Unsupported/conflicting/injection/error cases | Mocked cases preserve potential conflicts and uncertainty; injection indicators plus role/schema/extractive boundaries; evidence survives failed repair and later search/analysis recovers. |
| HTTP composition | `test_analysis_api.py`: valid analysis, strict invalid inputs, missing credentials/timeouts/provider errors, empty/unsafe/unsupported requests and fail-closed invalid artifacts. |
| Calibrated semantic eligibility | 30 agent-reviewed tuning questions only; pinned corpus/chunk/model, policy threshold 0.5398210883140564. Binary tuning F1 0.9583, one false accept/one false reject; three intended targets missed by Flat semantic top-10. No held-out judgments used. |

Review is explicitly agent source inspection, not independent human assessment. Grounding is conservative/extractive, not general paraphrase entailment. Prompt indicators are neither exhaustive nor a live-model security guarantee. The user chose to proceed without a configured live provider. That delivery smoke test and actual generated-answer review remain open and must not be reported as passed.
