# Structured analysis and grounding

`AnalysisService` composes the existing correlation service with the provider-neutral adapter. It is a callable backend service; this milestone does not add `/analyze` or change the frontend.

```python
from backend.analysis import AnalysisService
from backend.correlation import CorrelationService
from backend.retrieval import RetrievalService

with RetrievalService.from_database('data/corpus-v2.sqlite3') as retrieval:
    correlation = CorrelationService.from_retrieval(retrieval)
    analysis = AnalysisService(correlation)  # reads server provider configuration lazily
    result = analysis.analyze('CVE-2021-44228', source_types=['cve', 'incident'])
```

Provider configuration is described in [CORRELATION_PROVIDER.md](CORRELATION_PROVIDER.md). The example can make a paid request if configured; automated tests instead inject deterministic providers. No live provider verification has been performed.

## Structured output

`analysis_contract.StructuredAnalysis` defines strict required fields, forbids extra fields and exports the schema passed to `generate(messages, response_schema)`. The provider supplies `status`, `claims`, `mitigations`, `related_entities`, `uncertainty` codes and `conflicts`. Statements include text, cited chunk IDs and an explicit inferred flag. Entities include canonical ID/title, citations and inferred flag. Potential conflicts identify excerpts from distinct documents. The service adds stored evidence, selected context IDs, original source-supported relationships and inferred associations, timings, grounding mode and generation-attempt/error metadata. This matches the existing frontend's core field shapes; no UI integration is claimed.

At most eight unique chunks are sent, ordered by exact-identifier evidence, supporting relationship chunks, then remaining semantic results. The service checks snapshot identities and selected excerpts against stored chunks. The provider can cite only those eight chunks, even if other evidence is retained in the response. Relationship records without chunks cannot become invented chunk citations. Context objects are copied; the provider cannot mutate stored evidence. Original evidence remains available on every generation failure.

## Conservative grounding policy

Citation membership alone is not evidence of entailment. The default policy therefore permits factual statements only as **one complete, unchanged supplied chunk excerpt with its single citation**. It rejects free-form paraphrases, partial excerpts, removed negation, arbitrary quotations beside unsupported prose, and fabricated citations. This is deliberately extractive analysis, not a claim to have solved general semantic entailment. Source truth, relevance, and mitigation applicability still require review. A source excerpt can itself be wrong; passing this validator does not independently establish its truth.

Mitigations additionally require an active ATT&CK course-of-action source or an explicitly headed mitigation/remediation/recommendation/solution section. Unavailable mitigation evidence produces an empty list. Active ATT&CK identifiers mentioned in output are checked against the canonical corpus, including subtechniques; revoked/inactive/unknown IDs fail validation. Related entities require an active canonical record and its exact stored title, with citations to that entity's own document or text mentioning its ID. Historical out-of-sample CVE mentions may remain verbatim in a real source excerpt; they cannot become an invented active entity.

Inferred prose is limited to one controlled statement saying query similarity does not establish exploitation or a source-supported relationship, cited to semantic evidence and accompanied by semantic uncertainty. Purely semantic entity associations must also be labeled inferred. No inferred mitigation or arbitrary inferred exploitation claim is accepted. Stored relationship types remain unchanged: mentions cannot become exploitation claims through generation.

Conflicts require distinct cited documents and a potential-conflict uncertainty marker. They are displayed as **potential** conflicts for inspection; this validates references and preserves both excerpts, not their semantic contradiction. It does not automatically resolve a conflict or certify that the sources contradict each other.

## Failure and prompt boundaries

One repair attempt is allowed for invalid JSON/schema/citations/grounding/safety, including an invalid provider envelope or malformed provider result object. Duplicate JSON keys, non-JSON constants and excessive nesting are invalid, not ambiguously accepted. Repair feedback contains only a safe validator code; rejected output is not reflected into prompts. A second invalid result returns `generation_error`, empty generated claims/entities/mitigations and unchanged evidence. Missing credentials, configuration errors, timeouts, refusals and provider errors also return evidence and a specific safe error. These failures do not turn into fictional explanations or unhandled provider-text errors. A single terminal failure path clears all generated claims, mitigations, entities and conflict flags, sets `response_mode=evidence_only`, and provides a safe uncertainty message/error code. Successful validated output has `response_mode=validated_analysis`. Unexpected exceptions are isolated only at provider construction/invocation boundaries; retrieval/artifact failures remain explicit errors, never stale evidence fallbacks. A failed repair cannot trigger a third provider call or retain partially validated claims.

Source data and the question are serialized in a user message under fixed system instructions. Only explicit chunk fields and a server-computed mitigation-eligibility flag enter prompts; arbitrary provenance, URLs and imported configuration/role/tool fields are omitted. Canonical entity labels remain untrusted and are screened. Neither evidence nor repair feedback can add system roles, tools, endpoint changes or server secrets. Every attempt receives fresh copies of messages and schema. No tool execution interface is provided.

Conservative indicators screen instruction-like text, role markers, tool-call requests and secret-exfiltration requests. Unicode compatibility normalization and removal of format characters catch common obfuscations. Flagged chunks/titles are withheld from generation (with priority-ordered safe replacements up to eight chunks), while the original source evidence remains inspectable. Unsafe requests or entirely flagged context return evidence-only responses without a provider call. `safety.excluded_chunk_ids` reports omissions. The same check rejects a model copying instruction-like text verbatim into a supposedly grounded claim or entity label.

These are defense-in-depth boundaries, not a complete prompt-injection detector or a guarantee about a live model's internal instruction following. Recognized patterns may also flag legitimate security material that quotes attacks; unknown, encoded or multilingual attacks may evade the indicator check. Strict schema, exact-excerpt validation, no tools, no prompt secrets and no provider configuration from evidence remain independent controls. No flagged source is deleted or silently rewritten, and deterministic tests do not establish universal live-model resistance.

Empty context returns `insufficient_evidence` without calling a provider. Semantic-only context also returns evidence without generation because no tuning-calibrated relevance threshold exists yet (`relevance_not_calibrated`). This preserves the BUILD.md calibration requirement without inventing a threshold or relevance result. Exact-ID context can proceed; the provider may still return structured insufficient evidence. Phase 3 remains incomplete pending relevance calibration and analysis HTTP integration; formal answer evaluation and live-provider checks also remain unperformed.

Run deterministic checks with `python -m pytest backend/tests/test_analysis.py backend/tests/test_analysis_integration.py`. Local actual retrieval with mock generation is recorded separately in `data/manifests/analysis-validation-v1.json`; it is not a relevance/performance benchmark or live provider result.

Verified 2026-10-17: **254 backend tests passed in 63.52 seconds**, including 30 focused analysis cases. Actual local retrieval with deterministic mock generation passed with four context chunks and one validated excerpt; fabricated citations failed after two attempts with unchanged evidence. Dependency, compilation and whitespace checks passed.

Safety verification (2026-10-17): **283 backend tests passed in 64.96 seconds**, including 29 new failure/safety regressions and stored-fixture recovery. Six frontend tests, TypeScript/production build, dependency, compilation and whitespace checks also passed. No live provider checks were performed.
