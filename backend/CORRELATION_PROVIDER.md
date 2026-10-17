# Phase 3 correlation and provider foundations

These services are independent of HTTP routing and generation. Phase 3 remains incomplete: analysis orchestration, untrusted-context prompt construction, grounded output validation/retry and `/analyze` are not implemented by this milestone.

## Correlation

```python
from backend.retrieval import RetrievalService
from backend.correlation import CorrelationService

with RetrievalService.from_database('data/corpus-v2.sqlite3') as retrieval:
    correlation = CorrelationService.from_retrieval(retrieval)
    result = correlation.search('CVE-2021-44228', source_types=['cve', 'incident'])
```

The service validates that relationship and retrieval snapshots share a corpus identity. It expands one hop, in either direction, from retrieved documents; it never computes transitive exploitation chains. Only active, resolved, non-inferred assertions with active endpoints, provenance and recognized explicit support are admitted. Requested source filters apply to endpoints and supporting documents. Explicit empty selection returns no associations.

`source_supported_relationships` retain original direction, type, support category, source locator, text, provenance and metadata. Identifier occurrences remain `mentions_identifier`; only already admitted reviewed annotations may say `reports_exploitation_of`. A source assertion is not independent verification of its truth. No similarity or co-occurrence creates or strengthens a stored relationship.

Supporting section chunks are fetched from the matching immutable chunk snapshot, with original excerpts, offsets, URLs, dates and reuse provenance. They are deduplicated, and their score is `None`: fetching stored support is not a vector search. STIX assertions often have their own description/provenance without a document section. Those remain `source_relationship_record` evidence with zero supporting chunk IDs; endpoint descriptions are never fabricated as proof. A later generation layer must handle such records explicitly and must not invent chunk citations.

`inferred_semantic_associations` identify query-to-chunk similarity only, with original scores and `inferred=True`. They are separate from stored source relationships and explicitly state that similarity does not establish exploitation. Exact-ID matches alone are not inferred associations. Defaults cap expansion at 50 relationships and 50 unique supporting chunks (each configurable from 1 to 50), with deterministic relationship-ID and chunk-ordinal ordering and explicit truncation flags. This is not the later eight-chunk generation context selector, calibrated relevance threshold or formal evaluation.

## Provider adapter

`Provider.generate(messages, response_schema)` is the provider-neutral interface; `OpenAICompatibleProvider` implements a nonstreaming Chat Completions request using the Python standard library. No dependency pins changed. See [official OpenAI Chat API reference](https://developers.openai.com/api/reference/resources/chat) for the compatible messages and response-format contract reviewed during implementation. Provider/model compatibility must still be checked separately.

Use the names in [provider.env.example](provider.env.example) as **server environment variables**. No environment file is loaded automatically. Endpoint is a complete chat-completions URL; model and key have no defaults. Timeout defaults to 60 seconds (valid range greater than zero through 300); it is the HTTP socket-operation timeout, not a guaranteed wall-clock deadline across DNS and all reads. HTTPS is required except local HTTP. URL credentials/query parameters and authorization redirects are rejected. Keys/endpoints are omitted from config representations. Neither secrets nor upstream response bodies/exceptions appear in failure results or logs.

The default mode requests strict `json_schema`. Explicit `json_object` supports endpoints lacking strict schemas; callers must instruct JSON output and validate it themselves. There is no silent capability downgrade, request retry or tool execution. The transport bounds response bytes at 2 MB. Tool calls, incomplete envelopes and non-stop completions fail explicitly. The result contains status and, on success, raw content. Parsing/grounding/schema validation of that content belongs to the next generation milestone.

Statuses include `ok`, `missing_credentials`, `not_configured`, `timeout`, `provider_error`, `invalid_response`, and `refused`. HTTP failures retain only the numeric status. Missing credentials cause no network request. The caller owns retrieved evidence; provider failures cannot remove it. These services are not yet wired to an analysis response, so no end-to-end generation-failure UI claim is made.

Automated tests inject deterministic encoders/transports and require no credentials. No live provider call was made. Actual local correlation checks are recorded in `data/manifests/correlation-validation-v1.json`; they reuse existing corpus, chunks, embeddings and indexes.

Verification: full backend suite **224 passed in 76.83 seconds**; **28 focused tests passed** again after the final malformed-message guard. Dependency, compilation and whitespace checks passed. The actual Log4Shell lookup expanded five stored source relationships and three supporting chunks; CVE-only filtering yielded zero cross-source relationships. These are functional checks, not quality or performance benchmarks.
