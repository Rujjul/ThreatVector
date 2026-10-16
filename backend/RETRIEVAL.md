# Filtered semantic retrieval

Install the optional index environment and prepare the corpus/chunks/indexes as
described in [INDEXES.md](INDEXES.md). Run from the repository root:

```powershell
# No filter: search the full-corpus index.
.\.venv\Scripts\python.exe -m backend.cli search "remote code execution" --top-k 10

# Search each selected partition, then merge their comparable scores.
.\.venv\Scripts\python.exe -m backend.cli search "remote code execution" --source-types cve attack --index flat
.\.venv\Scripts\python.exe -m backend.cli search "vulnerable application" --source-types incident --index ivf

# Explicitly select nothing: empty evidence without query-model startup.
.\.venv\Scripts\python.exe -m backend.cli search "remote code execution" --source-types

.\.venv\Scripts\python.exe -m backend.verify_retrieval
.\.venv\Scripts\python.exe -m backend.verify_safeguards
.\.venv\Scripts\python.exe -m pytest --basetemp=data/test-temp-retrieval
```

`RetrievalService.from_database` validates the active generation and loads a
matching immutable evidence snapshot. Use it as a context manager so its local
query worker is closed. Reload the service after changing corpus/index versions;
automatic refresh and HTTP integration are not implemented. Returned evidence
contains original chunk excerpts, document/source IDs, public links, available
publication dates, attribution, section locators, snapshot hashes and character
offsets. Evidence also retains complete document provenance (including retrieval
timestamps), source modification date, reuse-review identity/category, text kind,
upstream locators, token offsets, content hash and tokenizer revision. Nested
provenance/locator data is copied so editing a response cannot change the stored
snapshot. Missing dates stay absent. Similarity scores do not establish incident
exploitation or source-supported relationships.

## Filter semantics

- `source_types=None` searches the `all` index. An explicit list searches only
  the named partitions, including when all three types are explicitly selected.
- `[]` selects nothing. Unknown types and malformed requests fail; duplicate
  selections are collapsed in `cve`, `attack`, `incident` order.
- Every selected nonempty partition contributes up to `top_k` candidates. Raw
  normalized-vector inner-product scores are comparable across partitions; no
  per-source score rescaling or result quotas are applied. Candidates merge by
  descending score, with chunk-ID ordering for equal candidate scores, and a
  single global result cap. Duplicate chunk IDs retain their highest score.
- This fetches `k` from **each selected subset**, rather than fetching global
  top-k and discarding other types. For exact Flat search, the candidate union
  contains a valid top-k for the selected union. IVF/HNSW remain approximate;
  merging partitions need not reproduce the separate full-corpus ANN index.
- Empty partitions contribute no candidates. An unavailable nonempty strategy
  fails the entire request before query encoding/search, with its recorded
  reason; it never silently substitutes Flat or returns an incomplete merge.
  The incident-only single-list IVF profile is valid for retrieval and retains
  its standard-benchmark exclusion.
- `top_k` defaults to 10 and is limited to 1–50. Queries must be nonblank, at
  most 2,000 characters and within the pinned model's 256-token limit. Longer
  tokenizations are explicitly rejected instead of silently truncated.

## Retrieval safeguards

The native index, retrieval service and CLI share the same default and maximum
constants. Out-of-range values, booleans, strings and noninteger limits are
rejected before embedding or search. Deduplication uses **chunk IDs**, retaining
the highest original score; distinct chunks from one document are preserved.
Native `-1` padding is omitted, while invalid labels and nonfinite scores fail
closed. Scores are never normalized again, rounded or presented as probabilities.

Loading verifies the complete declared generation, not merely the requested
partition. Missing files, partition/strategy entries, malformed JSON, invalid
pointer hashes and mismatched metadata raise `IndexValidationError` before
query-model startup. Typed comparisons prevent values such as float row indexes
or integer normalization flags from passing as valid metadata. Existing hash,
model/runtime, vector reconstruction and native structure checks remain active.
Retrieval snapshot construction also rejects duplicate/missing chunk IDs,
inactive or missing documents, incorrect source types and broken section/offset
joins. Unavailable legitimate skipped configurations remain explicit errors for
selected nonempty partitions. No fallback to another generation, strategy or
synthetic evidence is performed.

`verify_safeguards` records actual default/50-result queries for all three
strategies, exact score/metadata preservation, unique IDs and rejected invalid
limits. Mismatch/incompleteness probes use isolated temporary manifests and never
modify active files. Its report is
`data/manifests/retrieval-safeguards-validation-v1.json`. The optional-dependency
suite passed **167 tests**, including these regression cases. These are functional
checks, not relevance or performance benchmarks.

## CPU query embedding

The pinned MiniLM model embeds queries into normalized float32 vectors locally.
On this Windows environment, Torch and native FAISS operations exposed conflicting
OpenMP runtimes when run in one process. Query embedding therefore uses a
persistent local Python worker with its own Torch runtime; the parent process
uses FAISS. No unsafe duplicate-runtime override is set. The worker verifies
the same pinned model files, uses one CPU thread and communicates through local
JSON pipes. It has no hosted-provider calls or tool execution capability.

The model loads lazily on the first nonempty valid search and remains loaded
for subsequent requests on that service. Worker requests have a 90-second
timeout; failure, invalid vectors or malformed transport output returns an
error rather than fabricated evidence. Context-manager exit closes the worker.
Tests mock query models and worker transport; real local checks are explicit.
`embedding_ms` includes cold worker/model startup on the first request, while
`retrieval_ms` covers partition search, merge and evidence assembly. These are
diagnostics, not the phase-5 latency benchmark.

## Verified behavior

The actual full-corpus checks are recorded in
`data/manifests/filtered-retrieval-validation-v1.json`: 27 filter cases across
Flat/IVF/HNSW, all source subsets, independent candidate merging and exhaustive
Flat subset scores. For the recorded stored-CVE-vector probe, discarding
nonincident hits from full-corpus top-10 produced **0 incident results**;
incident-partition search correctly produced **10**. Three bounded live text
queries verified selected-source membership and source-offset traceability.

Automated adversarial tests likewise place enough higher-scoring CVEs ahead
of every incident result, then verify real native FAISS returns incident hits
through partition search. Tests cover score merging, full/default and explicit
all-type selection, empty/duplicate/invalid filters, global caps, unavailable
strategies, deduplication, deterministic ties, evidence joins, model limits,
worker failures/timeouts and lifecycle. This is functional filter validation,
not relevance labeling or an ANN quality comparison.

Exact CVE/ATT&CK lookup, correlation/generation, threshold calibration and
HTTP/frontend wiring remain separate work. No benchmark figures are inferred
from these functional checks; phase 2 remains in progress.
