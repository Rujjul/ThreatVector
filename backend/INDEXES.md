# Local embeddings and FAISS artifacts

Use the verified Windows x64 / Python 3.10.11 environment. Complete ingestion
and [chunk construction](CHUNKING.md) first. Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu
.\.venv\Scripts\python.exe -m pip install -r backend/requirements-index.lock
.\.venv\Scripts\python.exe -m backend.prepare_embedding
.\.venv\Scripts\python.exe -m backend.cli build-indexes
.\.venv\Scripts\python.exe -m backend.cli validate-indexes --output data/manifests/index-validation-v2.json
.\.venv\Scripts\python.exe -m pytest --basetemp=data/test-temp-indexes
```

The optional lock adds `faiss-cpu==1.10.0` to the previously verified embedding
environment (including NumPy 1.26.4). The core ingestion dependency lock stays
unchanged. FAISS tests use the real installed CPU library and a deterministic
encoder double; they explicitly skip when the optional FAISS dependency is
absent. Install the index lock to run the complete suite. No paid providers are
used. Downloading the pinned model is explicit; building and loading are offline.

## Verified full-corpus build (2026-10-16)

The actual full-corpus CPU run produced shared embeddings for 13,150 chunks.
Independent reload validation passed; the measured report is
`data/manifests/index-validation-v1.json` freezes the original 11-index build.
The incident exception is recorded separately in `index-validation-v2.json`;
the original report remains unchanged.

| Partition | Chunks | FlatIP | IVFFlat | HNSWFlat |
| --- | --- | --- | --- | --- |
| Complete corpus | 13,150 | Ready | Ready | Ready |
| CVE | 10,177 | Ready | Ready | Ready |
| ATT&CK | 2,951 | Ready | Ready | Ready |
| Incident | 22 | Ready | Ready: retrieval-only `nlist=1`, `nprobe=1` | Ready |

The original optional-dependency suite passed 106 tests; the incident-IVF
follow-up passed **109 tests**. Schema-2 validation verified **12 indexes** and
**78,900 indexed vector instances**, including all-incident exhaustive Flat
equivalence, persistence and benchmark exclusion. Full-corpus
validation uses actual model assets/vectors; automated tests substitute the
encoder and model-asset check, and use real FAISS. Initial embedding preparation
took about 1,336 seconds on one CPU thread including model setup and cache
validation/writing. Per-index timings are also recorded as diagnostics; these
are not the phase-5 benchmark or a claim about retrieval quality/performance.

## Strategies and shared vectors

`IndexFlatIP` is the default exact baseline. `IndexIVFFlat` uses a FlatIP coarse
quantizer, fixed seed 42, 25 clustering iterations and a deterministic sample of
up to 100,000 vectors. `IndexHNSWFlat` uses inner product and graph seed 42. All
strategies receive the **same ordered, normalized float32 384-dimensional vector
matrix**; reconstructing persisted vectors checks their values and order exactly.

Defaults are IVF `nlist=64`, `nprobe=4`; HNSW `M=16`, `efConstruction=200`,
`efSearch=64`. Build and search use one FAISS thread. CLI options `--nlist`,
`--nprobe`, `--m`, and `--ef-search` select the documented parameter ranges.
These are reproducible starting parameters, not tuned or recommended winners.
The model runs locally on CPU with one Torch thread and batch size 32; complete
embedding input lengths are checked against the actual pinned tokenizer before
encoding. Nonfinite, zero, nonunit, wrong-dimension or wrong-dtype vectors fail.

Each generation includes the complete corpus plus CVE, ATT&CK and incident
partitions built from slices of that same matrix. Standard IVF partitions with
fewer than 39 training vectors per centroid skip with an explicit reason.
The user-directed incident-only exception always uses `nlist=1`, `nprobe=1` and
`minimum_per_centroid=1`. The 22 vectors therefore train without applying the
standard 39-vector minimum. Empty partitions still skip every strategy.

Schema-2 manifests record each ready IVF entry's effective `ivf_configuration`:
list/probe counts, training minimum, profile, comparison group and benchmark
eligibility. Incident IVF has `profile=incident_single_list`,
`comparison_group=incident_retrieval_only` and
`standard_benchmark_eligible=false`. All other IVF entries use the global
standard configuration; `--nlist 1` remains invalid globally. The loader checks
these declarations against the partition policy and native index. Schema-1
generations remain readable with their original incident-skip behavior.

`IndexBundle.benchmark_index` rejects the reduced incident IVF configuration
for standard comparisons. Retrieval can use it through `search`; with its one
list fully probed it searches the complete incident subset. This configuration
is not an ANN performance comparison or evidence of an indexing advantage.

## Persistence and validation

`data/embeddings/<identity-hash>/` retains a reusable vector snapshot: `vectors.npy`,
`rows.json` and a manifest. Model revision, model asset lock hash, corpus/chunk
hashes, chunk settings, dimensions, normalization, dtype, Python and embedding
library versions bind the snapshot. A matching cache is validated before reuse;
a corrupted matching cache fails instead of being silently regenerated.

`data/indexes/<generation>/` contains its own identical vector snapshot, chunk-ID
row mapping, FAISS files and a manifest. Index metadata adds FAISS version,
metric, seed, thread count, training provenance and build/search parameters.
File SHA-256 hashes and byte sizes are recorded. Row mappings are validated
against current SQLite chunks, documents, source types and active state.
The SQLite corpus state, chunk hash, chunk IDs, excerpts, source offsets and SQL
chunk projections must agree before either building or loading.

All checksums are verified **before** FAISS deserialization. Loaded indexes must
match their declared class, metric, dimension, count, training state, search
parameters and exact reconstructed vectors. FAISS does not serialize IVF's
clustering-parameter object: the manifest records its seed/iterations as build
provenance; reload validation checks the resulting quantizer and vectors and the
persisted search parameters. Do not import untrusted native FAISS files; checksums
detect corruption and generation mismatch, not a malicious author's intent.

Builders write a new generation, validate every file/index and compare search
results before/after serialization, then check the corpus is still current.
Only then does an atomic replacement of `active.json` select the generation.
The pointer pins the manifest hash and permits only a generated directory name.
A failed build leaves the previous active pointer unchanged. Incomplete and
older generations remain ignored on disk for inspection; no automatic deletion
is performed. Rebuilding reuses verified embeddings but creates new indexes.
Readers reject changed corpus/chunks, model assets/revision, versions, vector
properties, row order, parameters or damaged files. Rebuild after an intentional
corpus/model/runtime change rather than editing manifests to bypass rejection.

`IndexBundle.search` is a low-level vector interface with Flat as default, a
single explicit partition and a 1–50 result cap. It excludes FAISS's `-1` padding
IDs and maps row numbers back to chunk IDs. [Filtered semantic retrieval](RETRIEVAL.md)
now adds query embedding and multi-source partition merging through a separate
service/CLI. Exact-ID supplementation and HTTP/frontend integration remain open.
The index milestone does not complete phase 2.

`validate-indexes` exports actual integrity, vector reconstruction, partition
membership and repeated-search checks. Per-index build durations and embedding
preparation duration are diagnostic observations (the latter includes cache
validation on reuse), not the phase-5 latency/memory or relevance benchmark.
No ANN recall, held-out relevance, answer quality or performance advantage is
claimed. Generated model files, vectors, row mappings and native indexes stay
under ignored data directories; only small validation reports are committed.

Implementation references: [FAISS index classes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes)
and [FAISS persistence and parameter handling](https://github.com/facebookresearch/faiss/wiki/Index-IO,-cloning-and-hyper-parameter-tuning).
