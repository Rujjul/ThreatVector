# Tokenizer-aware chunks and pinned MiniLM

Run from the repository root. The optional model environment was verified on
Windows x64 / Python 3.10.11; the basic ingestion environment stays lightweight.
Install the CPU wheel first, then the complete optional dependency lock:

```powershell
.\.venv\Scripts\python.exe -m pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu
.\.venv\Scripts\python.exe -m pip install -r backend/requirements-embedding.lock
.\.venv\Scripts\python.exe -m backend.prepare_embedding
.\.venv\Scripts\python.exe -m backend.verify_embedding
.\.venv\Scripts\python.exe -m backend.cli chunk
.\.venv\Scripts\python.exe -m backend.verify_chunking
```

Only `prepare_embedding` accesses the network: eleven explicitly named files
from immutable revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` of
`sentence-transformers/all-MiniLM-L6-v2`. The project lock records measured byte
counts and SHA-256 hashes. Downloads are bounded by those sizes, hash checked,
and replaced atomically. Every load checks all asset hashes, uses local files
only, and disables remote code. Downloaded model assets stay ignored under
`data/models/`; preserve the model card's Apache-2.0 attribution if distributing
assets separately. This project commits the lock and measured verification
reports, not weights or corpus vectors.

The model's frozen configuration uses 384 dimensions, mean pooling and
normalization, with a Sentence Transformers sequence limit of 256. The upstream
BERT position limit of 512 does **not** replace that 256-token limit. The local
CPU smoke check verifies actual inference, finite float32 vectors, unit norms,
repeatability and tokenizer agreement. It is not a retrieval benchmark.

Chunking uses the same fast WordPiece tokenizer, without truncation. Each input
contains a prefix (source type/identifier, title and section heading, capped at
48 tokens), followed by an exact substring of one source section. Re-tokenizing
the complete input ensures the **220-token maximum includes the prefix and
special tokens**. Long titles/headings remain intact in document storage; only
the embedding prefix is shortened. Windows overlap by **30 source-body tokens**,
never cross sections/documents, and exclude inactive documents. Empty sections
produce no chunks. An impossible token budget raises rather than losing text.

`token_start`/`token_end` are end-exclusive offsets into the section's tokenization
without special tokens. `char_start`/`char_end` are Python character offsets into
the exact stored section text, also end-exclusive. The excerpt is the original
substring, never decoded/reconstructed WordPiece text. Leading/trailing whitespace
outside the first/last token is omitted; all source tokens are covered. Prefix
text is separate from the cited excerpt. Stable IDs bind offsets, text, metadata,
ordinal and tokenizer revision; ordinals are document-local.

SQLite's existing `chunks` table stores excerpts and token offsets. The additive
`chunk_details` table stores full chunk payloads, including character offsets,
embedding input and total token count. Both are replaced in one transaction;
failed replacements preserve the previous generation. Identical replay writes
zero rows. `state.chunk_manifest` binds the generation to the corpus hash,
chunk hash, revision and parameters. After additive ingestion, rerun chunking;
future embedding/index consumers must reject a stale corpus/chunk manifest.
Document joins provide URL, publication date, source identifier and provenance;
section joins preserve raw snapshot hashes and source locators.

`verify_chunking` checks the full local corpus: exact source substrings, source
and document links, active-only selection, token coverage/overlap, stored
payloads, token limits, SQL integrity and zero-write replay. Its measured report
is saved separately from frozen phase-1 reports. Unit tests use an offline
deterministic tokenizer double and synthetic boundary cases; the real tokenizer
and CPU model checks above are explicit local integration checks.

Bulk embedding generation and FAISS persistence now have a separate
[index guide](INDEXES.md). Retrieval, filtering and application wiring remain
subsequent work. Phase 2 remains incomplete.
