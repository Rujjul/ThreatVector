# SQLite and corpus ingestion

Run from the repository root. Acquisition, ingestion and storage use the standard library; runtime dependencies are unchanged.

## Offline imports

```powershell
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/raw-normalizers-v1.json --database data/fixture.sqlite3 --reviewed-annotations --check-idempotence
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/full-corpus-v1.json --database data/corpus.sqlite3 --reviewed-annotations --check-idempotence
.\.venv\Scripts\python.exe -m backend.cli verify-corpus --manifest data/manifests/full-corpus-v1.json --database data/corpus.sqlite3 --reviewed-annotations --output data/manifests/full-corpus-validation-v1.json
.\.venv\Scripts\python.exe -m backend.cli inspect --database data/corpus.sqlite3
```

The fixture yields nine documents and ten relationships. Without `--reviewed-annotations`, the four stronger incident annotations are omitted; identifier mentions remain. Imported text cannot enable this trusted operator option. Use separate databases for different corpus configurations.

The full import measured **10,000 CVEs, 2,091 ATT&CK records and 20 incident summaries**, with 12,109 sections and 20,432 relationships. There are 11,380 active documents. The 345 rejected NVD records and 386 inactive ATT&CK records remain for provenance. Of 2,121 unresolved relationships, 2,116 have STIX endpoints outside supported object types and five are incident CVE mentions outside the selected sample. Unresolved relationships do not become active evidence.

The full manifest freezes hashes, selected IDs, retrieval times, attribution and notices. `incident-curation-v1.json` records reviewed headings, HTML hashes, page-date labels and original summaries. `source-review-full-v1.json` extends seed decisions. The validation report records actual checks, not retrieval benchmarks.

## Acquisition and preparation

```powershell
.\.venv\Scripts\python.exe -m backend.cli prepare-nvd
.\.venv\Scripts\python.exe -m backend.cli prepare-attack
.\.venv\Scripts\python.exe -m backend.cli acquire-incidents
.\.venv\Scripts\python.exe -m backend.cli prepare-corpus
```

These make bounded public GET requests; incident URLs come from the explicit 18-entry list without link traversal. NVD fetches official 2021 feed META first, waits six seconds, then checks the archive against the **uncompressed** size and SHA-256. Acquisition has three attempts, 45-second request timeouts, bounded sizes and retry delays. No API key, registration or scheduled refresh is used.

Selection is CVE-2021-44228 and CVE-2021-45046 plus the lowest 9,998 other numeric 2021 IDs. Records remain unchanged inside a derived envelope with CNA attribution and NIST/CVE notices. This historical sample includes rejected records; it is not a current-risk census. ATT&CK 17.1 is pinned to `dc2ea9270f1a91398c750a6dceb3591b86082ce8` with a verified bundle hash and MITRE notice.

Acquisition downloads a new snapshot; ingestion replays frozen bytes. Preserve the ignored `data/raw/full-v1/` archive for exact offline replay. A fresh clone can run fixtures immediately; full-v1 requires restoring archived snapshots. Live feeds/pages can change, so new downloads cannot guarantee old hashes. For a newer corpus, review changed passages/terms, freeze a new manifest and use a separate database. Do not silently rewrite reviewed hashes or label a different snapshot full-v1. Preparation rejects HTML differing from reviewed curation hashes.

The database and downloads stay ignored. Small original summaries, manifests and validation reports may be versioned; original CISA HTML/prose are not redistributed. Reports include campaign advisories and recovery guidance, not necessarily 20 distinct victims. Unknown exact publication dates and HTML sharing markings remain absent; agency assessments remain attributed.

## Persistence and checks

Schema version 1 stores documents, sections, relationships, provenance, diagnostics, import receipts and corpus state. Source identities are indexed. Endpoint identifiers may be unresolved; supporting section references have foreign keys. Imports are atomic transactions. Conflicting revisions reject the entire import and roll back writes. Replays merge provenance without duplicates. Automatic replacement/deletion is absent: use a fresh database for an updated revision.

The corpus hash covers content, activity, provenance and diagnostics in deterministic order. Verification re-normalizes hashed inputs, compares complete records and SQL projections, checks integrity/foreign keys and proves another replay changes zero rows. The chunk table is reserved for phase 2 and empty; sections are not tokenizer-generated chunks.

```powershell
.\.venv\Scripts\python.exe -m pytest --basetemp=data/test-temp-corpus-v1
python data/fixtures/verify_fixture.py
```

A workspace-local temporary directory avoids a Windows sandbox rename denial in the system temporary directory. Tests use deterministic HTTP substitutes, without network or paid providers. Unsupported STIX types remain diagnosed. CLI storage is not wired to the placeholder HTTP corpus endpoint or frontend. Chunking, embeddings, FAISS, retrieval, analysis and evaluation remain later work.
