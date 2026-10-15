# SQLite and corpus ingestion

Run from the repository root. Acquisition, ingestion and storage use the standard library; runtime dependencies are unchanged.

## Offline imports

```powershell
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/raw-normalizers-v1.json --database data/fixture.sqlite3 --reviewed-annotations --check-idempotence
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/full-corpus-v2.json --database data/corpus-v2.sqlite3 --reviewed-annotations --check-idempotence
.\.venv\Scripts\python.exe -m backend.cli verify-corpus --manifest data/manifests/full-corpus-v2.json --database data/corpus-v2.sqlite3 --reviewed-annotations --output data/manifests/full-corpus-validation-v2.json
.\.venv\Scripts\python.exe -m backend.cli inspect
```

The fixture yields nine documents and ten relationships. Without `--reviewed-annotations`, the four stronger incident annotations are omitted; identifier mentions remain. Imported text cannot enable this trusted operator option. Use separate databases for different corpus configurations.

The current v2 import measured **10,000 CVEs, 2,239 ATT&CK records and 20 incident summaries**, with 12,257 sections and 20,432 relationships. There are 11,524 active documents. The 345 rejected NVD records and 390 inactive ATT&CK records remain for provenance. Every source STIX relationship now has resolved endpoints. Five incident CVE mentions remain outside the selected CVE sample and do not become active evidence. The earlier v1 manifest/database/report remain frozen with their legacy profile. See `PHASE1_ACCEPTANCE.md` for the closure audit.

The full manifest freezes hashes, selected IDs, retrieval times, attribution and notices. `incident-curation-v1.json` records reviewed headings, HTML hashes, page-date labels and original summaries. `source-review-full-v1.json` extends seed decisions. The validation report records actual checks, not retrieval benchmarks.

## Acquisition and preparation

```powershell
.\.venv\Scripts\python.exe -m backend.cli prepare-nvd
.\.venv\Scripts\python.exe -m backend.cli prepare-attack
.\.venv\Scripts\python.exe -m backend.cli acquire-incidents
.\.venv\Scripts\python.exe -m backend.cli prepare-corpus
.\.venv\Scripts\python.exe -m backend.cli prepare-complete-corpus
```

These make bounded public GET requests; incident URLs come from the explicit 18-entry list without link traversal. NVD fetches official 2021 feed META first, waits six seconds, then checks the archive against the **uncompressed** size and SHA-256. Acquisition has three attempts, 45-second request timeouts, bounded sizes and retry delays. No API key, registration or scheduled refresh is used.

Selection is CVE-2021-44228 and CVE-2021-45046 plus the lowest 9,998 other numeric 2021 IDs. Records remain unchanged inside a derived envelope with CNA attribution and NIST/CVE notices. This historical sample includes rejected records; it is not a current-risk census. ATT&CK 17.1 is pinned to `dc2ea9270f1a91398c750a6dceb3591b86082ce8` with a verified bundle hash and MITRE notice.

Acquisition downloads a new snapshot; ingestion replays frozen bytes. Preserve the ignored `data/raw/full-v1/` archive: both full-v1 and full-v2 use these same source bytes. A fresh clone can run fixtures immediately; exact full-corpus replay requires restoring archived snapshots. Live feeds/pages can change, so new downloads cannot guarantee old hashes. For a newer source snapshot, review changed passages/terms, freeze a new manifest and use a separate database. Do not silently rewrite reviewed hashes or label different bytes as an old snapshot. Preparation rejects HTML differing from reviewed curation hashes. `prepare-complete-corpus` creates v2 by selecting the complete normalization profile over the existing frozen v1 sources, without downloading or changing upstream data.

The database and downloads stay ignored. Small original summaries, manifests and validation reports may be versioned; original CISA HTML/prose are not redistributed. Reports include campaign advisories and recovery guidance, not necessarily 20 distinct victims. Unknown exact publication dates and HTML sharing markings remain absent; agency assessments remain attributed.

## Persistence and checks

Schema version 1 stores documents, sections, relationships, provenance, diagnostics, import receipts and corpus state. Source identities are indexed. Endpoint identifiers may be unresolved; supporting section references have foreign keys. Imports are atomic transactions. Conflicting revisions reject the entire import and roll back writes. Replays merge provenance without duplicates. Automatic replacement/deletion is absent: use a fresh database for an updated revision.

The corpus hash covers content, activity, provenance and diagnostics in deterministic order. Verification re-normalizes hashed inputs, replays raw record/section JSON pointers, compares complete records and SQL projections, checks integrity/foreign keys and proves another replay changes zero rows. The complete profile also checks every source STIX entity/relationship is preserved. Manifest versions and notice hashes are validated before import. The chunk table is reserved for phase 2 and empty; sections are not tokenizer-generated chunks.

```powershell
.\.venv\Scripts\python.exe -m pytest --basetemp=data/test-temp-corpus-v1
python data/fixtures/verify_fixture.py
```

A workspace-local temporary directory avoids a Windows sandbox rename denial in the system temporary directory. Tests use deterministic HTTP substitutes, without network or paid providers. Unsupported STIX types remain diagnosed. CLI storage is not wired to the placeholder HTTP corpus endpoint or frontend. Chunking, embeddings, FAISS, retrieval, analysis and evaluation remain later work.
