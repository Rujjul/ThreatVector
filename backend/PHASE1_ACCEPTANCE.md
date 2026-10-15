# Phase 1 acceptance — complete

Verified on 2026-10-15 against the Phase 1 deliverables and exit criteria in `BUILD.md`. Current corpus: `data/manifests/full-corpus-v2.json`; database: ignored `data/corpus-v2.sqlite3`. Earlier v1 artifacts remain frozen for historical replay.

| Deliverable / exit criterion | Verified evidence |
| --- | --- |
| NVD, ATT&CK and incident normalizers | 60 offline tests pass. The complete ATT&CK profile handles every nonstructural entity type in pinned Enterprise 17.1, including 38 data sources, 109 data components and one matrix. Legacy profiles remain reproducible. |
| SQLite schema | Documents, evidence sections, relationships, provenance, diagnostics, import receipts and corpus state persist. Chunk schema exists; tokenizer-generated chunks belong to phase 2. Integrity is `ok` and foreign-key checks are empty. |
| Permitted attributed fixtures | Frozen seed integrity passes. The new small ATT&CK subset retains unchanged real objects, selected-record hashes, provenance and the MITRE license. NIST/CVE notices are hash-verified. CISA evidence remains original attributed summaries. |
| Full-data manifests and local availability | 10,000 NVD CVEs, 2,239 ATT&CK records and 20 incident summaries are imported. Snapshots retain selected IDs, hashes, retrieval times, attribution and applicable source dates. No fixture substitution or network access occurs during ingestion. |
| Ingestion CLI and persistent idempotence | Complete import and reopen/replay pass. The full verifier records zero database-row changes on repeated ingestion. Conflicting revisions reject the whole transaction; rollback and late endpoint resolution are tested. |
| Metadata, relationships and traceability survive | All 20,411 source STIX relationships are preserved with resolved endpoints. The verifier replays 32,685 record references and 12,257 section text references against exact raw bytes, in addition to checking complete stored records and SQL projections. |

The saved measured result is `data/manifests/full-corpus-validation-v2.json`. Corpus SHA-256: `c3c3cf11a4b1038e3e56db1e362c8febd69c7f911a1b2844abc025a2bbc6d40a`. It contains 12,259 documents, 12,257 sections and 20,432 relationships; 11,524 documents and 20,285 relationships are active. Every nonstructural object in the pinned bundle is normalized. Identity and marking-definition objects remain in the hash-verified raw bundle, rather than becoming retrieval documents.

The earlier completion claim was too broad: v1 omitted 148 ATT&CK metadata objects, leaving 2,116 in-bundle endpoints unresolved. The complete profile closes that gap in v2 without rewriting the v1 manifest, database or validation report. Source code cannot select its own normalization profile; the trusted project manifest selects it.

## Retained corpus boundaries

- Five incident CVE mentions refer to vulnerabilities outside the deterministic 10,000-record historical selection. These source mentions are preserved and explicitly inactive/unresolved; no exploit relationship or missing CVE description is invented. They do not indicate missing entities in the pinned ATT&CK bundle.
- 345 rejected CVEs and 390 inactive ATT&CK records remain for provenance. Four ATT&CK records have no description. One empty upstream translation is omitted with a diagnostic. Legacy external IDs retain stable STIX identities.
- The CVE selection is focused on 2021. The 20 incident reports include campaign advisories and recovery guidance and are represented by original factual summaries, not full source prose or necessarily 20 distinct victims.
- Raw downloads and databases stay outside Git. Exact offline reproduction needs the archived source bytes because upstream pages/feeds can change. The fixture workflow works with committed permitted files alone.
- Chunking, embeddings, FAISS, HTTP/frontend database wiring, retrieval, generation and evaluation are later phases. Their absence does not leave a phase-1 deliverable open.

## Checks run

```powershell
.\.venv\Scripts\python.exe -m pytest --basetemp=data/test-temp-phase1-acceptance-pass
python data/fixtures/verify_fixture.py
.\.venv\Scripts\python.exe -m backend.cli prepare-complete-corpus
.\.venv\Scripts\python.exe -m backend.cli ingest --manifest data/manifests/full-corpus-v2.json --database data/corpus-v2.sqlite3 --reviewed-annotations --check-idempotence
.\.venv\Scripts\python.exe -m backend.cli verify-corpus --manifest data/manifests/full-corpus-v2.json --database data/corpus-v2.sqlite3 --reviewed-annotations --output data/manifests/full-corpus-validation-v2.json
.\.venv\Scripts\python.exe -m compileall -q backend
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

All passed. Frontend code and HTTP routes were unchanged, so frontend builds/browser checks were not repeated. No paid provider calls, new source downloads or retrieval benchmark runs were made during this completion audit.
