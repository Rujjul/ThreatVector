# Attributed seed corpus

Raw source-shaped normalizer fixtures are now available separately in [raw_normalizers/](raw_normalizers/README.md), with NVD/CVE notices and the pinned MITRE license. The seed corpus described below remains six curated summary documents; the new raw inputs are tested through `backend/normalization/` and do not change the application demo.

`corpus.json` contains **six documents, eight curated sections, five explicit relationships and two unsupported cases**:

| Type | Selected sources |
| --- | --- |
| Vulnerability | NVD CVE-2021-44228; NVD CVE-2021-45046 |
| Technique | MITRE ATT&CK T1190; T1059.001, Enterprise release 17.1 |
| Historical incident evidence | CISA/FBI AA22-320A; CISA/CGCYBER AA22-174A |

The retrieval-oriented text is an original factual summary, **not an original source excerpt**. Every section declares this representation and points to an upstream JSON field or PDF page/heading. Display it as a curated summary if wired into the UI later; do not label it a verbatim excerpt. No UI or backend integration has been performed. The existing browser demo remains fictional and separate.

Stable document/section IDs support subsequent ingestion work. Relationships cite a source section and have `support: explicit_source_statement`, with report-specific relationship types. No similarity scores, CVSS values, inferred campaign identities, embedding vectors or performance metrics are supplied. The unsupported cases cover the tempting but unsupported CVE-2021-45046 incident link and a shared-campaign assumption.

Provenance includes original URLs, available publication dates, retrieval timestamps, attribution, raw-source SHA-256, selected-record SHA-256 where applicable, and summary-content hashes. ATT&CK definitions are pinned to commit `dc2ea9270f1a91398c750a6dceb3591b86082ce8`. Publication dates absent from selected STIX objects remain `null`. Retrieval timestamps are UTC; local retrieval date is recorded with Asia/Calcutta timezone.

## Reuse and attribution

Read [SOURCE_REVIEW.md](SOURCE_REVIEW.md) and preserve source attribution and [the MITRE notice](notices/MITRE-ATTACK-LICENSE.txt). The repository MIT license applies to original project work; it does not replace upstream terms or grant rights to linked source documents. The MITRE notice is copied unchanged from the pinned source and includes its original 2025 copyright designation. No publisher endorsement is implied.

Original CISA prose, PDFs, third-party graphics, executable payloads and complete raw datasets are excluded from tracked fixtures. Full CISA report-text redistribution remains uncleared; summaries restate verified facts. NVD descriptions identify Apache as the CNA source, so the fixture does not indiscriminately call all NVD text government-created public-domain work.

Follow-up review revision 2 closes the CISA policy-access and NVD JavaScript-shell gaps. Current CISA policies still do not establish a worldwide full-report license, so only original factual summaries are approved. [NVD_API_POLICY.md](NVD_API_POLICY.md) documents verified API/bulk access and modified-content attribution rules. NVD-based summaries explicitly identify ThreatVector as author and retain original-record provenance separately.

Every manifest entry now has one of four decisions: **Redistributable full text**, **Permitted excerpts/summaries only**, **Metadata and links only**, or **Excluded sources**, with source-specific conditions. Eligibility for full text does not change the fixture's current summary representation. Two Microsoft candidates remain metadata/link-only; one NCSC-authored article is eligible under OGL v3.0; its separately linked joint advisory is excluded pending independent review. These candidates were not added to the six-document fixture.

## Verify the frozen snapshot

From the repository root, using standard-library Python only:

```powershell
python data/fixtures/verify_fixture.py
```

This verifies committed artifact hashes, content hashes, counts, unique IDs, provenance fields, explicit relationship references, notice preservation and negative-case boundaries. If this workspace still has the ignored downloaded snapshots, also run:

```powershell
python data/fixtures/verify_fixture.py --check-local-sources
```

The second check verifies exact downloaded bytes and selected NVD/STIX object hashes and source locators. It makes no network calls. Missing local downloads cause an explicit failure, not a fixture substitution. A clean clone can perform the first check without downloads.

Verification also checks the final reuse categories, candidate admission restrictions, policy-evidence references and separate summary attribution. With local sources present, it checks the policy evidence hashes as well. It does not automatically determine copyright status or certify legal compliance.

`../manifests/fixture-v1.json` is the frozen fixture manifest; `../manifests/source-review-2026-10-15.json` records review decisions and retrieval evidence. Future live NVD responses can change: their historical bytes are not promised reconstructible from a mutable URL. The committed curated snapshot is self-contained; raw downloaded snapshots remain ignored local artifacts. PDF page references and factual support were reviewed manually, not inferred by the checker.

This is not the target 10,000-CVE/20-report corpus, a raw ingestion-normalizer fixture, an evaluation question set or proof of phase-1 completion. The checked-in verification script is an offline integrity check only.
