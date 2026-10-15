# Public-source and report-reuse review

Reviewed: **2026-10-15, Asia/Calcutta**, follow-up revision 2. Scope: six seed documents, NVD API/bulk policies and named incident-report candidates. This is an evidence-backed reuse decision for these fixture representations, not clearance of every document on a publisher's site. No full-corpus ingestion, vector indexing, model calls, application wiring, or 20-report collection was performed.

## Final project decisions

These categories state what ThreatVector may include under this review, with the listed conditions. They distinguish actual license grants from a conservative project choice. A summary-only decision is not publisher permission for arbitrary quotations, and exclusion pending review is not a claim that a source can never be licensed.

| Source | Category | Decision and conditions |
| --- | --- | --- |
| Selected NVD/CVE records | **Redistributable full text** | Unmodified selected CVE/NIST record content, with applicable NIST and CVE notices retained before distribution. [NVD access/key terms](https://nvd.nist.gov/developers/request-an-api-key), [NIST license](https://www.nist.gov/open/license), and [CVE terms](https://www.cve.org/legal/termsofuse) reviewed. Linked vendor content is not covered. Included summaries are authored and attributed to ThreatVector, with separate upstream references. |
| MITRE ATT&CK T1190 and T1059.001 | **Redistributable full text** | The pinned [release-17.1 license](https://github.com/mitre/cti/blob/dc2ea9270f1a91398c750a6dceb3591b86082ce8/LICENSE.txt) permits reuse with its copyright designation and license. The exact notice is retained locally. No endorsement or linked third-party rights implied. Fixture text remains summarized. |
| CISA/FBI AA22-320A | **Permitted excerpts/summaries only** | Project approval covers original factual summaries only; no verbatim excerpt permission is asserted. Current [Terms of Use](https://www.cisa.gov/terms-use) and [Intellectual Property Policy](https://www.cisa.gov/intellectual-property-policy) were read. They do not establish a general worldwide report-text license. Full prose/PDF republication is not approved for this project without additional rights evidence. |
| CISA/CGCYBER AA22-174A | **Permitted excerpts/summaries only** | Same summary-only project decision. Preserve attribution, historical date and original TLP:WHITE marking. This is not permission to copy logos, graphics, report prose or linked third-party material. |
| Microsoft HAFNIUM report (2021-03-02) | **Metadata and links only** | Read the report and its actual footer-linked [Terms of Use](https://www.microsoft.com/en-us/legal/terms-of-use), especially Personal and Non-Commercial Use Limitation, Content and Documents. The Documents permission excludes network reposting and modifications; no report-specific override was found. No report prose, excerpts, generated report summaries or images are approved for the distributed corpus. |
| Microsoft Log4j exploitation guidance (2021-12-11) | **Metadata and links only** | Same publisher terms and [content-permission guidance](https://www.microsoft.com/en-us/legal/intellectualproperty/copyright/permissions). The page was checked for its own copyright/license override; none establishing corpus redistribution was found. TLP labels attached to separate IOC material do not license the article. |
| NCSC IRGC vulnerability-exploitation article (2022-09-20) | **Redistributable full text** | NCSC-authored article text, under the website's [OGL v3.0 terms](https://www.ncsc.gov.uk/section/about-this-website/terms-and-conditions) and [the OGL](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/). Acknowledge NCSC/Crown copyright and link the license. Exclude logos, third-party images and separately linked documents. This is a reviewed candidate only, not a seventh fixture or a completed incident-report import. |
| CISA AA22-257A linked from that NCSC article | **Excluded sources** | Excluded from corpus acquisition/use at this milestone because the independently coauthored advisory has not received a report-specific rights/content review. The NCSC article's OGL is not transferred through its outbound link. The manifest retains only the audit link and reason; this does not assert a legal prohibition. |

## CISA: what is now resolved

The earlier `/about/website-policies` URL renders **Page Not Found**; the HTTP 403 was not the only issue. Navigating CISA's live Site Links identified the current Terms of Use and Intellectual Property Policy. Their content is now verified, so the policy-access blocker is closed.

The terms provide operating/security conditions, not a blanket content redistribution license. The IP policy specifically reserves logos and marks. [17 U.S.C. 105](https://www.govinfo.gov/content/pkg/USCODE-2024-title17/html/USCODE-2024-title17-chap1-sec105.htm) removes U.S. copyright protection from qualifying U.S. Government works; that does not by itself establish worldwide rights for every element of a joint report. **Government-authored prose may be reusable under U.S. law, but worldwide full-report republication is not established by the reviewed evidence.** For this locally developed, potentially public repository, the final approved representation remains original factual summaries. No permission request was sent and no permission was invented.

Both selected PDFs' notices retain copyright qualifications. [FIRST TLP](https://www.first.org/tlp/) is about sharing boundaries, not an open-content license. Keep the original WHITE/CLEAR labels. Original PDFs, logos, payload commands and copied prose remain ignored local review materials.

## NVD: policy gap closed

Read the rendered Getting Started, key-request Terms of Use, expanded API workflows, data feeds and CVE-license pages. See [NVD_API_POLICY.md](NVD_API_POLICY.md) for the request limits, bulk pagination, feed META validation, key handling, attribution and modified-content rules. The old shell-only download remains recorded as historical failed content review; new rendered-policy evidence supersedes it. No API key, bulk ingestion or scheduler was created.

## Evidence and audit trail

Normalizer-fixture milestone: two unchanged NVD response bodies and an object-preserving subset of the licensed MITRE bundle are now tracked under `raw_normalizers/`, with NIST/CVE notices and the pinned MITRE license. CISA input remains the project-authored summary-manifest representation. These additions follow the recorded decisions and are independently hashed in `data/manifests/raw-normalizers-v1.json`; they do not add candidate report prose or change the six-document summary seed.

`data/manifests/source-review-2026-10-15.json` revision 2 records every named candidate's category, decision scope, conditions, evidence IDs and remaining restrictions. It preserves historical downloads and prior decisions separately. New rendered-body and HTTP evidence snapshots have actual retrieval timestamps, byte sizes and SHA-256 values; they remain under ignored `data/raw/reuse-review-2026-10-15/`. HTML/body evidence is not mislabeled as original HTTP response bytes.

## Provenance and correlation review

- NVD records were retrieved individually through `cveId`; selection is explicit, not a sample claimed representative of the full NVD. API response bytes and selected canonical record hashes are measured separately.
- ATT&CK JSON and the license were fetched using the resolved immutable commit, not a moving branch. The raw bundle is 39,787,657 bytes; only two reviewed technique summaries enter this fixture.
- AA22-320A page 2 identifies CVE-2021-44228 in the overview and maps its reported initial access to T1190. The same page separately labels PowerShell execution T1059.001. The advisory says it uses ATT&CK version 12; that historical version is retained independently of this fixture's release-17.1 technique definitions.
- AA22-174A page 1 explicitly identifies CVE-2021-44228. Neither selected PDF's extracted text contains `45046`; this bounded check does **not** prove that CVE-2021-45046 was never exploited elsewhere.
- CVE-2021-45046's NVD description explicitly refers to the incomplete fix for CVE-2021-44228. This is a vulnerability-to-vulnerability relationship, not evidence of its use in either report.
- Dates come from the API fields or PDF cover pages, not search-engine crawl dates. ATT&CK STIX creation/modification timestamps are separate fields; unavailable publication dates remain `null`.
- Sections are manually curated evidence units, not tokenizer-generated retrieval chunks. No token limits, retrieval relevance, ANN quality or benchmark performance have been measured.

## Before expanding the corpus

Apply each manifest decision to its precise source and representation. Do not import text from metadata-only or excluded candidates. Full-text eligibility requires the listed notices and attribution to accompany distribution; it is not permission to copy a website layout or every linked file. Re-review changed snapshots and new joint authorship or third-party notices. Permission or jurisdiction-specific review is still needed before expanding CISA use beyond the approved summaries or Microsoft use beyond metadata/links.

The user-requested policy/candidate review is complete for the named entries; phase 1 remains incomplete because ingestion, idempotence and the full target corpus are not implemented. No publisher contact, login, terms-acceptance form, payment, crawling or model generation was performed.
