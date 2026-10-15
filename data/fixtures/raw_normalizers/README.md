# Raw normalizer inputs

These offline fixtures exercise source-shaped adapters. They are separate from the six-document `../corpus.json` summary seed and are not wired into the application.

| Input | Representation and origin |
| --- | --- |
| `nvd-44228.json` | Exact NVD API 2.0 response bytes for CVE-2021-44228 from the reviewed bounded download. |
| `nvd-45046.json` | Exact NVD API 2.0 response bytes for CVE-2021-45046. |
| `attack-enterprise-17.1.json` | Bundle subset from pinned MITRE ATT&CK Enterprise 17.1: T1190, T1059, T1059.001, M1051, a deprecated legacy mitigation, two actual STIX relationships and their identity/marking objects. Selected object bodies are unchanged. The bundle as a whole is reduced, not an original full HTTP response. |
| `incident-summaries.json` | ThreatVector-authored raw incident-manifest input containing the approved CISA summaries and four manually reviewed annotations. It is not original CISA prose or a raw report PDF. |

`data/manifests/raw-normalizers-v1.json` records exact input hashes, original response/bundle provenance, selected-record hashes, timestamps, representations, context/policy IDs and applicable notices. Subset and project-manifest inputs use `urn:threatvector:fixture:...` snapshot origins so they are not falsely presented as response bytes from the upstream URL. The original upstream URL/hash is recorded separately. For the incident fixture, local curation/read time is distinct from each original report's retrieval timestamp.

## Attribution and notices

- **NVD/CVE:** preserve [NIST's non-SRD data/work notice](../notices/NIST-DATA-NOTICE.txt) and [CVE terms/designation](../notices/CVE-TERMS.txt). NVD publishes the original record; the CNA description source is Apache Software Foundation. These raw responses are unchanged; they are not the project-authored summaries in the separate seed corpus.
- **MITRE ATT&CK:** preserve [the exact pinned 2025 notice/license](../notices/MITRE-ATTACK-LICENSE.txt). No endorsement is implied. Original technique and relationship descriptions remain source text, not generated explanations.
- **CISA:** original factual summaries are attributed to ThreatVector; original report metadata, page references and sharing labels are retained. Original CISA prose, logos and PDFs remain excluded from tracked inputs under the final source-review decision.

The repository MIT license does not replace upstream notices. No Microsoft article text or excluded AA22-257A material is included. New synthetic malformed, revoked, missing-field and injection cases are created only as explicitly labeled in-memory test mutations; they are not represented as real public incidents.

## Input contract and verification

NVD uses its actual `NVD_CVE`/`2.0` response envelope with `vulnerabilities[].cve`. STIX uses `type: bundle` and `objects[]`. The project-defined incident format is `threatvector_incident_manifest`, integer `version: 1`, and `reports[]` containing identity, source URL/date, reuse ID, sections and optional annotations. Each section supplies `key`, `heading`, `text`, `text_kind` and `upstream_locator`. An annotation supplies `target_source_id`, `relationship_type`, `section_key` and `basis`.

The incident adapter does not scrape HTML or extract PDFs. Stronger annotations require a trusted caller's `reviewed_annotations=True`; an imported document cannot enable that setting. Without it, the normalizer records identifier occurrences as `mentions_identifier` only. Neither identifier presence nor structural annotation validation proves semantic entailment.

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend/requirements-dev.lock
.\.venv\Scripts\python.exe -m pytest
python data/fixtures/verify_fixture.py
```

The deterministic normalization slice yields **nine documents** (eight active, one deprecated legacy mitigation) and **ten explicit relationships** (two STIX statements, four identifier mentions, four caller-reviewed source annotations). This is an in-memory normalization result, not a database import, benchmark, or enlargement of the six-document application seed.
