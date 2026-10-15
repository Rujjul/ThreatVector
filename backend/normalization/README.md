# Source normalization

Pure Python adapters accept raw bytes and explicit project-reviewed source context. They do not open files, make network/provider calls, write a database, tokenize, embed, index or generate explanations. Tests and callers load their own source bytes and trusted manifest configuration.

Public entry points exported by `backend.normalization`:

- `normalize_nvd(raw, context=...)`: NVD API 2.0 envelopes; English descriptions, source IDs, publication/modification metadata, CNA source, source metrics/references and record/snapshot hashes. Rejected or English-description-missing records remain inactive with provenance; missing dates stay absent. Native descriptions are retained as source text; CVE mentions in prose do not become inferred exploitation mappings.
- `normalize_attack(raw, context=...)`: STIX bundles; techniques/sub-techniques, mitigations, groups, campaigns, tools/malware and tactics; actual STIX relationship types/endpoints and supporting descriptions. Revoked/deprecated records remain as inactive evidence. Noncanonical legacy external IDs use stable STIX identities rather than collide with active technique IDs. Unsupported object types and unresolved endpoints produce explicit issues; unresolved relationships remain inactive rather than disappearing.
- `normalize_incidents(raw, contexts=..., reviewed_annotations=False)`: project-defined incident manifests, currently restricted to approved project-authored factual summaries. Preserves source metadata, report-specific page references and original TLP markings. Identifier occurrences create `mentions_identifier` edges only. Stronger annotations require explicit trusted-caller review opt-in and a supporting section containing the named identifier; the adapter does not assess entailment.
- `merge_batches(...)`: deterministic identity/content deduplication with retained snapshot provenance. Conflicting revisions of the same identity raise `NormalizationError`; the caller must choose an update policy when persistence is implemented. Different source identities are never collapsed just because their text is identical. References resolve against the merged document set, respecting inactive assertions/endpoints.

## Trusted context and untrusted source data

`ReuseDecision.from_manifest(project_manifest, decision_id)` reads **trusted project configuration**, not a policy assertion embedded in a report. `SourceContext` supplies that decision, source URI, retrieval timestamp, attribution, representation and optional expected snapshot/upstream hashes. Metadata/link-only and excluded sources are rejected for text normalization. NVD/STIX descriptions must be labeled original source text; this incident-manifest adapter accepts only approved factual summaries. These are structural policy guards, not automated legal clearance or proof that arbitrary text is an original summary.

Caller context can use an HTTP(S) snapshot URL, or a project fixture URN for a selected/derived input with separate upstream URL/hash. Only document source links are user-facing. External references and descriptions are retained as untrusted data and never followed or executed. Invalid UTF-8/JSON, duplicate keys, non-finite numbers, unsupported envelopes, invalid IDs/timestamps, unsafe primary URLs and nonboolean flags fail explicitly. New unsupported STIX entity types must be implemented separately; they are not silently treated as techniques.

## Output and provenance

`Batch` contains document, relationship and issue tuples. Documents contain ordered evidence `Section`s, source metadata, reuse/attribution fields, active state and stable hashes. Sections are **not retrieval chunks**: token limits, token offsets and overlap belong to the later chunker. Every section records its exact input snapshot SHA-256 and JSON pointer. Document/relationship provenance also records input byte count, retrieval time, record pointer and canonical source-record hash. This keeps source references valid even when repeated snapshots have different array ordering.

Document IDs use `nvd:<CVE>`, `incident:<report ID>`, and canonical ATT&CK external IDs when appropriate, with STIX identity fallback for missing/legacy IDs. Content hashes exclude retrieval provenance, while raw snapshot and record hashes preserve the imported evidence. Frozen dataclasses group the output; nested metadata is ordinary JSON data and callers should treat it as read-only.

Structural reference validation cannot prove that an explanation is grounded or a manually reviewed relationship is entailed. Provider-based analysis, citation validation at generation time, persistence/upserts, CLI ingestion, full corpus preparation and retrieval remain separate work.
