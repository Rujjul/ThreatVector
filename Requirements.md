# ThreatVector requirements

## Goal and audience

Build a local cybersecurity RAG portfolio application centered on semantic vulnerability correlation, hybrid retrieval, evidence-grounded explanations, and FAISS indexing. Hybrid retrieval combines exact CVE/ATT&CK identifier lookup with semantic vector retrieval; lexical/BM25 ranking is not part of the current scope. Historical incident reports provide supporting evidence for vulnerability correlations. Reviewers must be able to inspect evidence and reproduce comparisons of FAISS Flat, IVF, and HNSW indexes.

## Scope

- React/TypeScript frontend; Python/FastAPI backend; SQLite metadata storage.
- Local CPU embedding and retrieval; configurable hosted LLM for explanations.
- Public NVD CVE data, MITRE Enterprise ATT&CK data, and curated public incident reports.
- Investigation, evidence-detail, and benchmark views.
- CLI commands for ingestion, index construction, and evaluation.

Excluded from v1: generic log monitoring, incident dashboards, SIEM workflows, authentication, private documents, multi-user operation, cloud deployment, automated refresh schedules, model fine-tuning, and arbitrary web crawling.

## Functional requirements

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| R1 | Reproducible public corpus | A manifest identifies the source snapshot, selected records, retrieval dates, and hashes; repeated ingestion does not duplicate records. |
| R2 | Traceable evidence | Each chunk resolves to its source document, public URL, and available publication date and source identifier. Missing metadata is explicitly absent. |
| R3 | Semantic and identifier retrieval | Natural-language queries retrieve ranked evidence; exact CVE and ATT&CK IDs resolve directly and receive supplemental semantic results. |
| R4 | Comparable indexes | FlatIP, IVFFlat, and HNSWFlat use identical normalized embeddings and corpus snapshots. |
| R5 | Correct filters | Source-type filters search the matching corpus subset rather than discarding only nonmatching top results. |
| R6 | Evidence-based correlation | Source-supported relationships and semantic associations are displayed distinctly; similarity does not prove exploitation. |
| R7 | Grounded analysis | Explanations, techniques, and mitigations cite retrieved evidence. Citation IDs and technique IDs are validated before rendering. |
| R8 | Honest uncertainty | Unsupported questions, contradictory sources, and inferred associations are explicitly identified. |
| R9 | Graceful provider failure | Retrieval remains usable without credentials or when the hosted model times out or returns invalid output. |
| R10 | Inspectable UI | Reviewers can ask questions, select an index, filter source types, inspect excerpts and sources, and view benchmark charts. |
| R11 | Reproducible evaluation | Export actual metrics with corpus hash, parameters, seed, versions, hardware, and thread count. |
| R12 | Local setup | Document Windows setup, configuration, source preparation, sample queries, and verification steps. |

## Data and evaluation targets

- Full demo corpus: 10,000 NVD CVE records, a pinned Enterprise ATT&CK release, and 20 curated public incident reports.
- Begin with a small attributed fixture corpus. Verify source availability and reuse terms before distributing report text.
- Use 60 manually reviewed questions: 30 tuning queries and 30 held-out queries. Include vulnerability lookup, technique discovery, incident correlation, and unsupported questions.
- Report ANN recall@10 against Flat separately from document relevance recall@10 and MRR.
- Measure p50/p95 search latency, build time, serialized index size, and peak process memory; report embedding and generation timing separately.
- Manually assess 20 held-out answers for evidence support, technique accuracy, and mitigation relevance. Record the rubric and results.

## Quality requirements

- No hosted-model API keys in the browser, committed files, or logs.
- Treat retrieved text as untrusted context; document prompt injection must not override analysis instructions.
- Pin dependency versions and model revision; reject indexes whose metadata does not match the active corpus and embedder.
- Preserve retrieval access on generation failure, with a visible error status.
- Automated tests use deterministic model mocks; live-provider verification is documented separately.
- Publish observed quality and performance without promising a latency threshold or ANN advantage before measurement.

## Definition of done

All implementation phases in `BUILD.md` meet their exit criteria; backend tests and frontend type/build checks pass; the end-to-end demonstration works; actual benchmark exports and answer-review results are available; setup documentation and known limitations are current. A missing full corpus or unperformed live-provider test must be reported as incomplete validation.
