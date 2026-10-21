# Measured FAISS results

Run `faiss-20261021T095559Z` compared 19 standard configurations over the same 13,150 corpus vectors and 60 frozen question vectors. The table below shows the three defaults fixed before held-out evaluation. No source filters or identifier assistance enter this ANN comparison.

| Index | ANN recall@10 vs Flat | Target-document recall@10 | MRR | p50 ms | p95 ms | Peak process MiB |
| --- | --- | --- | --- | --- | --- | --- |
| flat | 1.000 | 0.750 | 0.528 | 1.324 | 1.743 | 137.52 |
| ivf | 0.730 | 0.625 | 0.467 | 0.093 | 0.176 | 146.20 |
| hnsw | 0.900 | 0.667 | 0.510 | 0.145 | 0.236 | 147.80 |

ANN recall uses actual k=10 searches, exactly as timed. Document relevance deduplicates the first 50 chunk candidates to ten documents and uses the 24 supported held-out target judgments. Six unsupported held-out cases are kept separate; their neighbors are not treated as relevant labels. One warm-up and five timed passes were used, one FAISS thread and seed 42. Embedding time is recorded separately, not included in search latency.

Each configuration ran in a fresh process. Peak memory includes imports, input arrays, build, serialization/reload copies and search; it is not steady-state index-only RAM. Serialized bytes measure the actual FAISS serialization. Hardware, versions, source artifact identity, training/build/search parameters and query-set hashes are in the JSON export. The CSV has all 19 configurations. JSON/CSV numeric equality and saved API loading were checked.

Both tuning and held-out metrics are preserved, with defaults fixed in advance and no held-out parameter selection. The incident-only nlist=1 profile is excluded. The observed default IVF/HNSW latency reductions trade off ANN and target-document recall; these observations are specific to this machine/run, not a performance guarantee.

Judgments were agent source inspection, not exhaustive relevance annotation or independent human review. Target-document recall is therefore relative to the recorded targets. Agent source rationales and hashes remain auditable. Actual generated-answer quality and live provider smoke are deferred by the user; the 20 evidence-only attempts have zero rated answers, not fabricated quality scores. See ANSWER_REVIEW.md.

[JSON export](../data/manifests/benchmark-v1.json) · [CSV export](../data/manifests/benchmark-v1.csv)
