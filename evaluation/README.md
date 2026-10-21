# Evaluation inputs

`tuning.json` contains 30 questions: 24 supported target-document cases and six unsupported cases. Codex inspected the named stored sections and recorded rationales, section IDs and source-content hashes on 2026-10-21. This is agent source review, not independent human review. Labels describe intended target-document relevance; they are not exhaustive judgments over every potentially useful corpus document.

Only this split can calibrate `backend.relevance`. The measured policy is in `data/manifests/relevance-policy-v1.json`, bound to corpus/chunk/model identities and these exact question bytes. Binary F1 on the tuning labels selected threshold 0.5398210883140564: 23 true accepts, one false accept and one false reject. Three supported targets are absent from semantic Flat top-10. These limitations are retained, not repaired using held-out labels. The threshold is a heuristic, not an exploitation probability or guaranteed rejection of all unsupported questions.

Run `python -m backend.relevance` explicitly to reproduce calibration. Held-out inputs and benchmark results are separate later-phase deliverables; no held-out labels were used for this policy.
