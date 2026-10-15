# Complete ATT&CK normalization fixture

`attack-complete-subset.json` contains unchanged selected objects from MITRE Enterprise ATT&CK 17.1 at commit `dc2ea9270f1a91398c750a6dceb3591b86082ce8`: a data source, its data component, a technique, the matrix, one actual `detects` relationship, and identity/marking objects. The reduced bundle is a project fixture, not an original HTTP response. Matrix tactic references are preserved as metadata; the subset does not include every tactic.

The source URL, full-bundle hash, selected record hashes, retrieval timestamp and exact fixture-byte hash are in `data/manifests/phase1-attack-fixture-v1.json`. Copyright 2025 The MITRE Corporation; retain `data/fixtures/notices/MITRE-ATTACK-LICENSE.txt` with copies. No linked third-party report text was imported.

Tests compare the legacy and complete normalization profiles, persist the actual detection relationship, replay record/section pointers and use explicitly labeled in-memory mutations for inactive/malformed cases. Full-release coverage is measured separately in `data/manifests/full-corpus-validation-v2.json`.
