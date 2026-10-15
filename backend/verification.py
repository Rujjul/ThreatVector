"""Offline, measured corpus validation; independent of retrieval/evaluation."""
import json
import platform
import sqlite3
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .ingestion import ROOT, normalize_manifest
from .normalization.common import require
from .storage import CorpusStore, encode


def verify_corpus(manifest, database, *, root=ROOT, reviewed_annotations=False):
    require(Path(database).is_file(), 'Database does not exist')
    expected, manifest_hash = normalize_manifest(manifest, root=root, reviewed_annotations=reviewed_annotations)
    with CorpusStore(database) as store:
        db = store.connection
        require(store.load() == expected, 'Database content/provenance differs from normalized manifest')
        integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
        foreign_keys = db.execute('PRAGMA foreign_key_check').fetchall()
        require(integrity == 'ok' and not foreign_keys, 'Database integrity check failed')
        for d in expected.documents:
            require(db.execute('SELECT source_type,source_id,content_sha256,active FROM documents WHERE id=?', (d.id,)).fetchone() == (d.source_type, d.source_id, d.content_sha256, int(d.active)), 'Document SQL projection mismatch')
            rows = db.execute('SELECT id,ordinal,text,payload FROM sections WHERE document_id=? ORDER BY ordinal', (d.id,)).fetchall()
            require(rows == [(s.id, s.ordinal, s.text, encode(asdict(s))) for s in d.sections], 'Section SQL projection mismatch')
        for r in expected.relationships:
            row = db.execute('SELECT source_document_id,target_document_id,evidence_section_id,relationship_type,active,resolved FROM relationships WHERE id=?', (r.id,)).fetchone()
            require(row == (r.source_document_id, r.target_document_id, r.evidence_section_id, r.relationship_type, int(r.active), int(r.resolved)), 'Relationship SQL projection mismatch')
        expected_provenance = {(kind, v.id, p.snapshot.sha256, p.locator, p.record_sha256, encode(asdict(p))) for kind, values in [('document', expected.documents), ('relationship', expected.relationships)] for v in values for p in v.provenance}
        require(set(db.execute('SELECT * FROM provenance')) == expected_provenance, 'Provenance SQL projection mismatch')
        # Import receipts may be added once for a newly frozen manifest; the second
        # complete replay must change no rows, including provenance and receipts.
        report = store.ingest(expected, manifest_hash)
        changes = db.total_changes
        again = store.ingest(expected, manifest_hash)
        require(changes == db.total_changes and not again['changed_documents'] and not again['changed_relationships'], 'Idempotent replay wrote database rows')
        report.update({'schema_version': 1, 'manifest_sha256': manifest_hash,
            'verified_at': datetime.now(timezone.utc).isoformat(), 'idempotence_verified': True,
            'replay_database_row_changes': db.total_changes - changes,
            'manifest_matches_database': True, 'sql_projections_verified': True,
            'integrity_check': integrity, 'foreign_key_errors': foreign_keys,
            'inactive_documents_by_type': dict(Counter(d.source_type for d in expected.documents if not d.active)),
            'unresolved_relationships': sum(not r.resolved for r in expected.relationships),
            'active_relationships': sum(r.active for r in expected.relationships),
            'normalization_diagnostics': dict(sorted(Counter(i.code for i in expected.issues).items())),
            'chunks': db.execute('SELECT COUNT(*) FROM chunks').fetchone()[0],
            'python_version': platform.python_version(), 'sqlite_version': sqlite3.sqlite_version,
            'reviewed_annotations_enabled': reviewed_annotations,
            'limitations': ['Sections are source evidence units, not tokenized chunks.',
                'Inactive records and unresolved relationships are retained; unsupported STIX object types are diagnosed.',
                '2021-focused CVE sample and original incident summaries; no retrieval/answer/index benchmark claimed.']})
    return report
