"""Offline, measured corpus validation; independent of retrieval/evaluation."""
import json
import platform
import sqlite3
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .ingestion import ROOT, local_path, normalize_manifest
from .normalization.common import canonical, digest, require, NormalizationError
from .storage import CorpusStore, corpus_hash, encode


def pointer(payload, locator):
    require(isinstance(locator, str) and locator.startswith('/'), 'Invalid source JSON pointer')
    try:
        for token in locator[1:].split('/'):
            key = token.replace('~1', '/').replace('~0', '~')
            payload = payload[int(key)] if isinstance(payload, list) else payload[key]
        return payload
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise NormalizationError('Source JSON pointer does not resolve: ' + locator) from exc


def verify_source_references(batch, manifest_path, *, root=ROOT):
    """Replay every stored record and section pointer against exact source bytes.

    One source is decoded at a time; no network, extraction or model is involved.
    """
    root = Path(root)
    manifest = json.loads(Path(manifest_path).read_bytes())
    records, sections = {}, {}
    for item in (*batch.documents, *batch.relationships):
        for p in item.provenance:
            records.setdefault(p.snapshot.sha256, set()).add((p.locator, p.record_sha256))
    for d in batch.documents:
        for s in d.sections:
            sections.setdefault(s.source_snapshot_sha256, []).append(s)
    verified_records = verified_sections = 0
    coverage = None
    seen = set()
    for entry in manifest['entries']:
        sha = entry['sha256']
        if sha in seen:
            continue
        raw = local_path(root, entry['path']).read_bytes()
        require(digest(raw) == sha, 'Source reference snapshot hash mismatch')
        payload = json.loads(raw)
        if entry['format'] == 'stix_bundle' and entry.get('normalization_profile') == 'enterprise_complete_v1':
            source_relationships = {'attack:' + o['id'] for o in payload['objects'] if o['type'] == 'relationship'}
            stored_relationships = {r.id for r in batch.relationships if r.support == 'explicit_stix_relationship'}
            require(source_relationships == stored_relationships, 'Pinned ATT&CK relationships were not fully preserved')
            require(all(r.resolved for r in batch.relationships if r.support == 'explicit_stix_relationship'), 'Pinned ATT&CK relationship endpoints remain unresolved')
            source_documents = {o['id'] for o in payload['objects'] if o['type'] not in {'relationship', 'identity', 'marking-definition'}}
            stored_documents = {d.metadata['stix_id'] for d in batch.documents if d.source_type == 'attack'}
            require(source_documents == stored_documents, 'Pinned ATT&CK entities were not fully preserved')
            coverage = {'source_object_counts': dict(sorted(Counter(o['type'] for o in payload['objects']).items())),
                        'all_nonstructural_entities_preserved': True, 'all_stix_relationships_preserved': True,
                        'all_stix_relationship_endpoints_resolved': True,
                        'structural_objects_retained_in_raw_snapshot': ['identity', 'marking-definition']}
        for locator, expected_hash in records.get(sha, set()):
            require(digest(canonical(pointer(payload, locator))) == expected_hash, 'Source record pointer/hash mismatch')
            verified_records += 1
        for s in sections.get(sha, []):
            text = pointer(payload, s.source_locator)
            require(isinstance(text, str) and text.strip().replace('\r\n', '\n').replace('\r', '\n') == s.text, 'Section source pointer/text mismatch')
            require(digest(s.text.encode('utf-8')) == s.content_sha256, 'Section text hash mismatch')
            verified_sections += 1
        seen.add(sha)
    require(set(records) <= seen and set(sections) <= seen, 'Stored provenance snapshot absent from manifest')
    result = {'source_record_references_verified': verified_records, 'section_source_references_verified': verified_sections}
    if coverage is not None:
        result['attack_coverage'] = coverage
    return result


def verify_corpus(manifest, database, *, root=ROOT, reviewed_annotations=False):
    require(Path(database).is_file(), 'Database does not exist')
    expected, manifest_hash = normalize_manifest(manifest, root=root, reviewed_annotations=reviewed_annotations)
    traceability = verify_source_references(expected, manifest, root=root)
    with CorpusStore(database) as store:
        db = store.connection
        require(store.load() == expected, 'Database content/provenance differs from normalized manifest')
        require(db.execute("SELECT value FROM state WHERE key='corpus_sha256'").fetchone() == (corpus_hash(expected),), 'Stored corpus state hash mismatch')
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
        report.update(traceability)
    return report
