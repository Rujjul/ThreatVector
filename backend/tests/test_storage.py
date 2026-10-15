"""Persistent corpus invariants; offline public fixtures and labeled mutations."""
import json
import sqlite3
from dataclasses import replace

import pytest

from backend.ingestion import ROOT, ingest, local_path, normalize_manifest
from backend.normalization import Batch, NormalizationError
from backend.storage import CorpusStore, corpus_hash

MANIFEST = ROOT / 'data/manifests/raw-normalizers-v1.json'


def fixture():
    return normalize_manifest(MANIFEST, reviewed_annotations=True)[0]


def test_reopen_reimport_preserves_all_metadata_and_no_duplicates(tmp_path):
    path = tmp_path / 'corpus.sqlite3'
    batch = fixture()
    with CorpusStore(path) as store:
        first = store.ingest(batch, 'fixture')
        assert store.load() == batch
        changes = store.connection.total_changes
        again = store.ingest(batch, 'fixture')
        assert store.connection.total_changes == changes
        assert first['corpus_sha256'] == again['corpus_sha256']
        assert again['changed_documents'] == again['changed_relationships'] == 0
    with CorpusStore(path) as store:
        assert store.load() == batch
        assert store.connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert store.connection.execute('PRAGMA foreign_key_check').fetchall() == []
        assert store.connection.execute('SELECT COUNT(*) FROM imports').fetchone()[0] == 1


def test_conflict_rolls_back_entire_import(tmp_path):
    batch = fixture()
    with CorpusStore(tmp_path / 'db') as store:
        store.ingest(batch, 'first')
        conflicting = replace(batch.documents[-1], content_sha256='bad')
        new = replace(batch.documents[0], id='synthetic:new', source_id='synthetic:new')
        with pytest.raises(NormalizationError, match='Conflicting revisions'):
            store.ingest(Batch((new, conflicting)), 'bad-import')
        assert store.load() == batch
        assert store.connection.execute('SELECT COUNT(*) FROM imports').fetchone()[0] == 1


def test_relationships_resolve_when_endpoints_arrive_later(tmp_path):
    batch = fixture()
    incidents = tuple(d for d in batch.documents if d.source_type == 'incident')
    incident_rels = tuple(r for r in batch.relationships if r.source_document_id.startswith('incident:'))
    with CorpusStore(tmp_path / 'db') as store:
        store.ingest(Batch(incidents, incident_rels), 'incidents')
        assert not any(r.resolved for r in store.load().relationships)
        store.ingest(batch, 'all')
        assert store.load().relationships == batch.relationships


def test_additional_snapshot_provenance_is_retained_once(tmp_path):
    batch = fixture()
    d = batch.documents[0]
    p = d.provenance[0]
    another = replace(d, provenance=(replace(p, snapshot=replace(p.snapshot, retrieved_at='2026-10-16T00:00:00Z')),))
    with CorpusStore(tmp_path / 'db') as store:
        store.ingest(batch, 'first')
        store.ingest(Batch((another,)), 'second')
        loaded = next(v for v in store.load().documents if v.id == d.id)
        assert len(loaded.provenance) == 2
        changes = store.connection.total_changes
        store.ingest(Batch((another,)), 'second')
        assert changes == store.connection.total_changes


def test_order_independent_persistent_hash(tmp_path):
    batch = fixture()
    with CorpusStore(tmp_path / 'a') as a, CorpusStore(tmp_path / 'b') as b:
        a.ingest(batch, 'a')
        b.ingest(Batch(tuple(reversed(batch.documents)), tuple(reversed(batch.relationships)), batch.issues), 'b')
        assert corpus_hash(a.load()) == corpus_hash(b.load())


def test_cli_pipeline_and_hash_failure_precedes_database_write(tmp_path):
    path = tmp_path / 'db'
    assert ingest(MANIFEST, path)['documents'] == 9
    manifest = json.loads(MANIFEST.read_bytes())
    manifest['entries'][0]['sha256'] = '0' * 64
    bad = tmp_path / 'bad.json'
    bad.write_text(json.dumps(manifest), encoding='utf-8')
    with pytest.raises(NormalizationError, match='hash mismatch'):
        ingest(bad, path)
    with CorpusStore(path) as store:
        assert len(store.load().documents) == 9


def test_path_escape_and_unrecognized_schema_rejected(tmp_path):
    with pytest.raises(NormalizationError, match='escapes'):
        local_path(tmp_path, '../outside')
    path = tmp_path / 'future.db'
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA user_version=99')
    with pytest.raises(ValueError, match='schema version'):
        CorpusStore(path)


def test_missing_relationship_evidence_section_rolls_back(tmp_path):
    batch = fixture()
    relation = replace(batch.relationships[0], evidence_section_id='missing:section')
    with CorpusStore(tmp_path / 'db') as store:
        with pytest.raises(sqlite3.IntegrityError):
            store.ingest(Batch(batch.documents, (relation,)), 'bad-evidence')
        assert not store.load().documents


def test_full_verifier_detects_tampered_sql_projection(tmp_path):
    from backend.verification import verify_corpus
    path = tmp_path / 'db'
    ingest(MANIFEST, path, reviewed_annotations=True)
    report = verify_corpus(MANIFEST, path, reviewed_annotations=True)
    assert report['idempotence_verified'] and report['replay_database_row_changes'] == 0
    with sqlite3.connect(path) as db:
        db.execute("UPDATE sections SET text='synthetic tampering' WHERE id=(SELECT MIN(id) FROM sections)")
    with pytest.raises(NormalizationError, match='Section SQL projection'):
        verify_corpus(MANIFEST, path, reviewed_annotations=True)
