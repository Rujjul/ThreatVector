"""Transactional, immutable-revision SQLite corpus storage (standard library only)."""
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from .normalization import Batch, Document, Relationship, Section, Snapshot, merge_batches
from .normalization.models import Issue, Provenance
from .normalization.common import canonical, digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
 id TEXT PRIMARY KEY, source_type TEXT NOT NULL, source_id TEXT NOT NULL,
 content_sha256 TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)),
 payload TEXT NOT NULL, UNIQUE(source_type, source_id));
CREATE INDEX IF NOT EXISTS documents_source ON documents(source_type, active);
CREATE TABLE IF NOT EXISTS sections (
 id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id),
 ordinal INTEGER NOT NULL, text TEXT NOT NULL, payload TEXT NOT NULL,
 UNIQUE(document_id, ordinal));
CREATE TABLE IF NOT EXISTS relationships (
 id TEXT PRIMARY KEY, source_document_id TEXT NOT NULL, target_document_id TEXT NOT NULL,
 evidence_section_id TEXT REFERENCES sections(id), relationship_type TEXT NOT NULL,
 active INTEGER NOT NULL, resolved INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS relationships_target ON relationships(target_document_id);
CREATE TABLE IF NOT EXISTS chunks (
 id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id),
 section_id TEXT NOT NULL REFERENCES sections(id), ordinal INTEGER NOT NULL,
 text TEXT NOT NULL, token_start INTEGER NOT NULL, token_end INTEGER NOT NULL,
 content_sha256 TEXT NOT NULL, tokenizer_revision TEXT NOT NULL,
 CHECK(token_start >= 0 AND token_end > token_start), UNIQUE(document_id, ordinal));
CREATE TABLE IF NOT EXISTS provenance (
 entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, snapshot_sha256 TEXT NOT NULL,
 locator TEXT NOT NULL, record_sha256 TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(entity_type, entity_id, payload));
CREATE TABLE IF NOT EXISTS issues (payload TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS imports (
 manifest_sha256 TEXT PRIMARY KEY, corpus_sha256 TEXT NOT NULL, report TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def encode(value):
    return canonical(value).decode('utf-8')


def provenance(values):
    return tuple(Provenance(Snapshot(**v['snapshot']), v['locator'], v['record_sha256']) for v in values)


def document(value):
    value = dict(value)
    value['sections'] = tuple(Section(**s) for s in value['sections'])
    value['provenance'] = provenance(value['provenance'])
    return Document(**value)


def relationship(value):
    value = dict(value)
    value['provenance'] = provenance(value['provenance'])
    return Relationship(**value)


def corpus_hash(batch):
    """Hash content, activity and full provenance; independent of ingestion order."""
    return digest(canonical(asdict(merge_batches(batch))))


class CorpusStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=30)
        self.connection.execute('PRAGMA foreign_keys=ON')
        version = self.connection.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            self.connection.close()
            raise ValueError(f'Unsupported corpus schema version {version}')
        self.connection.executescript(SCHEMA)
        self.connection.execute('PRAGMA user_version=1')
        self.connection.commit()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.connection.close()

    def load(self):
        db = self.connection
        return Batch(
            tuple(document(json.loads(r[0])) for r in db.execute('SELECT payload FROM documents ORDER BY id')),
            tuple(relationship(json.loads(r[0])) for r in db.execute('SELECT payload FROM relationships ORDER BY id')),
            tuple(Issue(**json.loads(r[0])) for r in db.execute('SELECT payload FROM issues ORDER BY payload')))

    def ingest(self, batch, manifest_sha256):
        """One transaction, including conflict detection. Replays perform no writes.

        Conflicting revisions are rejected, never silently overwritten. Build a new
        database for a new corpus revision; ingestion is additive within a snapshot.
        """
        db = self.connection
        try:
            db.execute('BEGIN IMMEDIATE')
            before = self.load()
            merged = merge_batches(before, batch)
            old_docs = {d.id: d for d in before.documents}
            old_rels = {r.id: r for r in before.relationships}
            changed_docs = [d for d in merged.documents if old_docs.get(d.id) != d]
            changed_rels = [r for r in merged.relationships if old_rels.get(r.id) != r]
            for d in changed_docs:
                db.execute('INSERT INTO documents VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
                           (d.id, d.source_type, d.source_id, d.content_sha256, int(d.active), encode(asdict(d))))
                for s in d.sections:
                    db.execute('INSERT INTO sections VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
                               (s.id, d.id, s.ordinal, s.text, encode(asdict(s))))
            for r in changed_rels:
                db.execute('INSERT INTO relationships VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET active=excluded.active,resolved=excluded.resolved,payload=excluded.payload',
                           (r.id, r.source_document_id, r.target_document_id, r.evidence_section_id, r.relationship_type, int(r.active), int(r.resolved), encode(asdict(r))))
            for kind, items in [('document', changed_docs), ('relationship', changed_rels)]:
                for item in items:
                    for p in item.provenance:
                        db.execute('INSERT OR IGNORE INTO provenance VALUES(?,?,?,?,?,?)',
                                   (kind, item.id, p.snapshot.sha256, p.locator, p.record_sha256, encode(asdict(p))))
            for issue in merged.issues:
                db.execute('INSERT OR IGNORE INTO issues VALUES(?)', (encode(asdict(issue)),))
            sha = corpus_hash(merged)
            report = {'corpus_sha256': sha, 'documents': len(merged.documents),
                      'active_documents': sum(d.active for d in merged.documents),
                      'relationships': len(merged.relationships),
                      'resolved_relationships': sum(r.resolved for r in merged.relationships),
                      'sections': sum(len(d.sections) for d in merged.documents),
                      'source_counts': {t: sum(d.source_type == t for d in merged.documents) for t in ('cve', 'attack', 'incident')},
                      'changed_documents': len(changed_docs), 'changed_relationships': len(changed_rels)}
            db.execute('INSERT OR IGNORE INTO imports VALUES(?,?,?)', (manifest_sha256, sha, encode(report)))
            db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE value != excluded.value', ('corpus_sha256', sha))
            db.commit()
            return report
        except BaseException:
            db.rollback()
            raise
