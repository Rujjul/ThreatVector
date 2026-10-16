"""Offline deterministic boundary, provenance and persistence checks."""
from dataclasses import replace
import re

import pytest

from backend.chunking import build_chunks, chunk_document, persist_chunks
from backend.ingestion import normalize_manifest, ROOT
from backend.normalization import Batch
from backend.storage import CorpusStore


class Tokenizer:
    """Deterministic word/punctuation test double; live MiniLM checked separately."""
    def __call__(self, text, **kwargs):
        offsets = [(m.start(), m.end()) for m in re.finditer(r'\w+|[^\w\s]', text)]
        return {'input_ids': list(range(len(offsets))), 'offset_mapping': offsets}

    def encode(self, text, add_special_tokens=True, **kwargs):
        return self(text)['input_ids'] + ([1, 2] if add_special_tokens else [])


def sample(text):
    batch, _ = normalize_manifest(ROOT / 'data/manifests/raw-normalizers-v1.json')
    doc = next(d for d in batch.documents if d.active and d.sections)
    return replace(doc, sections=(replace(doc.sections[0], text=text),))


def test_exact_offsets_coverage_overlap_and_total_budget():
    doc = sample('  ' + ' '.join(f'word{i}' for i in range(850)) + ' café 😀 尾')
    chunks = chunk_document(doc, Tokenizer())
    assert len(chunks) > 4
    assert chunks[0].token_start == 0
    assert chunks[-1].token_end == len(Tokenizer()(doc.sections[0].text)['input_ids'])
    for i, c in enumerate(chunks):
        assert c.text == doc.sections[0].text[c.char_start:c.char_end]
        assert c.document_id == doc.id and c.section_id == doc.sections[0].id
        assert c.token_count == len(Tokenizer().encode(c.embedding_text)) <= 220
        if i:
            assert chunks[i-1].token_end - c.token_start == 30
    assert chunks == chunk_document(doc, Tokenizer())
    assert chunks != chunk_document(replace(doc, title='Changed title'), Tokenizer())


def test_long_metadata_short_empty_inactive_and_section_boundaries():
    doc = replace(sample('one two'), title='verylong ' * 1000)
    assert len(chunk_document(doc, Tokenizer())) == 1
    assert chunk_document(sample(' \n\t'), Tokenizer()) == ()
    assert chunk_document(replace(doc, active=False), Tokenizer()) == ()
    second = replace(doc.sections[0], id='another', ordinal=1)
    both = chunk_document(replace(doc, sections=(doc.sections[0], second)), Tokenizer())
    assert [c.section_id for c in both] == [doc.sections[0].id, 'another']
    assert [c.ordinal for c in both] == [0, 1]


@pytest.mark.parametrize('maximum,overlap', [(221,30),(220,220),(0,0),(220,-1),(10,8)])
def test_invalid_budgets_fail(maximum, overlap):
    with pytest.raises(ValueError):
        chunk_document(sample('text'), Tokenizer(), maximum, overlap)


def test_atomic_storage_replay_repair_and_corrupt_state(tmp_path):
    batch, sha = normalize_manifest(ROOT / 'data/manifests/raw-normalizers-v1.json')
    with CorpusStore(tmp_path / 'db') as store:
        store.ingest(batch, sha)
        first = persist_chunks(store, Tokenizer())
        assert first['changed'] and first['chunks'] > 0
        changes = store.connection.total_changes
        assert not persist_chunks(store, Tokenizer())['changed']
        assert store.connection.total_changes == changes
        assert store.load() == batch
        store.connection.execute("UPDATE chunks SET text='tampered'")
        store.connection.commit()
        assert persist_chunks(store, Tokenizer())['changed']
        assert store.connection.execute('PRAGMA foreign_key_check').fetchall() == []
        store.connection.execute("UPDATE state SET value='bad' WHERE key='corpus_sha256'")
        store.connection.commit()
        with pytest.raises(ValueError, match='corrupt'):
            persist_chunks(store, Tokenizer())
        assert store.connection.execute('SELECT count(*) FROM chunks').fetchone()[0] == first['chunks']


def test_order_independent_chunks_and_inactive_exclusion():
    a = sample('short source')
    b = replace(a, id='other', active=False)
    assert build_chunks(Batch((b, a)), Tokenizer()) == build_chunks(Batch((a, b)), Tokenizer())


def test_failed_replacement_preserves_prior_generation(tmp_path):
    import sqlite3
    batch, sha = normalize_manifest(ROOT / 'data/manifests/raw-normalizers-v1.json')
    with CorpusStore(tmp_path / 'db') as store:
        store.ingest(batch, sha)
        persist_chunks(store, Tokenizer())
        store.connection.execute("UPDATE chunks SET text='original stored value'")
        store.connection.commit()
        rows = store.connection.execute('SELECT * FROM chunks').fetchall()
        store.connection.execute("CREATE TRIGGER deny_chunks BEFORE INSERT ON chunks BEGIN SELECT RAISE(ABORT, 'test denial'); END")
        with pytest.raises(sqlite3.IntegrityError, match='test denial'):
            persist_chunks(store, Tokenizer())
        assert store.connection.execute('SELECT * FROM chunks').fetchall() == rows


def test_model_asset_lock_rejects_tampering(tmp_path, monkeypatch):
    import hashlib
    import json
    import backend.embedding as embedding
    lock = {'model_id': embedding.MODEL_ID, 'revision': embedding.REVISION, 'files': {}}
    for name in embedding.FILES:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'test asset')
        lock['files'][name] = {'bytes': 10, 'sha256': hashlib.sha256(b'test asset').hexdigest()}
    lock_path = tmp_path / 'lock.json'
    lock_path.write_text(json.dumps(lock), encoding='utf-8')
    monkeypatch.setattr(embedding, 'LOCK_PATH', lock_path)
    assert embedding.verify_assets(tmp_path) == lock
    (tmp_path / 'tokenizer.json').write_bytes(b'changed')
    with pytest.raises(ValueError, match='asset mismatch'):
        embedding.verify_assets(tmp_path)
    lock['revision'] = 'main'
    lock_path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError, match='lock mismatch'):
        embedding.verify_assets(tmp_path)
