"""Offline full-corpus boundary, source traceability and replay verification."""
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .chunking import build_chunks, persist_chunks
from .cli import DEFAULT_DATABASE
from .embedding import load_tokenizer
from .storage import CorpusStore


def verify(database=DEFAULT_DATABASE):
    if not Path(database).is_file():
        raise ValueError('Ingest a corpus before verifying chunks')
    tokenizer = load_tokenizer()
    with CorpusStore(database) as store:
        report = persist_chunks(store, tokenizer)
        before = store.connection.total_changes
        again = persist_chunks(store, tokenizer)
        assert not again['changed'] and before == store.connection.total_changes
        batch = store.load()
        chunks = build_chunks(batch, tokenizer)
        documents = {d.id: d for d in batch.documents}
        sections = {s.id: s for d in batch.documents for s in d.sections}
        previous = {}
        for c in chunks:
            doc, section = documents[c.document_id], sections[c.section_id]
            assert doc.active and doc.url and doc.provenance
            assert section in doc.sections
            assert c.text == section.text[c.char_start:c.char_end]
            assert len(tokenizer.encode(c.embedding_text, truncation=False)) == c.token_count <= 220
            old = previous.get(c.section_id)
            assert c.token_start == (old.token_end - 30 if old else 0)
            previous[c.section_id] = c
        for d in batch.documents:
            if not d.active:
                continue
            for section in d.sections:
                count = len(tokenizer.encode(section.text, add_special_tokens=False))
                assert (previous[section.id].token_end == count) if count else section.id not in previous
        stored = {r[0]: json.loads(r[1]) for r in store.connection.execute('SELECT id,payload FROM chunk_details')}
        assert stored == {c.id: asdict(c) for c in chunks}
        assert store.connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert not store.connection.execute('PRAGMA foreign_key_check').fetchall()
        return {**report, 'verified_at': datetime.now(timezone.utc).isoformat(),
                'max_observed_tokens': max(c.token_count for c in chunks),
                'sections_verified': len(previous), 'replay_row_changes': 0,
                'source_offsets_verified': True, 'token_coverage_verified': True,
                'integrity_check': 'ok', 'foreign_key_errors': [],
                'scope': 'Chunk boundary/source/storage checks; no retrieval quality or performance benchmark'}


if __name__ == '__main__':
    report = verify()
    Path('data/manifests/chunk-validation-v1.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
