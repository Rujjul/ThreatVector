"""Section-local token windows with exact source substrings and bounded inputs."""
from dataclasses import asdict, dataclass

from .embedding import REVISION
from .normalization.common import canonical, digest


@dataclass(frozen=True)
class Chunk:
    id: str
    document_id: str
    section_id: str
    ordinal: int
    text: str
    token_start: int
    token_end: int
    char_start: int
    char_end: int
    embedding_text: str
    token_count: int
    content_sha256: str
    tokenizer_revision: str = REVISION


def chunk_document(document, tokenizer, max_tokens=220, overlap=30):
    """Offsets are section-local, end-exclusive; overlap counts body tokens.

    Prefix is bounded to 48 tokens; source title/heading remain intact in SQLite.
    Re-tokenize complete inputs to account for prefix/body boundary effects.
    Inactive documents never enter the retrieval corpus.
    """
    if not 0 <= overlap < max_tokens <= 220:
        raise ValueError('Invalid chunk token budget or overlap')
    if not document.active:
        return ()
    chunks = []
    for section in sorted(document.sections, key=lambda s: s.ordinal):
        prefix_text = f'{document.source_type}: {document.source_id}\n{document.title}\n{section.heading}'
        prefix_encoding = tokenizer(prefix_text, add_special_tokens=False, return_offsets_mapping=True)
        prefix_end = prefix_encoding['offset_mapping'][min(48, len(prefix_encoding['input_ids'])) - 1][1]
        prefix = prefix_text[:prefix_end] + '\n\n'
        body = tokenizer(section.text, add_special_tokens=False, return_offsets_mapping=True)
        offsets = body['offset_mapping']
        if not offsets:
            continue
        budget = max_tokens - len(tokenizer.encode(prefix, add_special_tokens=True))
        if budget <= overlap:
            raise ValueError('Metadata leaves insufficient body-token budget')
        start = 0
        while start < len(offsets):
            end = min(start + budget, len(offsets))
            while end > start:
                char_start, char_end = offsets[start][0], offsets[end - 1][1]
                text = section.text[char_start:char_end]
                embedded = prefix + text
                count = len(tokenizer.encode(embedded, add_special_tokens=True, truncation=False))
                if count <= max_tokens:
                    break
                end -= 1
            if end <= start or (end < len(offsets) and end - start <= overlap):
                raise ValueError('Tokenizer cannot make progress within token budget')
            identity = dict(document_id=document.id, section_id=section.id, ordinal=len(chunks),
                            text=text, token_start=start, token_end=end, char_start=char_start,
                            char_end=char_end, embedding_text=embedded, token_count=count,
                            content_sha256=digest(text.encode('utf-8')), tokenizer_revision=REVISION)
            chunks.append(Chunk(id='chunk:' + digest(canonical(identity)), **identity))
            if end == len(offsets):
                break
            start = end - overlap
    return tuple(chunks)


def build_chunks(batch, tokenizer):
    return tuple(c for d in sorted(batch.documents, key=lambda d: d.id) for c in chunk_document(d, tokenizer))


def chunk_hash(chunks):
    return digest(canonical([asdict(c) for c in chunks]))


def persist_chunks(store, tokenizer):
    """Atomically replace stale generations; identical replay performs no writes."""
    from .storage import corpus_hash, encode
    batch = store.load()
    corpus = corpus_hash(batch)
    chunks = build_chunks(batch, tokenizer)
    manifest = {'version': 1, 'corpus_sha256': corpus, 'chunk_sha256': chunk_hash(chunks),
                'model_revision': REVISION, 'max_tokens': 220, 'overlap': 30,
                'prefix_max_tokens': 48, 'chunks': len(chunks)}
    db = store.connection
    db.execute('CREATE TABLE IF NOT EXISTS chunk_details (id TEXT PRIMARY KEY REFERENCES chunks(id) ON DELETE CASCADE, payload TEXT NOT NULL)')
    db.commit()
    try:
        db.execute('BEGIN IMMEDIATE')
        state = db.execute("SELECT value FROM state WHERE key='corpus_sha256'").fetchone()
        if state is None or state[0] != corpus or corpus_hash(store.load()) != corpus:
            raise ValueError('Corpus state changed or is corrupt')
        rows = [(c.id, c.document_id, c.section_id, c.ordinal, c.text, c.token_start,
                 c.token_end, c.content_sha256, c.tokenizer_revision) for c in chunks]
        details = [(c.id, encode(asdict(c))) for c in chunks]
        old = db.execute('SELECT * FROM chunks ORDER BY id').fetchall()
        old_details = db.execute('SELECT id,payload FROM chunk_details ORDER BY id').fetchall()
        prior = db.execute("SELECT value FROM state WHERE key='chunk_manifest'").fetchone()
        changed = old != sorted(rows) or old_details != sorted(details) or prior != (encode(manifest),)
        if changed:
            db.execute('DELETE FROM chunk_details')
            db.execute('DELETE FROM chunks')
            db.executemany('INSERT INTO chunks VALUES(?,?,?,?,?,?,?,?,?)', rows)
            db.executemany('INSERT INTO chunk_details VALUES(?,?)', details)
            db.execute("INSERT INTO state VALUES('chunk_manifest',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (encode(manifest),))
        db.commit()
        return {**manifest, 'changed': changed}
    except BaseException:
        db.rollback()
        raise
