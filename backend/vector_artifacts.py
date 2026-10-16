"""CPU embedding snapshots bound to validated SQLite chunks and model assets."""
import json
import os
import platform
import uuid
from dataclasses import asdict, dataclass
from importlib.metadata import version
from pathlib import Path

import numpy as np

from .chunking import Chunk, chunk_hash
from .embedding import LOCK_PATH, MODEL_ID, REVISION, load_model, verify_assets
from .normalization.common import canonical, digest
from .storage import CorpusStore, corpus_hash

DIMENSION = 384
SEED = 42


def versions():
    return {p: version(p) for p in ('numpy', 'torch', 'sentence-transformers',
                                   'transformers', 'tokenizers', 'huggingface-hub', 'safetensors')}


def write_json(path, value):
    Path(path).write_bytes(canonical(value))


def file_hash(path):
    import hashlib
    sha = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def inventory(path):
    return {'sha256': file_hash(path), 'bytes': Path(path).stat().st_size}


def check_file(directory, name, expected):
    path = Path(directory) / name
    if path.is_symlink() or not path.is_file() or inventory(path) != expected:
        raise ValueError(f'Artifact checksum/size mismatch: {name}')
    return path


@dataclass(frozen=True)
class ChunkContext:
    chunks: tuple
    rows: tuple
    identity: dict


def current_chunks(database):
    """Reject stale generations and SQL/payload drift before building or loading."""
    if not Path(database).is_file():
        raise ValueError('Corpus database does not exist')
    # Metadata alone must not authorize a locally modified active embedder.
    verify_assets()
    with CorpusStore(database) as store:
        db = store.connection
        db.execute('BEGIN')
        batch = store.load()
        sha = corpus_hash(batch)
        state = dict(db.execute('SELECT key,value FROM state'))
        if state.get('corpus_sha256') != sha or 'chunk_manifest' not in state:
            raise ValueError('Missing or corrupt corpus/chunk state; verify corpus and run chunking')
        manifest = json.loads(state['chunk_manifest'])
        chunks = tuple(Chunk(**json.loads(r[0])) for r in db.execute(
            'SELECT payload FROM chunk_details ORDER BY json_extract(payload,\'$.document_id\'), json_extract(payload,\'$.ordinal\')'))
        expected = {'version': 1, 'corpus_sha256': sha, 'chunk_sha256': chunk_hash(chunks),
                    'model_revision': REVISION, 'max_tokens': 220, 'overlap': 30,
                    'prefix_max_tokens': 48, 'chunks': len(chunks)}
        if manifest != expected or not chunks:
            raise ValueError('Stale, empty or mismatched chunk generation; rerun chunking')
        projections = [(c.id, c.document_id, c.section_id, c.ordinal, c.text, c.token_start,
                        c.token_end, c.content_sha256, c.tokenizer_revision) for c in chunks]
        if sorted(projections) != db.execute('SELECT * FROM chunks ORDER BY id').fetchall():
            raise ValueError('Chunk SQL projection mismatch')
        docs = {d.id: d for d in batch.documents}
        rows = []
        for c in chunks:
            d = docs[c.document_id]
            sections = {s.id: s for s in d.sections}
            s = sections[c.section_id]
            identity = asdict(c)
            identity.pop('id')
            if (not d.active or c.tokenizer_revision != REVISION or not 0 < c.token_count <= 220
                    or not 0 <= c.char_start < c.char_end <= len(s.text)
                    or not 0 <= c.token_start < c.token_end
                    or c.text != s.text[c.char_start:c.char_end]
                    or c.content_sha256 != digest(c.text.encode('utf-8'))
                    or c.id != 'chunk:' + digest(canonical(identity))):
                raise ValueError('Invalid chunk identity, activity or source offsets')
            rows.append({'chunk_id': c.id, 'document_id': d.id, 'section_id': s.id, 'source_type': d.source_type})
    model_lock = json.loads(LOCK_PATH.read_bytes())
    identity = {'corpus_sha256': sha, 'chunk_sha256': manifest['chunk_sha256'],
                'chunk_parameters': {'version': 1, 'max_tokens': 220, 'overlap': 30, 'prefix_max_tokens': 48},
                'model_id': MODEL_ID, 'model_revision': REVISION,
                'model_assets_sha256': digest(canonical(model_lock)),
                'dimension': DIMENSION, 'dtype': 'float32', 'normalized': True, 'device': 'cpu',
                'versions': versions(), 'python': platform.python_version()}
    return ChunkContext(chunks, tuple(rows), identity)


def validate_vectors(vectors, count):
    if (not isinstance(vectors, np.ndarray) or vectors.dtype != np.float32
            or vectors.shape != (count, DIMENSION) or not vectors.flags.c_contiguous
            or not np.isfinite(vectors).all()
            or not np.allclose(np.linalg.norm(vectors, axis=1), 1, atol=1e-5, rtol=0)):
        raise ValueError('Expected finite, unit-normalized contiguous float32 vectors of dimension 384')


def load_vectors(directory, context):
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    if (manifest.get('schema_version') != 1 or manifest.get('identity') != context.identity
            or manifest.get('count') != len(context.chunks)
            or manifest.get('encoding') != {'batch_size': 32, 'threads': 1, 'seed': SEED}
            or set(manifest.get('files', {})) != {'vectors.npy', 'rows.json'}):
        raise ValueError('Embedding manifest does not match active corpus/embedder')
    for name, expected in manifest['files'].items():
        check_file(directory, name, expected)
    if json.loads((directory / 'rows.json').read_bytes()) != list(context.rows):
        raise ValueError('Embedding row mapping mismatch')
    vectors = np.load(directory / 'vectors.npy', allow_pickle=False)
    validate_vectors(vectors, len(context.chunks))
    return vectors, manifest


def build_vectors(context, root='data/embeddings', *, encoder=None):
    """Encoder injection is for deterministic tests; CLI always uses pinned MiniLM."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    destination = root / digest(canonical(context.identity))
    if destination.exists():
        vectors, manifest = load_vectors(destination, context)
        return destination, vectors, manifest
    if encoder is None:
        import torch
        verify_assets()
        torch.set_num_threads(1)
        torch.manual_seed(SEED)
        model = load_model()
        for c in context.chunks:
            if len(model.tokenizer.encode(c.embedding_text, truncation=False)) != c.token_count:
                raise ValueError('Actual model tokenizer disagrees with stored chunk token count')
        encoder = model.encode
    texts = [c.embedding_text for c in context.chunks]
    vectors = encoder(texts, batch_size=32, normalize_embeddings=True,
                      convert_to_numpy=True, show_progress_bar=False)
    validate_vectors(vectors, len(texts))
    temporary = root / ('.pending-' + uuid.uuid4().hex)
    temporary.mkdir()
    np.save(temporary / 'vectors.npy', vectors, allow_pickle=False)
    write_json(temporary / 'rows.json', list(context.rows))
    manifest = {'schema_version': 1, 'identity': context.identity, 'count': len(texts),
                'encoding': {'batch_size': 32, 'threads': 1, 'seed': SEED},
                'files': {name: inventory(temporary / name) for name in ('vectors.npy', 'rows.json')}}
    write_json(temporary / 'manifest.json', manifest)
    load_vectors(temporary, context)
    os.replace(temporary, destination)
    return destination, vectors, manifest
