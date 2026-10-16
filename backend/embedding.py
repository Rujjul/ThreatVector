"""Pinned local MiniLM assets; no remote code or implicit network access."""
import hashlib
import json
import os
from pathlib import Path

MODEL_ID = 'sentence-transformers/all-MiniLM-L6-v2'
REVISION = '1110a243fdf4706b3f48f1d95db1a4f5529b4d41'
MODEL_DIRECTORY = Path('data/models/all-MiniLM-L6-v2')
LOCK_PATH = Path(__file__).with_name('embedding-model.json')
FILES = ('config.json', 'sentence_bert_config.json', 'config_sentence_transformers.json',
         'modules.json', '1_Pooling/config.json', 'tokenizer.json', 'tokenizer_config.json',
         'special_tokens_map.json', 'vocab.txt', 'model.safetensors', 'README.md')


def local_cache():
    # Keep library bookkeeping inside ignored workspace data, including on Windows.
    os.environ.setdefault('HF_HOME', str(Path('data/model-cache').resolve()))
    os.environ.setdefault('HF_HUB_OFFLINE', '1')


def verify_assets(directory=MODEL_DIRECTORY):
    lock = json.loads(LOCK_PATH.read_text(encoding='utf-8'))
    if lock['model_id'] != MODEL_ID or lock['revision'] != REVISION or set(lock['files']) != set(FILES):
        raise ValueError('Embedding model lock mismatch')
    for name, expected in lock['files'].items():
        raw = (Path(directory) / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected['sha256'] or len(raw) != expected['bytes']:
            raise ValueError(f'Embedding asset mismatch: {name}')
    return lock


def load_tokenizer(directory=MODEL_DIRECTORY):
    local_cache()
    from transformers import AutoTokenizer
    verify_assets(directory)
    tokenizer = AutoTokenizer.from_pretrained(str(directory), local_files_only=True, trust_remote_code=False, use_fast=True)
    if not tokenizer.is_fast:
        raise ValueError('Offset-aware fast tokenizer required')
    return tokenizer


def load_model(directory=MODEL_DIRECTORY):
    local_cache()
    from sentence_transformers import SentenceTransformer
    verify_assets(directory)
    model = SentenceTransformer(str(directory), device='cpu', local_files_only=True, trust_remote_code=False)
    if model.get_sentence_embedding_dimension() != 384 or model.max_seq_length != 256:
        raise ValueError('Unexpected MiniLM architecture or sequence limit')
    return model
