"""Explicit local CPU smoke check, separate from deterministic unit tests."""
import json
import platform
from importlib.metadata import version
from datetime import datetime, timezone
from pathlib import Path

from .embedding import MODEL_ID, REVISION, load_model, load_tokenizer, verify_assets


def verify():
    import numpy as np
    import torch
    torch.set_num_threads(1)
    lock = verify_assets()
    tokenizer = load_tokenizer()
    model = load_model()
    inputs = ['CVE-2021-44228 permits remote code execution through Log4j.',
              'An attacker executes commands through a vulnerable application.']
    vectors = model.encode(inputs, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
    repeated = model.encode(inputs, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
    assert vectors.shape == (2, 384) and vectors.dtype == np.float32
    assert np.isfinite(vectors).all() and np.allclose(np.linalg.norm(vectors, axis=1), 1, atol=1e-6)
    assert np.allclose(vectors, repeated, atol=1e-7)
    assert model.device.type == 'cpu'
    assert model.tokenizer.encode(inputs[0]) == tokenizer.encode(inputs[0])
    return {'verified_at': datetime.now(timezone.utc).isoformat(), 'model_id': MODEL_ID,
            'revision': REVISION, 'asset_files_verified': len(lock['files']),
            'dimension': 384, 'max_sequence_length': model.max_seq_length,
            'device': 'cpu', 'dtype': str(vectors.dtype), 'finite': True,
            'normalized': True, 'repeatable_within_atol': 1e-7,
            'python': platform.python_version(), 'platform': platform.platform(),
            'threads': torch.get_num_threads(),
            'versions': {p: version(p) for p in ('torch', 'sentence-transformers', 'transformers', 'tokenizers', 'numpy', 'huggingface-hub', 'safetensors')},
            'scope': 'Two fixed inputs; compatibility smoke check, not a relevance or performance benchmark'}


if __name__ == '__main__':
    report = verify()
    Path('data/manifests/embedding-validation-v1.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
