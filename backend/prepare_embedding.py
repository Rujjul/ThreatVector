"""Explicit bounded download of the pinned model; subsequent loads are offline."""
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

from .embedding import FILES, MODEL_DIRECTORY, MODEL_ID, REVISION, LOCK_PATH


def download(directory=MODEL_DIRECTORY):
    lock = json.loads(LOCK_PATH.read_text(encoding='utf-8'))
    for name in FILES:
        path = Path(directory) / name
        expected = lock['files'][name]
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected['sha256']:
            continue
        url = f'https://huggingface.co/{MODEL_ID}/resolve/{REVISION}/{name}'
        with urlopen(url, timeout=120) as response:
            raw = response.read(expected['bytes'] + 1)
        if len(raw) != expected['bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
            raise ValueError(f'Download hash mismatch: {name}')
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + '.partial')
        temporary.write_bytes(raw)
        temporary.replace(path)


if __name__ == '__main__':
    download()
