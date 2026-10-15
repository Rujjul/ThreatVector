"""Network-independent acquisition checks with deterministic HTTP substitutes."""
import gzip
import json
import urllib.error
from pathlib import Path

import pytest

from backend import acquisition
from backend.normalization import NormalizationError
from backend.normalization.common import digest


def test_nvd_meta_verifies_uncompressed_bytes_and_deterministic_selection(tmp_path, monkeypatch):
    records = [{'cve': {'id': f'CVE-2021-{i}', 'descriptions': []}} for i in [45046, 1001, 44228, 1000]]
    raw = json.dumps({'vulnerabilities': records}).encode()
    meta = f'sha256:{digest(raw)}\nsize:{len(raw)}\n'.encode()
    calls = []
    def fake_fetch(url, destination, **kwargs):
        calls.append(url)
        body = meta if url.endswith('.meta') else gzip.compress(raw)
        return body, {'retrieved_at': '2026-10-15T00:00:00Z', 'sha256': digest(body)}
    monkeypatch.setattr(acquisition, 'fetch', fake_fetch)
    sleeps = []
    monkeypatch.setattr(acquisition.time, 'sleep', sleeps.append)
    entry = acquisition.prepare_nvd(tmp_path, count=3)
    assert calls[0].endswith('.meta') and calls[1].endswith('.json.gz')
    assert sleeps == [6]
    assert set(entry['selected_ids']) == {'CVE-2021-1000', 'CVE-2021-44228', 'CVE-2021-45046'}
    subset = json.loads(Path(entry['path']).read_bytes())
    assert all(r in records for r in subset['vulnerabilities'])
    assert entry['uncompressed_feed_sha256'] == digest(raw)


def test_nvd_rejects_inconsistent_meta_archive(tmp_path, monkeypatch):
    def fake_fetch(url, destination, **kwargs):
        return (b'sha256:bad\nsize:2\n' if url.endswith('.meta') else gzip.compress(b'{}')), {'retrieved_at': '2026-10-15T00:00:00Z', 'sha256': 'unused'}
    monkeypatch.setattr(acquisition, 'fetch', fake_fetch)
    monkeypatch.setattr(acquisition.time, 'sleep', lambda _: None)
    with pytest.raises(NormalizationError, match='META integrity'):
        acquisition.prepare_nvd(tmp_path)
    assert not (tmp_path / 'nvd-selected-10000.json').exists()


def test_fetch_retries_rate_limit_then_writes_measured_receipt(tmp_path, monkeypatch):
    class Response:
        url = 'https://www.cisa.gov/test'
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, count): return b'public source'
    calls = []
    def urlopen(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(Response.url, 429, 'rate limit', {'Retry-After': '12'}, None)
        return Response()
    monkeypatch.setattr(acquisition.urllib.request, 'urlopen', urlopen)
    sleeps = []
    monkeypatch.setattr(acquisition.time, 'sleep', sleeps.append)
    path = tmp_path / 'source.html'
    body, receipt = acquisition.fetch(Response.url, path)
    assert len(calls) == 2 and sleeps == [12]
    assert path.read_bytes() == body
    assert receipt['sha256'] == digest(body)
    assert json.loads(path.with_suffix('.html.receipt.json').read_bytes()) == receipt


def test_fetch_rejects_unapproved_hosts_and_oversized_source(tmp_path, monkeypatch):
    with pytest.raises(NormalizationError, match='not approved'):
        acquisition.fetch('https://example.com/private', tmp_path / 'bad')
    class Response:
        url = 'https://www.cisa.gov/test'
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, count): return b'x' * count
    monkeypatch.setattr(acquisition.urllib.request, 'urlopen', lambda *a, **k: Response())
    with pytest.raises(NormalizationError, match='size limit'):
        acquisition.fetch(Response.url, tmp_path / 'big', max_bytes=10)
    assert not (tmp_path / 'big').exists()
