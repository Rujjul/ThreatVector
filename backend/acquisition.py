"""Bounded public-source acquisition; separate from offline ingestion."""
import gzip
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from html.parser import HTMLParser

from .normalization.common import digest, require


def prepare_attack(directory):
    from .preparation import ATTACK_SHA, ATTACK_URL
    path = Path(directory) / 'enterprise-attack-v17.1.json'
    body, receipt = fetch(ATTACK_URL, path)
    require(digest(body) == ATTACK_SHA, 'Downloaded ATT&CK bundle differs from pinned snapshot')
    return receipt


class MainText(HTMLParser):
    """Review aid only; extracted upstream prose stays in ignored local storage."""
    def __init__(self):
        super().__init__()
        self.inside = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == 'main':
            self.inside = True
        if self.inside and tag in ('p', 'li', 'h1', 'h2', 'h3', 'h4', 'div', 'tr'):
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag == 'main':
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)


def acquire_incidents(candidate_manifest, directory):
    candidates = json.loads(Path(candidate_manifest).read_bytes())
    directory = Path(directory)
    receipts = []
    for source_id in candidates['advisory_ids']:
        url = candidates['url_template'].format(lowercase_id=source_id.lower())
        body, receipt = fetch(url, directory / (source_id + '.html'), max_bytes=3_000_000)
        parser = MainText()
        parser.feed(body.decode('utf-8'))
        text = '\n'.join(line.strip() for line in ''.join(parser.parts).splitlines() if line.strip())
        require(source_id in text, 'Advisory ID missing from downloaded page')
        (directory / (source_id + '.txt')).write_text(text, encoding='utf-8')
        receipts.append(dict(receipt, source_id=source_id))
        (directory / 'incident-downloads.json').write_text(json.dumps(receipts, indent=2), encoding='utf-8')
        print('Acquired ' + source_id, flush=True)
        time.sleep(1)
    return receipts


def fetch(url, destination, *, max_bytes=80_000_000, attempts=3, spacing=6):
    """No credentials, bounded retries/size/time; callers list explicit URLs only."""
    require(url.startswith(('https://nvd.nist.gov/', 'https://www.cisa.gov/', 'https://raw.githubusercontent.com/mitre/cti/')), 'Source host is not approved')
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'ThreatVector/0.1 (bounded public corpus preparation)'})
            with urllib.request.urlopen(request, timeout=45) as response:
                require(response.url.startswith('https://'), 'Non-HTTPS redirect rejected')
                body = response.read(max_bytes + 1)
                require(len(body) <= max_bytes, 'Download exceeds size limit')
                result = {'source_url': url, 'resolved_url': response.url, 'retrieved_at': datetime.now(timezone.utc).isoformat(), 'sha256': digest(body), 'bytes': len(body)}
            temporary = destination.with_suffix(destination.suffix + '.partial')
            temporary.write_bytes(body)
            temporary.replace(destination)
            destination.with_suffix(destination.suffix + '.receipt.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            return body, result
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if isinstance(exc, urllib.error.HTTPError) and exc.code not in (429, 500, 502, 503, 504):
                raise
            if attempt + 1 == attempts:
                raise
            time.sleep(max(spacing * (attempt + 1), min(60, int(exc.headers.get('Retry-After', '0'))) if isinstance(exc, urllib.error.HTTPError) and exc.headers.get('Retry-After', '0').isdigit() else 0))


def prepare_nvd(directory, *, count=10000):
    """Freeze a 2021 feed subset: seed CVEs plus lowest numeric IDs.

    Retains original records unchanged in a derived API-shaped envelope and the
    full feed/META/compressed bytes locally. META authenticates uncompressed bytes.
    """
    directory = Path(directory)
    base = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2021'
    meta, _ = fetch(base + '.meta', directory / 'nvd-2021.meta', max_bytes=10000)
    fields = dict(line.split(':', 1) for line in meta.decode().splitlines() if ':' in line)
    time.sleep(6)
    compressed, receipt = fetch(base + '.json.gz', directory / 'nvd-2021.json.gz')
    # Bound decompression as well as network bytes.
    import io
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(500_000_001)
    require(len(raw) <= 500_000_000, 'Uncompressed feed exceeds limit')
    require(digest(raw) == fields['sha256'].lower() and len(raw) == int(fields['size']), 'NVD META integrity mismatch; retry preparation against a consistent feed')
    (directory / 'nvd-2021-full.json').write_bytes(raw)
    payload = json.loads(raw)
    records = payload['vulnerabilities']
    by_id = {r['cve']['id']: r for r in records}
    mandatory = {'CVE-2021-44228', 'CVE-2021-45046'}
    require(mandatory <= by_id.keys(), 'Required demo CVEs missing from feed')
    ids = sorted(by_id, key=lambda k: int(k.rsplit('-', 1)[1]))
    selected = sorted(mandatory | set([i for i in ids if i not in mandatory][:count - len(mandatory)]))
    require(len(selected) == count, 'Feed cannot satisfy CVE target')
    subset = dict(payload, format='NVD_CVE', version='2.0', startIndex=0, resultsPerPage=count, totalResults=count, vulnerabilities=[by_id[i] for i in selected])
    body = json.dumps(subset, ensure_ascii=False).encode('utf-8')
    path = directory / 'nvd-selected-10000.json'
    path.write_bytes(body)
    return {'path': path.as_posix(), 'format': 'nvd_api_2_0', 'representation': 'original_source_text',
            'source_url': 'urn:threatvector:corpus:nvd-2021-selected-10000', 'retrieved_at': receipt['retrieved_at'],
            'sha256': digest(body), 'bytes': len(body), 'selected_ids': selected,
            'upstream_url': base + '.json.gz', 'upstream_sha256': receipt['sha256'],
            'uncompressed_feed_sha256': digest(raw), 'selection': 'CVE-2021-44228 and CVE-2021-45046 plus lowest 9998 other numeric 2021 IDs; unchanged records; derived envelope',
            'reuse_review_id': 'nvd-cve', 'attribution': 'NIST National Vulnerability Database; original CVE CNA descriptions retained unchanged. See NIST and CVE notices; CNA identifiers remain per record.',
            'required_notices': ['data/fixtures/notices/NIST-DATA-NOTICE.txt', 'data/fixtures/notices/CVE-TERMS.txt']}
