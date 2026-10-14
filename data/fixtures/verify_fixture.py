"""Offline integrity/provenance check. Does not ingest, retrieve, or assess entailment."""
import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(value):
    return hashlib.sha256(value).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

def local_path(value):
    path = (ROOT / value).resolve()
    require(path.is_relative_to(ROOT), f'Path outside project: {value}')
    return path

def pointer(value, location):
    for key in location.strip('/').split('/'):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value

def verify(check_local_sources=False):
    manifest = json.loads((ROOT / 'data/manifests/fixture-v1.json').read_text(encoding='utf-8'))
    for artifact in manifest['artifacts']:
        raw = local_path(artifact['path']).read_bytes()
        require(sha(raw) == artifact['sha256'], f'Artifact hash mismatch: {artifact["path"]}')
        require(len(raw) == artifact['bytes'], f'Artifact size mismatch: {artifact["path"]}')
    corpus_path = ROOT / 'data/fixtures/corpus.json'
    require(sha(corpus_path.read_bytes()) == manifest['corpus_sha256'], 'Corpus snapshot mismatch')
    corpus = json.loads(corpus_path.read_text(encoding='utf-8'))
    require(corpus['fixture_id'] == manifest['fixture_id'], 'Fixture identity mismatch')
    docs = corpus['documents']
    require(Counter(d['source_type'] for d in docs) == {'cve': 2, 'attack': 2, 'incident': 2}, 'Unexpected source coverage')
    require(len({d['id'] for d in docs}) == len(docs), 'Duplicate document identity')
    require(len({(d['source_type'], d['source_id']) for d in docs}) == len(docs), 'Duplicate source identity')
    require(sorted(d['source_id'] for d in docs) == sorted(manifest['selected_source_ids']), 'Selection mismatch')
    sections = {s['id']: (d, s) for d in docs for s in d['sections']}
    require(len(sections) == sum(len(d['sections']) for d in docs) == 8, 'Duplicate/missing sections')
    review = json.loads((ROOT / 'data/manifests/source-review-2026-10-15.json').read_text(encoding='utf-8'))
    reviews = {r['id']: r for r in review['decisions']}
    for doc in docs:
        require(all(doc[k] for k in ['id', 'source_id', 'title', 'url', 'retrieved_at', 'attribution']), 'Missing provenance')
        require(doc['url'].startswith('https://'), 'Expected public HTTPS source')
        require(doc['reuse_review_id'] in reviews, 'Missing reuse decision')
        require(doc['original_source_text_redistributed'] is False, 'Unexpected original source prose')
        require(sha(canonical(doc['sections'])) == doc['content_sha256'], 'Document content hash mismatch')
        if doc['source_type'] == 'attack':
            require(not doc['revoked'] and not doc['deprecated'], 'Inactive technique selected')
            require(doc['attack_commit'] == manifest['attack']['commit'], 'ATT&CK revision mismatch')
            require(doc['publication_date'] is None, 'Unverified technique publication date')
        for section in doc['sections']:
            require(section['text_kind'] == 'project_authored_factual_summary', 'Text representation mislabeled')
            require(section['source_locator'], 'Missing source locator')
            require(sha(section['text'].encode('utf-8')) == section['content_sha256'], 'Section hash mismatch')
        if check_local_sources:
            snapshot = doc['upstream_snapshot']
            raw = local_path(snapshot['local_ignored_path']).read_bytes()
            require(sha(raw) == snapshot['sha256'], f'Upstream snapshot mismatch: {doc["id"]}')
            if 'source_record_sha256' in doc:
                record = pointer(json.loads(raw), doc['source_record_locator'])
                require(sha(canonical(record)) == doc['source_record_sha256'], 'Selected record hash mismatch')
                for section in doc['sections']:
                    require(isinstance(pointer(json.loads(raw), section['source_locator']['json_pointer']), str), 'Bad source text locator')
    relationships = corpus['relationships']
    require(len(relationships) == len({r['id'] for r in relationships}) == 5, 'Relationship count/identity mismatch')
    ids = {d['id'] for d in docs}
    for rel in relationships:
        require(rel['source_document_id'] in ids and rel['target_document_id'] in ids, 'Dangling relationship')
        require(rel['evidence_section_id'] in sections, 'Dangling supporting evidence')
        require(sections[rel['evidence_section_id']][0]['id'] == rel['source_document_id'], 'Wrong evidence owner')
        require(rel['support'] == 'explicit_source_statement' and rel['inferred'] is False, 'Unsupported inferred relationship')
        require(not (rel['source_document_id'].startswith('incident:') and rel['target_document_id'] == 'nvd:CVE-2021-45046'), 'Unsupported incident-CVE edge')
    require(len(corpus['negative_cases']) == 2, 'Missing unsupported cases')
    require(all(n['expected'] == 'insufficient_evidence_in_this_fixture' for n in corpus['negative_cases']), 'Overclaimed negative case')
    license_bytes = (ROOT / 'data/fixtures/notices/MITRE-ATTACK-LICENSE.txt').read_bytes()
    require(sha(license_bytes) == manifest['attack']['license_sha256'], 'Upstream license changed')
    require('2025 The MITRE Corporation' in license_bytes.decode('utf-8'), 'Pinned copyright missing')
    if check_local_sources:
        for source in review['downloads']:
            if source['status'] == 200:
                require(sha(local_path(source['local_ignored_path']).read_bytes()) == source['sha256'], f'Source-review download changed: {source["file"]}')
    print('PASS: 6 documents, 8 sections, 5 explicit relationships, 2 unsupported cases; hashes, attribution and source references verified.' + (' Local upstream bytes and selected records also verified.' if check_local_sources else ' No network access required.'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-local-sources', action='store_true')
    args = parser.parse_args()
    try:
        verify(args.check_local_sources)
    except (ValueError, KeyError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
