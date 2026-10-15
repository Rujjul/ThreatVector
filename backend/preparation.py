"""Assemble the reviewed full corpus manifest without crawling or inventing data."""
import json
from collections import Counter
from pathlib import Path

from .ingestion import ROOT, local_path
from .normalization.common import digest, require

ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/dc2ea9270f1a91398c750a6dceb3591b86082ce8/enterprise-attack/enterprise-attack.json'
ATTACK_SHA = '9537a22166367a5b3c1434f5b17b27361cb9c88b34926e655344768fdbda3e85'


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def prepare_corpus(*, root=ROOT, directory='data/raw/full-v1', attack_path=None, output='data/manifests/full-corpus-v1.json'):
    root = Path(root)
    folder = local_path(root, directory)
    attack_path = attack_path or directory + '/enterprise-attack-v17.1.json'
    curation = json.loads(local_path(root, 'data/manifests/incident-curation-v1.json').read_bytes())
    entries = json.loads(local_path(root, 'data/manifests/raw-normalizers-v1.json').read_bytes())['entries']
    seed = next(e for e in entries if e['format'] == 'threatvector_incident_manifest_1')
    reports = json.loads(local_path(root, seed['path']).read_bytes())['reports']
    contexts = dict(seed['context_by_source_id'])
    review = json.loads(local_path(root, 'data/manifests/source-review-2026-10-15.json').read_bytes())
    review['scope'] = 'Full-v1 corpus admission: unchanged selected NVD records, pinned MITRE bundle and 20 original CISA-report summaries. No third-party prose.'
    for decision in review['decisions']:
        if decision['id'] == 'nvd-cve':
            decision['publisher'] = 'NIST NVD / record-specific CVE CNAs'
            decision['decision_scope'] = '10,000 unchanged records selected from the META-verified 2021 NVD feed; CNA attribution retained per record; no linked vendor text.'
            decision['selection_manifest'] = output
        if decision['id'] == 'mitre-attack':
            decision['decision_scope'] = 'Enterprise ATT&CK 17.1 full STIX bundle at pinned commit; MITRE license retained; third-party linked prose excluded.'
    for item in curation['reports']:
        source_id = item['source_id']
        upstream = local_path(root, directory + '/' + source_id + '.html').read_bytes()
        require(digest(upstream) == item['upstream_sha256'] and len(upstream) == item['upstream_bytes'], 'Reviewed incident snapshot changed: ' + source_id)
        url = 'https://www.cisa.gov/news-events/cybersecurity-advisories/' + source_id.lower()
        policy_id = 'cisa-' + source_id.lower()
        attribution = 'CISA and report-specific coauthoring agencies, ' + source_id + '. Original factual summary by ThreatVector; source assessments remain attributed. No agency endorsement implied.'
        reports.append({'source_id': source_id, 'title': item['title'], 'url': url,
                        'publication_date': item['publication_date'], 'sharing_marking': None,
                        'reuse_review_id': policy_id, 'upstream_url': url, 'upstream_sha256': item['upstream_sha256'],
                        'upstream_retrieved_at': item['upstream_retrieved_at'], 'report_attack_release': None,
                        'sections': [{'key': 'reviewed-summary', 'heading': 'Reviewed factual summary', 'text': item['summary'],
                                      'text_kind': 'project_authored_factual_summary',
                                      'upstream_locator': {'format': 'html', 'heading': item['heading'], 'snapshot_sha256': item['upstream_sha256']}}],
                        'relationships': []})
        contexts[source_id] = {'reuse_review_id': policy_id, 'attribution': attribution, 'upstream_url': url, 'upstream_sha256': item['upstream_sha256']}
        review['decisions'].append({'id': policy_id, 'publisher': 'CISA and report-specific coauthors', 'source_ids': [source_id],
            'decision_category': 'permitted_excerpts_summaries_only', 'decision_status': 'final_project_decision_with_stated_conditions',
            'allowed_representations': ['project_authored_factual_summary', 'metadata_and_links'],
            'decision_scope': 'Original factual summary of reviewed HTML passages only. No blanket permission for original prose; missing sharing marking remains absent.',
            'not_approved': ['original_source_text', 'third_party_text', 'images', 'logos', 'ransom_notes'],
            'policy_evidence_ids': ['cisa-terms-use', 'cisa-intellectual-property'],
            'terms_urls': ['https://www.cisa.gov/terms-use', 'https://www.cisa.gov/intellectual-property-policy'],
            'reviewed_date': curation['reviewed_date'], 'source_snapshot_sha256': item['upstream_sha256'],
            'source_url': url, 'source_locator': item['heading'], 'original_text_redistributed': False,
            'publisher_license_for_summaries_asserted': False,
            'conditions': ['Attribute factual summaries to ThreatVector and keep original agency assessments qualified.',
                           'Retain source URL, reviewed snapshot hash, retrieval date and heading locator.',
                           'Original report prose, images, logos and third-party material remain excluded.']})
    review['decision_counts'] = dict(Counter(d['decision_category'] for d in review['decisions']))
    review['nvd_api_policy']['status'] = 'review_complete_bulk_acquisition_implemented_no_key_registration'
    review['review_completion']['not_claimed'] = [v for v in review['review_completion']['not_claimed'] if v not in {'completed_20_report_curation', 'implemented_or_validated_ingestion'}]
    review['review_completion']['full_corpus_admission'] = '20 reports reviewed for original-summary representation; ingestion validation recorded separately'
    review_path = 'data/manifests/source-review-full-v1.json'
    write_json(local_path(root, review_path), review)
    incident_path = 'data/manifests/incident-summaries-v1.json'
    write_json(local_path(root, incident_path), {'format': 'threatvector_incident_manifest', 'version': 1, 'reports': reports})
    body = local_path(root, incident_path).read_bytes()
    incident_entry = dict(seed, path=incident_path, source_url='urn:threatvector:corpus:incident-summaries-v1',
                          retrieved_at=curation['curated_at'], sha256=digest(body), bytes=len(body), selected_ids=[r['source_id'] for r in reports], context_by_source_id=contexts)
    incident_entry.pop('timestamp_note', None)
    incident_entry['timestamp_note'] = 'Project curation timestamp; each upstream retrieval time is recorded separately.'
    attack_raw = local_path(root, attack_path).read_bytes()
    require(digest(attack_raw) == ATTACK_SHA, 'Pinned ATT&CK bundle hash mismatch')
    attack_receipt = json.loads(local_path(root, attack_path + '.receipt.json').read_bytes())
    require(attack_receipt['sha256'] == ATTACK_SHA, 'ATT&CK receipt differs from pinned snapshot')
    attack_entry = {'path': attack_path, 'format': 'stix_bundle', 'representation': 'original_source_text',
                    'source_url': ATTACK_URL, 'retrieved_at': attack_receipt['retrieved_at'], 'sha256': ATTACK_SHA, 'bytes': len(attack_raw),
                    'reuse_review_id': 'mitre-attack', 'attribution': 'MITRE ATT&CK Enterprise 17.1. Copyright 2025 The MITRE Corporation. See MITRE-ATTACK-LICENSE.txt.',
                    'required_notices': ['data/fixtures/notices/MITRE-ATTACK-LICENSE.txt']}
    nvd_entry = json.loads((folder / 'nvd-entry.json').read_bytes())
    manifest = {'schema_version': 1, 'corpus_id': 'threatvector-full-v1', 'source_review_manifest': review_path,
                'source_review_sha256': digest(local_path(root, review_path).read_bytes()),
                'targets': {'cve': 10000, 'attack': 2091, 'incident': 20},
                'entries': [nvd_entry, attack_entry, incident_entry],
                'limitations': ['CVE sample is 2021-focused, not a current vulnerability census.',
                    'Incident evidence is original factual summaries, not full source prose; historical advisories can cover multiple incidents.',
                    'Unsupported STIX object types and unresolved endpoints are retained as diagnostics; no inferred exploitation links.',
                    'Tokenized chunks, embeddings, retrieval and generation are separate later phases.']}
    write_json(local_path(root, output), manifest)
    return {'manifest': output, 'sha256': digest(local_path(root, output).read_bytes()), 'targets': manifest['targets']}
