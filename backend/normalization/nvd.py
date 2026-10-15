"""Normalize bounded NVD API-2.0 responses without network access."""
import re

from .common import SourceContext, document, mapping, merge_batches, parse, require, section, sequence, string, timestamp
from .models import Batch, Issue

CVE_ID = re.compile(r'CVE-\d{4}-\d{4,}')


def normalize_nvd(raw: bytes, *, context: SourceContext) -> Batch:
    payload, snapshot = parse(raw, context)
    require(context.representation == 'original_source_text', 'NVD API descriptions must be labeled original source text')
    require(payload.get('format') == 'NVD_CVE' and payload.get('version') == '2.0', 'Expected NVD_CVE version 2.0')
    entries = sequence(payload.get('vulnerabilities'), '/vulnerabilities')
    for key in ['totalResults', 'resultsPerPage', 'startIndex']:
        require(type(payload.get(key)) is int and payload[key] >= 0, f'/{key}: expected nonnegative integer')
    require(payload['totalResults'] >= len(entries), 'NVD totalResults smaller than returned records')
    docs, issues = [], []
    for i, entry in enumerate(entries):
        locator = f'/vulnerabilities/{i}/cve'
        cve = mapping(mapping(entry, f'/vulnerabilities/{i}').get('cve'), locator)
        source_id = string(cve.get('id'), locator + '/id')
        require(bool(CVE_ID.fullmatch(source_id)), f'{locator}/id: invalid CVE identifier')
        doc_id = 'nvd:' + source_id
        published = timestamp(cve.get('published'), locator + '/published', assume_utc=True)
        modified = timestamp(cve.get('lastModified'), locator + '/lastModified', assume_utc=True)
        status = cve.get('vulnStatus')
        require(status is None or isinstance(status, str), f'{locator}/vulnStatus: expected string')
        descriptions, seen = [], set()
        for j, value in enumerate(sequence(cve.get('descriptions', []), locator + '/descriptions')):
            desc = mapping(value, f'{locator}/descriptions/{j}')
            lang = string(desc.get('lang'), f'{locator}/descriptions/{j}/lang')
            text = string(desc.get('value'), f'{locator}/descriptions/{j}/value')
            if lang.lower() == 'en' and text not in seen:
                descriptions.append(section(doc_id, len(descriptions), 'Description', text, context.representation, f'{locator}/descriptions/{j}/value', snapshot=snapshot))
                seen.add(text)
        if not descriptions:
            issues.append(Issue('missing_english_description', locator, 'Record retained as inactive metadata; no translated text invented.'))
        active = bool(descriptions) and (status or '').lower() != 'rejected'
        docs.append(document(snapshot=snapshot, record=cve, locator=locator, context=context, id=doc_id, source_type='cve', source_id=source_id, title=source_id, url=f'https://nvd.nist.gov/vuln/detail/{source_id}', publication_date=published[:10] if published else None, source_modified_at=modified, active=active, sections=tuple(descriptions), metadata={'published_at': published, 'cna_source_identifier': cve.get('sourceIdentifier'), 'vulnerability_status': status, 'metrics': mapping(cve.get('metrics', {}), locator + '/metrics'), 'references': sequence(cve.get('references', []), locator + '/references')}))
    return merge_batches(Batch(tuple(docs), (), tuple(issues)))
