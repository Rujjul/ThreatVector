"""Canonical corpus identities only; mentions and legacy aliases are not lookups."""
import re

PATTERN = re.compile(r'(?<![A-Z0-9_.-])(?:CVE-\d{4}-\d{4,}|TA\d{4}|DS\d{4}|T\d{4}(?:\.\d{3})?|[MGSC]\d{4})(?![A-Z0-9_-]|\.\d)', re.IGNORECASE | re.ASCII)


def extract_identifiers(query):
    return tuple(dict.fromkeys(m.group().upper() for m in PATTERN.finditer(query)))


def lookup_identifiers(query, documents, chunks, source_types):
    allowed = {'cve','attack','incident'} if source_types is None else set(source_types)
    by_identity = {(d.source_type,d.source_id.upper()):d for d in documents.values()}
    by_document = {}
    for chunk in chunks.values():
        by_document.setdefault(chunk['document_id'],[]).append(chunk)
    matches, statuses = [], []
    for order, identifier in enumerate(extract_identifiers(query)):
        source = 'cve' if identifier.startswith('CVE-') else 'attack'
        document = by_identity.get((source,identifier))
        if source not in allowed:
            status = 'filtered_out'
        elif document is None:
            status = 'not_found'
        elif not document.active:
            status = 'inactive'
        elif not by_document.get(document.id):
            status = 'no_retrievable_evidence'
        else:
            status = 'matched'
            for chunk in by_document[document.id]:
                matches.append((chunk['ordinal'],order,chunk['id'],identifier))
        statuses.append({'identifier':identifier,'status':status,
                         'document_id':document.id if document is not None and source in allowed else None})
    # First evidence chunk for each requested identity before subsequent chunks.
    matches.sort()
    return matches, statuses
