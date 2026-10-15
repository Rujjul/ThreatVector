"""Normalize curated report manifests; no web/PDF extraction or semantic inference."""
import re

from .common import SourceContext, boolean, date_value, digest, document, http_url, mapping, merge_batches, parse, relationship, require, section, sequence, string, timestamp
from .models import Batch, Issue

IDENTIFIER = re.compile(r'(?<![\w])(?:CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)(?![\w]|\.\d)', re.IGNORECASE)
ALLOWED_RELATIONSHIPS = {'reports_exploitation_of': 'cve', 'reports_use_of_technique': 'attack', 'mentions_identifier': None}


def normalize_incidents(raw: bytes, *, contexts: dict[str, SourceContext], reviewed_annotations: bool = False) -> Batch:
    """Only caller configuration can enable reviewed annotations; input flags cannot."""
    require(bool(contexts), 'At least one incident source context is required')
    require(type(reviewed_annotations) is bool, 'reviewed_annotations must be a caller boolean')
    payload, _ = parse(raw, next(iter(contexts.values())))
    require(payload.get('format') == 'threatvector_incident_manifest' and type(payload.get('version')) is int and payload['version'] == 1, 'Expected ThreatVector incident manifest version 1')
    docs, relations, issues = [], [], []
    for i, value in enumerate(sequence(payload.get('reports'), '/reports')):
        locator = f'/reports/{i}'
        report = mapping(value, locator)
        source_id = string(report.get('source_id'), locator + '/source_id')
        require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', source_id)), 'Invalid report source identity')
        require(source_id in contexts, f'Unreviewed incident source: {source_id}')
        context = contexts[source_id]
        _, snapshot = parse(raw, context)
        require(context.representation == 'project_authored_factual_summary', 'This incident-manifest adapter accepts reviewed project-authored summaries only')
        require(report.get('reuse_review_id') == context.reuse.id, 'Report cannot override the trusted reuse decision')
        if context.upstream_url is not None:
            require(report.get('upstream_url') == context.upstream_url and report.get('upstream_sha256') == context.upstream_sha256, 'Incident upstream provenance conflicts with trusted context')
        timestamp(report.get('upstream_retrieved_at'), locator + '/upstream_retrieved_at')
        doc_id = 'incident:' + source_id
        sections, by_key, source_sections = [], {}, {}
        for j, value in enumerate(sequence(report.get('sections'), locator + '/sections')):
            source_locator = f'{locator}/sections/{j}'
            entry = mapping(value, source_locator)
            key = string(entry.get('key'), source_locator + '/key')
            require(key not in by_key, 'Duplicate incident section key')
            require(entry.get('text_kind') == context.representation, 'Source representation conflicts with reviewed policy')
            heading = string(entry.get('heading'), source_locator + '/heading')
            text = string(entry.get('text'), source_locator + '/text')
            normalized = section(doc_id, j, heading, text, context.representation, source_locator + '/text', mapping(entry.get('upstream_locator'), source_locator + '/upstream_locator'), snapshot=snapshot)
            sections.append(normalized)
            by_key[key] = normalized
            source_sections[key] = (entry, source_locator)
        require(bool(sections), 'Incident manifest requires a nonempty reviewed summary')
        active = boolean(report.get('active', True), locator + '/active')
        doc = document(snapshot=snapshot, record=report, locator=locator, context=context, id=doc_id, source_type='incident', source_id=source_id, title=string(report.get('title'), locator + '/title'), url=http_url(report.get('url'), locator + '/url'), publication_date=date_value(report.get('publication_date'), locator + '/publication_date'), source_modified_at=None, active=active, sections=tuple(sections), metadata={'sharing_marking': report.get('sharing_marking'), 'summary_author': 'ThreatVector', 'upstream_url': report.get('upstream_url'), 'upstream_sha256': report.get('upstream_sha256'), 'upstream_retrieved_at': report.get('upstream_retrieved_at'), 'report_attack_release': report.get('report_attack_release')})
        docs.append(doc)
        # An occurrence is a mention only; co-occurrence never proves exploitation.
        for key, current in by_key.items():
            source_section, section_locator = source_sections[key]
            for identifier in sorted({m.group().upper() for m in IDENTIFIER.finditer(current.text)}):
                target = ('nvd:' if identifier.startswith('CVE-') else 'attack:') + identifier
                rel_id = 'mention:' + digest(f'{current.id}|{target}'.encode('utf-8'))
                relations.append(relationship(snapshot=snapshot, record=source_section, locator=section_locator, id=rel_id, source_document_id=doc_id, target_document_id=target, relationship_type='mentions_identifier', evidence_document_id=doc_id, evidence_section_id=current.id, evidence_text=current.text, support='explicit_identifier_occurrence', active=False, resolved=False, assertion_active=active))
        annotations = sequence(report.get('relationships', []), locator + '/relationships')
        if annotations and not reviewed_annotations:
            issues.append(Issue('annotations_not_reviewed', locator + '/relationships', 'Stronger annotations were not admitted; only identifier occurrences were retained.'))
        if reviewed_annotations:
            for j, value in enumerate(annotations):
                rel_locator = f'{locator}/relationships/{j}'
                annotation = mapping(value, rel_locator)
                relation_type = string(annotation.get('relationship_type'), rel_locator + '/relationship_type')
                require(relation_type in ALLOWED_RELATIONSHIPS, 'Unknown incident relationship type')
                target_type = ALLOWED_RELATIONSHIPS[relation_type]
                target_id = string(annotation.get('target_source_id'), rel_locator + '/target_source_id').upper()
                require(bool(re.fullmatch(r'CVE-\d{4}-\d{4,}' if target_type == 'cve' else r'T\d{4}(?:\.\d{3})?' if target_type == 'attack' else r'(?:CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)', target_id)), 'Invalid annotated target identifier')
                key = string(annotation.get('section_key'), rel_locator + '/section_key')
                require(key in by_key, 'Annotation has no supporting section')
                current = by_key[key]
                require(target_id in {m.group().upper() for m in IDENTIFIER.finditer(current.text)}, 'Annotated identifier absent from supporting summary')
                target = ('nvd:' if target_id.startswith('CVE-') else 'attack:') + target_id
                basis = string(annotation.get('basis'), rel_locator + '/basis')
                rel_id = 'annotation:' + digest(f'{doc_id}|{target}|{relation_type}|{current.id}'.encode('utf-8'))
                relations.append(relationship(snapshot=snapshot, record=annotation, locator=rel_locator, id=rel_id, source_document_id=doc_id, target_document_id=target, relationship_type=relation_type, evidence_document_id=doc_id, evidence_section_id=current.id, evidence_text=current.text, support='caller_reviewed_source_annotation', active=False, resolved=False, assertion_active=active, metadata={'basis': basis, 'upstream_locator': current.upstream_locator}))
        if not active:
            issues.append(Issue('inactive_incident', locator, 'Inactive report retained for provenance.'))
    return merge_batches(Batch(tuple(docs), tuple(relations), tuple(issues)))
