"""Normalize STIX bundles, including explicit relationships and inactive endpoints."""
import re
from uuid import UUID

from .common import NormalizationError, SourceContext, boolean, document, http_url, mapping, merge_batches, parse, relationship, require, section, sequence, string, timestamp
from .models import Batch, Issue

DOCUMENT_TYPES = {'attack-pattern', 'course-of-action', 'intrusion-set', 'malware', 'tool', 'campaign', 'x-mitre-tactic'}
STRUCTURAL_TYPES = {'identity', 'marking-definition'}
DETECTION_TYPES = {'x-mitre-data-source', 'x-mitre-data-component', 'x-mitre-matrix'}
EXTERNAL_IDS = {'attack-pattern': r'T\d{4}(?:\.\d{3})?', 'course-of-action': r'M\d{4}', 'intrusion-set': r'G\d{4}', 'malware': r'S\d{4}', 'tool': r'S\d{4}', 'campaign': r'C\d{4}', 'x-mitre-tactic': r'TA\d{4}'}
DETECTION_IDS = {'x-mitre-data-source': r'DS\d{4}', 'x-mitre-data-component': r'(?!)', 'x-mitre-matrix': r'enterprise-attack'}


def stix_id(value, locator):
    value = string(value, locator)
    require(bool(re.fullmatch(r'[a-z][a-z0-9-]*--[0-9a-fA-F-]{36}', value)), locator + ': invalid STIX identity')
    try:
        require(str(UUID(value.split('--', 1)[1])) == value.split('--', 1)[1].lower(), locator + ': noncanonical UUID')
    except NormalizationError:
        raise
    except ValueError as exc:
        raise NormalizationError(locator + ': invalid STIX UUID') from exc
    return value


def flags(record: dict, locator: str) -> bool:
    revoked = boolean(record.get('revoked', False), locator + '/revoked')
    deprecated = boolean(record.get('x_mitre_deprecated', False), locator + '/x_mitre_deprecated')
    return not revoked and not deprecated


def normalize_attack(raw: bytes, *, context: SourceContext, profile: str = 'core_v1') -> Batch:
    require(profile in {'core_v1', 'enterprise_complete_v1'}, 'Unknown ATT&CK normalization profile')
    supported_types = DOCUMENT_TYPES | (DETECTION_TYPES if profile == 'enterprise_complete_v1' else set())
    payload, snapshot = parse(raw, context)
    require(context.representation == 'original_source_text', 'STIX object descriptions must be labeled original source text')
    require(payload.get('type') == 'bundle', 'Expected STIX bundle')
    objects = sequence(payload.get('objects'), '/objects')
    documents, relationships, issues = [], [], []
    by_stix_id = {}
    raw_objects = {}
    for i, item in enumerate(objects):
        locator = f'/objects/{i}'
        obj = mapping(item, locator)
        object_type = string(obj.get('type'), locator + '/type')
        object_id = stix_id(obj.get('id'), locator + '/id')
        require(object_id.startswith(object_type + '--'), locator + ': STIX type and identity disagree')
        prior = raw_objects.get(object_id)
        require(prior is None or prior == obj, f'Conflicting STIX objects: {object_id}')
        raw_objects[object_id] = obj
        if object_type not in supported_types:
            if object_type not in STRUCTURAL_TYPES | {'relationship'}:
                issues.append(Issue('unsupported_stix_type', locator, f'Object type {object_type} not normalized; raw provenance retained by caller.'))
            continue
        references = sequence(obj.get('external_references', []), locator + '/external_references')
        refs = [mapping(r, locator + '/external_references') for r in references]
        attack_refs = [r for r in refs if r.get('source_name') == 'mitre-attack' and r.get('external_id')]
        require(len(attack_refs) <= 1, locator + ': ambiguous ATT&CK external identifier')
        ref = attack_refs[0] if attack_refs else None
        external_id = string(ref['external_id'], locator + '/external_id') if ref else None
        if object_type == 'attack-pattern' and external_id:
            require(bool(re.fullmatch(r'T\d{4}(?:\.\d{3})?', external_id)), locator + ': invalid ATT&CK technique identifier')
        canonical_external = bool(external_id and re.fullmatch((EXTERNAL_IDS | DETECTION_IDS)[object_type], external_id))
        # Legacy deprecated mitigations can reference a technique's T-number.
        # Preserve that reference without colliding with the technique document.
        source_id = external_id if canonical_external else object_id
        if external_id and not canonical_external:
            issues.append(Issue('legacy_external_identifier', locator, 'External identifier does not identify this entity type; STIX identity retained.'))
        doc_id = 'attack:' + source_id
        require(object_id not in by_stix_id or by_stix_id[object_id] == doc_id, 'STIX identity remapped')
        by_stix_id[object_id] = doc_id
        name = string(obj.get('name'), locator + '/name')
        created = timestamp(obj.get('created'), locator + '/created')
        modified = timestamp(obj.get('modified'), locator + '/modified')
        active = flags(obj, locator)
        description = obj.get('description')
        require(description is None or isinstance(description, str), locator + '/description: expected string')
        sections = (section(doc_id, 0, 'Description', description, context.representation, locator + '/description', snapshot=snapshot),) if description and description.strip() else ()
        if not sections:
            issues.append(Issue('missing_description', locator, 'Metadata retained, but no content is available to retrieve.'))
            active = False
        url = http_url(ref['url'], locator + '/external_url') if ref and ref.get('url') else None
        metadata = {'stix_id': object_id, 'stix_type': object_type, 'external_id': external_id, 'created_at': created, 'object_version': obj.get('x_mitre_version'), 'revoked': obj.get('revoked', False), 'deprecated': obj.get('x_mitre_deprecated', False), 'external_references': refs, 'object_marking_refs': obj.get('object_marking_refs', []), 'created_by_ref': obj.get('created_by_ref')}
        if object_type in DETECTION_TYPES:
            # Embedded STIX references are source metadata, not invented assertions.
            parent = obj.get('x_mitre_data_source_ref')
            if parent is not None:
                parent = stix_id(parent, locator + '/x_mitre_data_source_ref')
                require(parent.startswith('x-mitre-data-source--'), 'Component parent must be a STIX data source')
            tactics = sequence(obj.get('tactic_refs', []), locator + '/tactic_refs')
            for value in tactics:
                require(stix_id(value, locator + '/tactic_refs').startswith('x-mitre-tactic--'), 'Matrix reference must identify a tactic')
            metadata.update(data_source_stix_id=parent, tactic_stix_ids=tactics,
                            platforms=sequence(obj.get('x_mitre_platforms', []), locator + '/x_mitre_platforms'),
                            collection_layers=sequence(obj.get('x_mitre_collection_layers', []), locator + '/x_mitre_collection_layers'))
            # Components lack individual external URLs; link the actual bundle.
            if url is None:
                candidate = context.upstream_url or context.source_url
                if candidate.startswith(('https://', 'http://')):
                    url = http_url(candidate, 'context.source_url')
        documents.append(document(snapshot=snapshot, record=obj, locator=locator, context=context, id=doc_id, source_type='attack', source_id=source_id, title=name, url=url, publication_date=None, source_modified_at=modified, active=active, sections=sections, metadata=metadata))
    docs_by_id = {d.id: d for d in documents}
    for i, item in enumerate(objects):
        if item['type'] != 'relationship':
            continue
        locator = f'/objects/{i}'
        source = stix_id(item.get('source_ref'), locator + '/source_ref')
        target = stix_id(item.get('target_ref'), locator + '/target_ref')
        relation_type = string(item.get('relationship_type'), locator + '/relationship_type')
        resolved = source in by_stix_id and target in by_stix_id
        if not resolved:
            issues.append(Issue('unresolved_stix_relationship', locator, 'Relationship has endpoints outside this input\'s supported objects; retained for later resolution.'))
        source_doc = by_stix_id.get(source, 'attack:' + source)
        target_doc = by_stix_id.get(target, 'attack:' + target)
        active = flags(item, locator) and resolved and docs_by_id[source_doc].active and docs_by_id[target_doc].active
        evidence = item.get('description')
        require(evidence is None or isinstance(evidence, str), locator + '/description: expected string')
        relationships.append(relationship(snapshot=snapshot, record=item, locator=locator, id='attack:' + item['id'], source_document_id=source_doc, target_document_id=target_doc, relationship_type=relation_type, evidence_document_id=None, evidence_section_id=None, evidence_text=evidence, support='explicit_stix_relationship', active=active, resolved=resolved, assertion_active=flags(item, locator), metadata={'source_stix_id': source, 'target_stix_id': target, 'created_at': timestamp(item.get('created'), locator + '/created'), 'modified_at': timestamp(item.get('modified'), locator + '/modified'), 'revoked': item.get('revoked', False), 'deprecated': item.get('x_mitre_deprecated', False), 'object_marking_refs': item.get('object_marking_refs', [])}))
    return merge_batches(Batch(tuple(documents), tuple(relationships), tuple(issues)))
