"""Strict provider output and deterministic extractive grounding checks."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .identifiers import extract_identifiers


INFERENCE = 'This is a semantic association with the query; it does not establish exploitation or a source-supported relationship.'
UNCERTAINTY = {
    'limited_evidence':'The supplied evidence may not fully answer the question.',
    'semantic_only':'Semantic similarity does not establish exploitation.',
    'potential_conflict':'Sources were flagged as potentially conflicting; inspect the cited excerpts.',
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Statement(StrictModel):
    text: str = Field(min_length=1,max_length=4000)
    citation_chunk_ids: list[str] = Field(min_length=1,max_length=8)
    inferred: bool


class Entity(StrictModel):
    id: str = Field(min_length=1,max_length=128)
    label: str = Field(min_length=1,max_length=500)
    citation_chunk_ids: list[str] = Field(min_length=1,max_length=8)
    inferred: bool


class Conflict(StrictModel):
    citation_chunk_ids: list[str] = Field(min_length=2,max_length=8)


class StructuredAnalysis(StrictModel):
    status: Literal['ok','insufficient_evidence']
    claims: list[Statement] = Field(max_length=8)
    mitigations: list[Statement] = Field(max_length=8)
    related_entities: list[Entity] = Field(max_length=12)
    uncertainty: list[Literal['limited_evidence','semantic_only','potential_conflict']] = Field(max_length=3)
    conflicts: list[Conflict] = Field(max_length=8)


class GroundingError(ValueError):
    """Contains a safe error code, never provider text or source instructions."""


def validate_analysis(content, evidence, documents):
    if not isinstance(content,str) or len(content)>100_000:
        raise GroundingError('invalid_shape')
    try:
        output = StructuredAnalysis.model_validate_json(content)
    except ValidationError:
        raise GroundingError('invalid_shape') from None
    chunks = {c['chunk_id']:c for c in evidence}
    if len(chunks) != len(evidence):
        raise GroundingError('duplicate_context')
    active_ids = {d.source_id:d for d in documents.values() if d.active and d.source_type in ('attack','cve')}

    def citations(ids):
        if len(set(ids)) != len(ids) or any(i not in chunks for i in ids):
            raise GroundingError('invalid_citation')
        return [chunks[i] for i in ids]

    for statement in [*output.claims,*output.mitigations]:
        cited = citations(statement.citation_chunk_ids)
        if statement.inferred:
            if statement.text != INFERENCE or any(c['match_type']!='semantic' for c in cited):
                raise GroundingError('unsupported_inference')
        elif len(cited)!=1 or statement.text != cited[0]['text']:
            # A quote supplied alongside an arbitrary paraphrase is not entailment.
            # Preserve the whole excerpt, including its negation and qualifiers.
            raise GroundingError('unsupported_statement')
        for identifier in extract_identifiers(statement.text):
            if not identifier.startswith('CVE-') and identifier not in active_ids:
                raise GroundingError('unknown_identifier')
    for mitigation in output.mitigations:
        if mitigation.inferred:
            raise GroundingError('unsupported_mitigation')
        for chunk in citations(mitigation.citation_chunk_ids):
            doc = documents[chunk['document_id']]
            section = next(s for s in doc.sections if s.id == chunk['section_id'])
            heading = section.heading.lower()
            if (doc.metadata.get('stix_type') != 'course-of-action'
                    and not any(word in heading for word in ('mitigat','remediat','recommend','solution'))):
                raise GroundingError('unsupported_mitigation')
    for entity in output.related_entities:
        cited = citations(entity.citation_chunk_ids)
        doc = active_ids.get(entity.id)
        if doc is None or entity.label != doc.title:
            raise GroundingError('unknown_entity')
        if not all(c['document_id']==doc.id or entity.id in extract_identifiers(c['text']) for c in cited):
            raise GroundingError('unsupported_entity')
        if entity.inferred != all(c['match_type']=='semantic' for c in cited):
            raise GroundingError('entity_inference_mismatch')
    for conflict in output.conflicts:
        cited = citations(conflict.citation_chunk_ids)
        if len({c['document_id'] for c in cited})<2:
            raise GroundingError('invalid_conflict')
    if bool(output.conflicts) != ('potential_conflict' in output.uncertainty):
        raise GroundingError('conflict_uncertainty_missing')
    if (any(s.inferred for s in output.claims) or any(e.inferred for e in output.related_entities)) and 'semantic_only' not in output.uncertainty:
        raise GroundingError('inference_uncertainty_missing')
    items = [*output.claims,*output.mitigations,*output.related_entities]
    if output.status=='insufficient_evidence' and (items or output.conflicts):
        raise GroundingError('invalid_insufficient_evidence')
    if output.status=='ok' and not items:
        raise GroundingError('empty_analysis')
    return output
