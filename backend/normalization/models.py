"""Provider-independent normalized records. Evidence is data, never instructions."""
from dataclasses import dataclass, field
from typing import Any, Literal

SourceType = Literal['cve', 'attack', 'incident']


@dataclass(frozen=True)
class Snapshot:
    url: str
    retrieved_at: str
    sha256: str
    byte_count: int
    upstream_url: str | None = None
    upstream_sha256: str | None = None


@dataclass(frozen=True)
class Provenance:
    snapshot: Snapshot
    locator: str
    record_sha256: str


@dataclass(frozen=True)
class Section:
    id: str
    ordinal: int
    heading: str
    text: str
    text_kind: str
    source_locator: str
    content_sha256: str
    source_snapshot_sha256: str
    upstream_locator: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Document:
    id: str
    source_type: SourceType
    source_id: str
    title: str
    url: str | None
    publication_date: str | None
    source_modified_at: str | None
    attribution: str
    reuse_review_id: str
    decision_category: str
    active: bool
    sections: tuple[Section, ...]
    metadata: dict[str, Any]
    content_sha256: str
    provenance: tuple[Provenance, ...]


@dataclass(frozen=True)
class Relationship:
    id: str
    source_document_id: str
    target_document_id: str
    relationship_type: str
    evidence_document_id: str | None
    evidence_section_id: str | None
    evidence_text: str | None
    source_locator: str
    support: str
    active: bool
    resolved: bool
    content_sha256: str
    provenance: tuple[Provenance, ...]
    inferred: bool = False
    assertion_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Issue:
    code: str
    locator: str
    message: str


@dataclass(frozen=True)
class Batch:
    documents: tuple[Document, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    issues: tuple[Issue, ...] = ()
