"""Validation and deterministic identity helpers; no I/O, providers, or persistence."""
import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from .models import Batch, Document, Provenance, Relationship, Section, Snapshot


class NormalizationError(ValueError):
    """Input is malformed, ambiguous, or not approved for the representation."""


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NormalizationError(message)


def mapping(value: Any, locator: str) -> dict:
    require(isinstance(value, dict), f'{locator}: expected object')
    return value


def sequence(value: Any, locator: str) -> list:
    require(isinstance(value, list), f'{locator}: expected array')
    return value


def string(value: Any, locator: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f'{locator}: expected nonblank string')
    return value.strip()


def http_url(value: Any, locator: str) -> str:
    value = string(value, locator)
    try:
        parsed = urlsplit(value)
        require(parsed.scheme in {'https', 'http'} and bool(parsed.hostname) and parsed.username is None and parsed.password is None, f'{locator}: expected public HTTP(S) URL without credentials')
    except NormalizationError:
        raise
    except ValueError as exc:
        raise NormalizationError(f'{locator}: invalid URL') from exc
    return value


def timestamp(value: Any, locator: str, *, optional: bool = True, assume_utc: bool = False) -> str | None:
    if value is None and optional:
        return None
    value = string(value, locator)
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            require(assume_utc, f'{locator}: timezone required')
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    except ValueError as exc:
        raise NormalizationError(f'{locator}: invalid timestamp or missing timezone') from exc


def date_value(value: Any, locator: str) -> str | None:
    if value is None:
        return None
    value = string(value, locator)
    require(bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}', value)), f'{locator}: expected YYYY-MM-DD')
    try:
        datetime.strptime(value, '%Y-%m-%d')
    except ValueError as exc:
        raise NormalizationError(f'{locator}: invalid calendar date') from exc
    return value


def boolean(value: Any, locator: str) -> bool:
    require(type(value) is bool, f'{locator}: expected boolean')
    return value


@dataclass(frozen=True)
class ReuseDecision:
    id: str
    category: str
    allowed_representations: tuple[str, ...]

    @classmethod
    def from_manifest(cls, trusted_manifest: dict, decision_id: str) -> 'ReuseDecision':
        """Caller supplies project-reviewed configuration, never a report's own policy."""
        candidates = [d for d in trusted_manifest['decisions'] if d['id'] == decision_id]
        require(len(candidates) == 1, 'Reuse decision absent or ambiguous')
        record = candidates[0]
        return cls(record['id'], record['decision_category'], tuple(record['allowed_representations']))


@dataclass(frozen=True)
class SourceContext:
    source_url: str
    retrieved_at: str
    reuse: ReuseDecision
    attribution: str
    representation: str = 'original_source_text'
    expected_sha256: str | None = None
    upstream_url: str | None = None
    upstream_sha256: str | None = None


def parse(raw: bytes, context: SourceContext) -> tuple[dict, Snapshot]:
    require(isinstance(raw, bytes), 'Normalizer input must be raw bytes')
    require(context.reuse.category not in {'metadata_and_links_only', 'excluded_sources'}, 'Source policy does not permit text normalization')
    require(context.reuse.category in {'redistributable_full_text', 'permitted_excerpts_summaries_only'}, 'Unknown reuse category')
    if context.representation == 'original_source_text':
        require(context.reuse.category == 'redistributable_full_text', 'Original source text not approved')
    else:
        require(context.representation == 'project_authored_factual_summary' and context.representation in context.reuse.allowed_representations, 'Summary representation not approved')
    string(context.attribution, 'context.attribution')
    source_url = string(context.source_url, 'context.source_url')
    if not source_url.startswith('urn:threatvector:'):
        source_url = http_url(source_url, 'context.source_url')
    require((context.upstream_url is None) == (context.upstream_sha256 is None), 'Upstream URL and hash must be supplied together')
    if context.upstream_url is not None:
        http_url(context.upstream_url, 'context.upstream_url')
        require(bool(re.fullmatch(r'[0-9a-f]{64}', context.upstream_sha256 or '')), 'Invalid upstream SHA-256')
    retrieved_at = timestamp(context.retrieved_at, 'context.retrieved_at', optional=False)
    raw_hash = digest(raw)
    require(context.expected_sha256 is None or context.expected_sha256 == raw_hash, 'Raw snapshot hash mismatch')

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f'Duplicate JSON key: {key}')
            result[key] = value
        return result

    def reject_constant(_):
        raise NormalizationError('Non-finite JSON number')

    try:
        payload = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise NormalizationError('Invalid UTF-8 JSON payload') from exc
    return mapping(payload, '/'), Snapshot(source_url, retrieved_at, raw_hash, len(raw), context.upstream_url, context.upstream_sha256)


def provenance(snapshot: Snapshot, record: dict, locator: str) -> Provenance:
    return Provenance(snapshot, locator, digest(canonical(record)))


def section(document_id: str, ordinal: int, heading: str, text: str, text_kind: str, locator: str, upstream_locator: dict | None = None, *, snapshot: Snapshot) -> Section:
    text = string(text, f'{locator}.text').replace('\r\n', '\n').replace('\r', '\n')
    return Section(f'{document_id}#section-{ordinal}', ordinal, heading, text, text_kind, locator, digest(text.encode('utf-8')), snapshot.sha256, upstream_locator or {})


def document(*, snapshot: Snapshot, record: dict, locator: str, context: SourceContext, **values) -> Document:
    # Content identity excludes retrieval provenance; repeated snapshots can merge.
    identity = dict(values, attribution=context.attribution, reuse_review_id=context.reuse.id, decision_category=context.reuse.category)
    identity['sections'] = [asdict(s) for s in identity['sections']]
    # JSON array positions are provenance, not content; input reordering is harmless.
    for item in identity['sections']:
        item.pop('source_locator')
        item.pop('source_snapshot_sha256')
    return Document(**values, attribution=context.attribution, reuse_review_id=context.reuse.id, decision_category=context.reuse.category, content_sha256=digest(canonical(identity)), provenance=(provenance(snapshot, record, locator),))


def relationship(*, snapshot: Snapshot, record: dict, locator: str, **values) -> Relationship:
    identity = {k: v for k, v in values.items() if k not in {'active', 'resolved'}}
    return Relationship(**values, source_locator=locator, content_sha256=digest(canonical(identity)), provenance=(provenance(snapshot, record, locator),))


def merge_batches(*batches: Batch) -> Batch:
    """Deduplicate stable identities; reject conflicting revisions rather than pick one."""
    def merge(items):
        output = {}
        for item in items:
            prior = output.get(item.id)
            if prior is None:
                output[item.id] = item
                continue
            require(prior.content_sha256 == item.content_sha256, f'Conflicting revisions for {item.id}')
            unique = {canonical(asdict(p)): p for p in prior.provenance + item.provenance}
            output[item.id] = replace(prior, provenance=tuple(unique[k] for k in sorted(unique)))
        return tuple(output[k] for k in sorted(output))
    docs = merge(doc for batch in batches for doc in batch.documents)
    relations = merge(rel for batch in batches for rel in batch.relationships)
    by_id = {d.id: d for d in docs}
    resolved_relations = []
    for rel in relations:
        resolved = rel.source_document_id in by_id and rel.target_document_id in by_id
        active = rel.assertion_active and resolved and by_id[rel.source_document_id].active and by_id[rel.target_document_id].active
        resolved_relations.append(replace(rel, resolved=resolved, active=active))
    issues = {(i.code, i.locator, i.message): i for batch in batches for i in batch.issues}
    return Batch(docs, tuple(resolved_relations), tuple(issues[k] for k in sorted(issues)))
