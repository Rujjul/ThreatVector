"""Hash-verified local manifest ingestion. No implicit downloads or providers."""
import json
from pathlib import Path

from .normalization import SourceContext, ReuseDecision, merge_batches, normalize_nvd, normalize_attack, normalize_incidents
from .normalization.common import digest, require
from .storage import CorpusStore

ROOT = Path(__file__).resolve().parents[1]


def local_path(root, relative):
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), 'Manifest path escapes corpus root')
    return path


def normalize_manifest(manifest_path, *, root=ROOT, reviewed_annotations=False):
    root = Path(root)
    raw_manifest = Path(manifest_path).read_bytes()
    manifest = json.loads(raw_manifest)
    review_raw = local_path(root, manifest['source_review_manifest']).read_bytes()
    require('source_review_sha256' not in manifest or digest(review_raw) == manifest['source_review_sha256'], 'Source review hash mismatch')
    review = json.loads(review_raw)
    batches = []
    for entry in manifest['entries']:
        raw = local_path(root, entry['path']).read_bytes()
        require(len(raw) == entry['bytes'] and digest(raw) == entry['sha256'], 'Snapshot size/hash mismatch: ' + entry['path'])
        for notice in entry['required_notices']:
            require(local_path(root, notice).is_file(), 'Required attribution notice absent')
        def context(detail):
            return SourceContext(entry['source_url'], entry['retrieved_at'],
                ReuseDecision.from_manifest(review, detail['reuse_review_id']), detail['attribution'],
                entry['representation'], entry['sha256'], detail.get('upstream_url'), detail.get('upstream_sha256'))
        if entry['format'] == 'nvd_api_2_0':
            batch = normalize_nvd(raw, context=context(entry))
        elif entry['format'] == 'stix_bundle':
            batch = normalize_attack(raw, context=context(entry))
        elif entry['format'] == 'threatvector_incident_manifest_1':
            batch = normalize_incidents(raw, contexts={k: context(v) for k, v in entry['context_by_source_id'].items()}, reviewed_annotations=reviewed_annotations)
        else:
            raise ValueError('Unsupported manifest format: ' + entry['format'])
        if 'selected_ids' in entry:
            actual = {d.source_id for d in batch.documents}
            require(set(entry['selected_ids']) <= actual, 'Selected source identities absent')
        batches.append(batch)
    batch = merge_batches(*batches)
    if 'targets' in manifest:
        for source_type, count in manifest['targets'].items():
            require(sum(d.source_type == source_type for d in batch.documents) == count, f'Target count mismatch: {source_type}')
    return batch, digest(raw_manifest)


def ingest(manifest_path, database, *, root=ROOT, reviewed_annotations=False):
    batch, manifest_hash = normalize_manifest(manifest_path, root=root, reviewed_annotations=reviewed_annotations)
    with CorpusStore(database) as store:
        return store.ingest(batch, manifest_hash)
