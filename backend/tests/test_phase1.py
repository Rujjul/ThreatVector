"""Phase-1 regression checks use a small, attributed subset of actual STIX data."""
import copy
import json
import sqlite3
from dataclasses import replace

import pytest

from backend.ingestion import ROOT, normalize_manifest
from backend.normalization import NormalizationError, ReuseDecision, SourceContext, normalize_attack
from backend.normalization.common import canonical, digest
from backend.storage import CorpusStore
from backend.verification import verify_source_references

MANIFEST = ROOT / 'data/manifests/phase1-attack-fixture-v1.json'
CONFIG = json.loads(MANIFEST.read_bytes())
ENTRY = CONFIG['entries'][0]
RAW = (ROOT / ENTRY['path']).read_bytes()
REVIEW = json.loads((ROOT / CONFIG['source_review_manifest']).read_bytes())


def context():
    return SourceContext(ENTRY['source_url'], ENTRY['retrieved_at'], ReuseDecision.from_manifest(REVIEW, ENTRY['reuse_review_id']), ENTRY['attribution'], ENTRY['representation'], ENTRY['sha256'], ENTRY['upstream_url'], ENTRY['upstream_sha256'])


def test_complete_profile_preserves_real_objects_and_resolves_detection_edges(tmp_path):
    payload = json.loads(RAW)
    assert all(digest(canonical(o)) == ENTRY['selected_record_sha256'][o['id']] for o in payload['objects'])
    batch, sha = normalize_manifest(MANIFEST)
    assert {d.metadata['stix_type'] for d in batch.documents} == {'attack-pattern', 'x-mitre-data-component', 'x-mitre-data-source', 'x-mitre-matrix'}
    assert all(d.url and d.provenance for d in batch.documents)
    assert not any(i.code in {'unsupported_stix_type', 'unresolved_stix_relationship'} for i in batch.issues)
    assert len(batch.relationships) == 1
    rel = batch.relationships[0]
    assert rel.relationship_type == 'detects' and rel.resolved and rel.active
    component = next(d for d in batch.documents if d.metadata['stix_type'] == 'x-mitre-data-component')
    source = next(d for d in batch.documents if d.metadata['stix_type'] == 'x-mitre-data-source')
    matrix = next(d for d in batch.documents if d.metadata['stix_type'] == 'x-mitre-matrix')
    assert component.metadata['data_source_stix_id'] == source.metadata['stix_id']
    assert matrix.metadata['tactic_stix_ids']
    with CorpusStore(tmp_path / 'db') as store:
        store.ingest(batch, sha)
        assert store.load() == batch
        assert store.ingest(batch, sha)['changed_relationships'] == 0
    references = verify_source_references(batch, MANIFEST)
    assert references['section_source_references_verified'] == 4


def test_legacy_profile_remains_reproducible_and_source_cannot_enable_profile():
    core = normalize_attack(RAW, context=context())
    assert len(core.documents) == 1
    assert not core.relationships[0].resolved
    payload = json.loads(RAW)
    payload['normalization_profile'] = 'enterprise_complete_v1'
    assert len(normalize_attack(canonical(payload), context=replace(context(), expected_sha256=None)).documents) == 1
    with pytest.raises(NormalizationError, match='profile'):
        normalize_attack(RAW, context=context(), profile='unknown')


def test_inactive_data_component_does_not_activate_detection_relationship():
    payload = json.loads(RAW)
    next(o for o in payload['objects'] if o['type'] == 'x-mitre-data-component')['revoked'] = True
    batch = normalize_attack(canonical(payload), context=replace(context(), expected_sha256=None), profile='enterprise_complete_v1')
    assert batch.relationships[0].resolved and not batch.relationships[0].active


def test_invalid_embedded_parent_reference_fails():
    payload = json.loads(RAW)
    component = next(o for o in payload['objects'] if o['type'] == 'x-mitre-data-component')
    component['x_mitre_data_source_ref'] = next(o['id'] for o in payload['objects'] if o['type'] == 'attack-pattern')
    with pytest.raises(NormalizationError, match='parent'):
        normalize_attack(canonical(payload), context=replace(context(), expected_sha256=None), profile='enterprise_complete_v1')


@pytest.mark.parametrize('change', ['schema', 'notice', 'profile'])
def test_manifest_controls_fail_before_import(tmp_path, change):
    config = copy.deepcopy(CONFIG)
    if change == 'schema':
        config['schema_version'] = 99
    elif change == 'notice':
        config['artifacts'][-1]['sha256'] = '0' * 64
    else:
        config['entries'][0]['normalization_profile'] = 'unknown'
    path = tmp_path / 'bad.json'
    path.write_bytes(canonical(config))
    with pytest.raises(NormalizationError):
        normalize_manifest(path)


def test_source_reference_replay_rejects_wrong_record_and_section_pointers():
    batch, _ = normalize_manifest(MANIFEST)
    d = batch.documents[0]
    bad_record = replace(d.provenance[0], locator='/objects/999999')
    with pytest.raises(NormalizationError, match='pointer'):
        verify_source_references(replace(batch, documents=(replace(d, provenance=(bad_record,)), *batch.documents[1:])), MANIFEST)
    bad_section = replace(d.sections[0], source_locator='/objects/0/id')
    with pytest.raises(NormalizationError, match='pointer/text'):
        verify_source_references(replace(batch, documents=(replace(d, sections=(bad_section,)), *batch.documents[1:])), MANIFEST)


def test_verifier_rejects_corrupt_state_instead_of_repairing_it(tmp_path):
    from backend.verification import verify_corpus
    batch, sha = normalize_manifest(MANIFEST)
    path = tmp_path / 'db'
    with CorpusStore(path) as store:
        store.ingest(batch, sha)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE state SET value='synthetic-corruption' WHERE key='corpus_sha256'")
    with pytest.raises(NormalizationError, match='state hash mismatch'):
        verify_corpus(MANIFEST, path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM state WHERE key='corpus_sha256'").fetchone()[0] == 'synthetic-corruption'
