"""Run with python -m backend.cli; ingestion never fetches source URLs."""
import argparse
import json

from .ingestion import ingest
from .storage import CorpusStore, corpus_hash

DEFAULT_DATABASE = 'data/corpus-v2.sqlite3'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    imp = sub.add_parser('ingest')
    imp.add_argument('--manifest', required=True)
    imp.add_argument('--database', default=DEFAULT_DATABASE)
    imp.add_argument('--reviewed-annotations', action='store_true', help='Trusted operator opt-in for manually reviewed relationship annotations')
    imp.add_argument('--check-idempotence', action='store_true')
    info = sub.add_parser('inspect')
    info.add_argument('--database', default=DEFAULT_DATABASE)
    prepare = sub.add_parser('prepare-nvd', help='Download and freeze the bounded 2021 NVD subset')
    prepare.add_argument('--directory', default='data/raw/full-v1')
    attack = sub.add_parser('prepare-attack', help='Download and verify pinned Enterprise ATT&CK 17.1')
    attack.add_argument('--directory', default='data/raw/full-v1')
    acquire = sub.add_parser('acquire-incidents', help='Download only the explicit candidate list for review')
    acquire.add_argument('--candidates', default='data/manifests/incident-candidates-v1.json')
    acquire.add_argument('--directory', default='data/raw/full-v1')
    assemble = sub.add_parser('prepare-corpus', help='Assemble the frozen reviewed full-v1 source manifest')
    assemble.add_argument('--directory', default='data/raw/full-v1')
    complete = sub.add_parser('prepare-complete-corpus', help='Freeze the complete Enterprise ATT&CK normalization revision using existing v1 sources')
    verify = sub.add_parser('verify-corpus', help='Verify hashes, SQL projections and a zero-write replay')
    verify.add_argument('--manifest', required=True)
    verify.add_argument('--database', default=DEFAULT_DATABASE)
    verify.add_argument('--reviewed-annotations', action='store_true')
    verify.add_argument('--output')
    chunk = sub.add_parser('chunk', help='Build pinned-tokenizer chunks offline')
    chunk.add_argument('--database', default=DEFAULT_DATABASE)
    args = parser.parse_args()
    if args.command == 'chunk':
        from pathlib import Path
        from .embedding import load_tokenizer
        from .chunking import persist_chunks
        if not Path(args.database).is_file():
            parser.error('Database does not exist; ingest a corpus first')
        tokenizer = load_tokenizer()
        with CorpusStore(args.database) as store:
            report = persist_chunks(store, tokenizer)
    elif args.command == 'ingest':
        report = ingest(args.manifest, args.database, reviewed_annotations=args.reviewed_annotations)
        if args.check_idempotence:
            again = ingest(args.manifest, args.database, reviewed_annotations=args.reviewed_annotations)
            if again['corpus_sha256'] != report['corpus_sha256'] or again['changed_documents'] or again['changed_relationships']:
                raise RuntimeError('Persistent idempotence check failed')
            report['idempotence_verified'] = True
    elif args.command == 'prepare-nvd':
        from pathlib import Path
        from .acquisition import prepare_nvd
        report = prepare_nvd(args.directory)
        Path(args.directory, 'nvd-entry.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    elif args.command == 'acquire-incidents':
        from .acquisition import acquire_incidents
        report = acquire_incidents(args.candidates, args.directory)
    elif args.command == 'prepare-attack':
        from .acquisition import prepare_attack
        report = prepare_attack(args.directory)
    elif args.command == 'prepare-corpus':
        from .preparation import prepare_corpus
        report = prepare_corpus(directory=args.directory)
    elif args.command == 'prepare-complete-corpus':
        from .preparation import prepare_complete_corpus
        report = prepare_complete_corpus()
    elif args.command == 'verify-corpus':
        from .verification import verify_corpus
        report = verify_corpus(args.manifest, args.database, reviewed_annotations=args.reviewed_annotations)
        if args.output:
            from .preparation import write_json
            from pathlib import Path
            write_json(Path(args.output), report)
    else:
        from pathlib import Path
        if not Path(args.database).is_file():
            parser.error('Database does not exist; ingest a corpus first')
        with CorpusStore(args.database) as store:
            batch = store.load()
            report = {'corpus_sha256': corpus_hash(batch), 'documents': len(batch.documents), 'relationships': len(batch.relationships),
                      'integrity_check': store.connection.execute('PRAGMA integrity_check').fetchone()[0],
                      'foreign_key_errors': store.connection.execute('PRAGMA foreign_key_check').fetchall()}
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
