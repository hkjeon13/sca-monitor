#!/usr/bin/env python3
"""Operator-only service credential lifecycle. Token files are created exclusively."""
import argparse
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.sca_monitor.config import load_settings
from backend.sca_monitor.db import Database, utcnow
from backend.sca_monitor.intel_integration import create_credential
from backend.sca_monitor.coordination import interactive_write


def main():
    p = argparse.ArgumentParser()
    p.add_argument('operation', choices=['create', 'rotate', 'revoke', 'list', 'grant'])
    p.add_argument('--name', default='ARTEX intel reader')
    p.add_argument('--days', type=int, default=90)
    p.add_argument('--id')
    p.add_argument('--output-token-file', type=Path)
    p.add_argument('--scope', action='append', choices=['intel:read', 'exploit:read', 'exploit:raw'],
        help='Repeat to grant scopes. Create defaults to intel:read; rotate preserves existing scopes.')
    args = p.parse_args()
    settings = load_settings('migration')
    db = Database(settings.database_url)
    scopes = args.scope
    if args.operation == 'rotate' and scopes is None:
        with db.connect() as conn:
            previous = conn.execute('SELECT scopes FROM intel_service_credentials WHERE id=? AND revoked_at IS NULL', (args.id,)).fetchone()
        if not previous:
            p.error('active credential not found')
        scopes = json.loads(previous['scopes'])
    if args.operation in ('create', 'rotate'):
        if not args.output_token_file or args.operation == 'rotate' and not args.id:
            p.error('create/rotate requires --output-token-file; rotate requires --id')
        # Reserve a private destination before creating a usable credential.
        descriptor = os.open(args.output_token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            token = 'sca_intel_' + secrets.token_urlsafe(48)
            output.write(token + '\n')
            output.flush()
            os.fsync(output.fileno())
            with interactive_write(settings.data_dir):
                item, token = create_credential(db, args.name, args.days,
                    rotate_id=args.id if args.operation == 'rotate' else None, token=token, scopes=scopes)
        print(json.dumps(item | {'token_file': str(args.output_token_file)}))
    else:
        with interactive_write(settings.data_dir), db.connect() as conn:
            if args.operation == 'grant':
                if not args.id or not args.scope:
                    p.error('grant requires --id and at least one --scope')
                previous = conn.execute('SELECT scopes FROM intel_service_credentials WHERE id=? AND revoked_at IS NULL', (args.id,)).fetchone()
                if not previous:
                    p.error('active credential not found')
                scopes = sorted(set(json.loads(previous['scopes'])) | set(args.scope))
                conn.execute('UPDATE intel_service_credentials SET scopes=? WHERE id=?', (json.dumps(scopes), args.id))
                print(json.dumps({'id': args.id, 'scopes': scopes, 'token_preserved': True}))
            elif args.operation == 'revoke':
                if not args.id:
                    p.error('revoke requires --id')
                count = conn.execute('UPDATE intel_service_credentials SET revoked_at=? WHERE id=? AND revoked_at IS NULL', (utcnow(), args.id)).rowcount
                print(json.dumps({'revoked': count, 'id': args.id}))
            else:
                rows = conn.execute('SELECT id,name,scopes,created_at,expires_at,revoked_at,last_used_at FROM intel_service_credentials ORDER BY created_at').fetchall()
                print(json.dumps({'credentials': [dict(r) for r in rows]}))


if __name__ == '__main__':
    main()
