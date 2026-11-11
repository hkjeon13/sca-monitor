import hashlib
import json
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import Settings
from backend.sca_monitor.intel_integration import canonical, create_credential, sha256

PREFIX = '/api/v2/integration/intel/'


@pytest.fixture
def intel(tmp_path):
    app = ScaMonitorApp(Settings(app_env='test', host='127.0.0.1', port=0,
        data_dir=tmp_path, database_url=str(tmp_path / 'db.sqlite3'), database_path=tmp_path / 'db.sqlite3',
        frontend_dir=Path('frontend').resolve(), smoke_token='test', auth_mode='local'))
    item, token = create_credential(app.db, 'ARTEX fixture')
    payload = {'id': 'GHSA-abcd-abcd-abcd', 'summary': 'Owned test advisory',
        'details': 'untrusted text 漢字' * 2000, 'aliases': ['CVE-2026-900000'],
        'affected': [{'package': {'ecosystem': 'npm', 'name': 'owned-demo'},
            'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '2.0.0'}]}]}],
        'references': [{'type': 'ADVISORY', 'url': 'https://example.invalid/advisory'}],
        'modified': '2026-11-03T00:00:00Z', 'published': '2026-11-02T00:00:00Z'}
    app.import_osv_payload(payload)
    server = ThreadingHTTPServer(('127.0.0.1', 0), app.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()

    def req(path, *, method='GET', credential=token):
        headers = {'Authorization': 'Bearer ' + credential} if credential else {}
        request = Request(f'http://127.0.0.1:{server.server_port}' + path, headers=headers, method=method)
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)
    yield app, item, token, payload, req
    server.shutdown();server.server_close();thread.join()


def test_intel_actual_get_search_detail_raw_and_hash_without_workspace_data(intel):
    app, _, _, payload, req = intel
    status, result = req(PREFIX + 'advisories?q=CVE-2026-900000&page_size=1')
    assert status == 200 and result['schema_version'] == 'sca-intel.v1'
    assert len(result['sources']) == 5 and result['result_status'] == 'matches'
    assert result['ordering']['fields'][0] == {'field': 'modified_at', 'direction': 'desc', 'nulls': 'last'}
    assert result['ordering']['sort_parameter_supported'] is False
    assert result['ordering']['unique_cve_ids'] is False
    assert result['fresh'] is False
    identifier = result['items'][0]['record_id']
    status, result = req(PREFIX + 'advisories/' + identifier)
    assert status == 200 and 'impacts' not in result and 'projects' not in canonical(result)
    item = result['advisory']
    assert item['fixed_version'] == '2.0.0' and item['affected_ranges'] and item['record_collected_at'] is None
    assert item['raw_payload_omitted'] and item['cpe_applicability'].startswith('unknown')
    offset, chunks = 0, []
    while offset is not None:
        status, piece = req(PREFIX + f'advisories/{identifier}/raw?offset={offset}&limit=8000&sha256={item["raw_sha256"]}')
        assert status == 200 and piece['offset_unit'] == 'unicode_codepoints'
        assert piece['chunk_sha256'] == sha256(piece['chunk'])
        chunks.append(piece['chunk']);offset = piece['next_offset']
    full = ''.join(chunks)
    assert sha256(full) == item['raw_sha256'] and json.loads(full) == payload
    assert req(PREFIX + f'advisories/{identifier}/raw?sha256=' + '0' * 64)[0] == 409
    assert req(PREFIX + 'advisories/' + payload['aliases'][0])[0] == 404
    assert req(PREFIX + 'advisories?q=CVE-2099-999999999')[1]['result_status'] == 'no_local_match'


@pytest.mark.parametrize('path', ['/api/v2/projects', '/api/v2/intel/sources', '/api/v1/services', '/api/v1/overview'])
def test_intel_service_bearer_cannot_access_browser_or_project_data(intel, path):
    assert intel[-1](path)[0] == 401


def test_intel_auth_scope_expiry_revocation_rotation_and_concurrency(intel):
    app, item, token, _, req = intel
    path = PREFIX + 'sources'
    assert req(path, credential='')[0] == 401
    assert req(path, credential='sca_intel_' + 'z' * 64)[0] == 401
    assert req(path, method='POST')[0] == 405
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(x[0] == 200 for x in pool.map(lambda _: req(path), range(8)))
    with app.db.connect() as conn:
        row = conn.execute('SELECT * FROM intel_service_credentials WHERE id=?', (item['id'],)).fetchone()
        assert row['token_hash'] != token and token not in canonical(dict(row)) and row['last_used_at']
        conn.execute('UPDATE intel_service_credentials SET scopes=? WHERE id=?', ('[]', item['id']))
    assert req(path)[0] == 403
    with app.db.connect() as conn:
        conn.execute('UPDATE intel_service_credentials SET scopes=?,expires_at=? WHERE id=?', ('["intel:read"]', '2020-01-01T00:00:00+00:00', item['id']))
    assert req(path)[0] == 401
    new_item, new_token = create_credential(app.db, 'rotated', rotate_id=item['id'])
    assert req(path)[0] == 401 and req(path, credential=new_token)[0] == 200
    with app.db.connect() as conn:
        conn.execute('UPDATE intel_service_credentials SET revoked_at=? WHERE id=?', ('2026-01-01', new_item['id']))
    assert req(path, credential=new_token)[0] == 401


def test_intel_failure_freshness_rate_limit_and_invalid_inputs(intel):
    app, item, _, _, req = intel
    now = datetime.now(timezone.utc).isoformat()
    with app.db.connect() as conn:
        for source in ('NVD', 'GHSA', 'OSV', 'OpenSSF', 'CISA_KEV'):
            conn.execute('''INSERT INTO advisory_sync_state(source,status,last_success_at,updated_at) VALUES(?,?,?,?)
                ON CONFLICT(source) DO UPDATE SET status=excluded.status,last_success_at=excluded.last_success_at''', (source, 'ok', now, now))
    app.workspace._source_cache = None
    assert req(PREFIX + 'sources')[1]['fresh'] is True
    with app.db.connect() as conn:
        conn.execute("UPDATE advisory_sync_state SET status='partial',last_error_message='private-detail' WHERE source='NVD'")
    app.workspace._source_cache = None
    result = req(PREFIX + 'sources')[1]
    assert not result['fresh'] and 'private-detail' not in canonical(result)
    assert next(s for s in result['sources'] if s['source'] == 'NVD')['error_code'] == 'collector_failed'
    for query in ['project_id=secret', 'q=x&q=y', 'page_size=0', 'page_size=26', 'source=unknown', 'kev=1', 'modified_from=2026-01-01']:
        assert req(PREFIX + 'advisories?' + query)[0] == 400
    with app.db.connect() as conn:
        conn.execute('UPDATE intel_service_credentials SET rate_window_start=?,rate_count=120 WHERE id=?', (now, item['id']))
    assert req(PREFIX + 'sources')[0] == 429


def test_intel_busy_is_503_not_empty_result(intel, monkeypatch):
    app, _, _, _, req = intel
    def busy(*args, **kwargs):
        raise sqlite3.OperationalError('database is locked')
    monkeypatch.setattr(app.intel_integration, 'search', busy)
    assert req(PREFIX + 'advisories?q=x') == (503, {'error': 'intel_temporarily_unavailable'})


def test_operator_cli_exclusive_private_file_and_rotation(intel, tmp_path):
    import os
    app, _, _, _, req = intel
    token_file = tmp_path / 'service-token'
    env = dict(os.environ, SCA_MONITOR_DATABASE_URL=app.db.database_url,
        SCA_MONITOR_DATA_DIR=str(app.settings.data_dir))
    command = [sys.executable, 'scripts/intel_credentials.py']
    created = subprocess.run(command + ['create', '--output-token-file', str(token_file)],
        capture_output=True, text=True, env=env, check=True)
    token = token_file.read_text().strip()
    assert token not in created.stdout and token_file.stat().st_mode & 0o777 == 0o600
    assert req(PREFIX + 'sources', credential=token)[0] == 200
    previous = token_file.read_bytes()
    conflict = subprocess.run(command + ['create', '--output-token-file', str(token_file)],
        capture_output=True, text=True, env=env)
    assert conflict.returncode and token_file.read_bytes() == previous
    listing = subprocess.run(command + ['list'], capture_output=True, text=True, env=env, check=True)
    assert token not in listing.stdout and 'token_hash' not in listing.stdout
    identifier = json.loads(created.stdout)['id']
    rotated_file = tmp_path / 'rotated-token'
    subprocess.run(command + ['rotate', '--id', identifier, '--output-token-file', str(rotated_file)],
        capture_output=True, text=True, env=env, check=True)
    assert req(PREFIX + 'sources', credential=token)[0] == 401
    assert req(PREFIX + 'sources', credential=rotated_file.read_text().strip())[0] == 200


def test_additive_migration_preserves_existing_records(tmp_path, monkeypatch):
    import backend.sca_monitor.db as database_module
    from backend.sca_monitor.db import Database
    paths = database_module.migration_files
    db = Database(tmp_path / 'existing.sqlite3')
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'migration_files', lambda backend: [p for p in paths(backend) if int(p.name[:3]) <= 22])
        db.migrate()
    with db.connect() as conn:
        before = [dict(r) for r in conn.execute('SELECT * FROM advisories ORDER BY id').fetchall()]
        assert conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 22
    db.migrate()
    with db.connect() as conn:
        assert before == [dict(r) for r in conn.execute('SELECT * FROM advisories ORDER BY id').fetchall()]
        from backend.sca_monitor.migrations import REQUIRED_MIGRATION_VERSION
        assert conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == REQUIRED_MIGRATION_VERSION
    item, token = create_credential(db, 'migration fixture')
    with db.connect() as conn:
        assert conn.execute('SELECT token_hash FROM intel_service_credentials WHERE id=?', (item['id'],)).fetchone()[0] == sha256(token)


def test_declared_fixed_order_matches_actual_modified_and_record_order(intel):
    app, _, _, payload, req = intel
    for suffix, modified in [('one', '2026-11-01T00:00:00Z'), ('two', '2026-11-04T00:00:00Z')]:
        app.import_osv_payload(payload | {'id': 'GHSA-order-' + suffix,
            'aliases': [], 'modified': modified})
    status, result = req(PREFIX + 'advisories?package=owned-demo&page_size=25')
    assert status == 200
    order = [(item['modified_at'], item['record_id']) for item in result['items']]
    assert order == sorted(order, reverse=True)
    assert req(PREFIX + 'advisories?sort=modified_desc')[0] == 400
