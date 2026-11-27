"""HTTP and durable-state regressions for collector recovery (owned data only)."""
import json
import gzip
import threading
import zipfile
import sqlite3
import stat
import subprocess
import sys
import os
from pathlib import Path
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request

import pytest

from backend.sca_monitor.advisory_sync import (
    NvdAPIClient, sync_nvd_modified_window, sync_nvd_cve,
    sync_osv_ecosystem_dump,
    parse_nvd_cve_vulnerability,
    _collector_connection, _committed_batch,
    sync_cisa_kev_catalog,
)
from test_smoke import make_test_app, nvd_cve_fixture, osv_fixture, malicious_osv_fixture, cisa_kev_fixture


START = "2026-06-01T00:00:00.000"
END = "2026-06-02T00:00:00.000"


@contextmanager
def upstream(responder, observed_encodings=None):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            query = parse_qs(urlparse(self.path).query)
            if observed_encodings is not None:
                observed_encodings.append(self.headers.get("Accept-Encoding"))
            calls.append(query)
            status, payload, headers = responder(query, len(calls))
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            if not isinstance(payload, bytes) and headers.get("Content-Encoding") == "gzip":
                body = gzip.compress(body)
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/cves", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def page(index, total=2):
    return {"startIndex": index, "resultsPerPage": 1, "totalResults": total,
        "vulnerabilities": nvd_cve_fixture(f"CVE-2026-{index + 1:04}")["vulnerabilities"]}


def state(app):
    with app.db.connect() as conn:
        return dict(conn.execute("SELECT * FROM advisory_sync_state WHERE source='NVD'").fetchone())


def collect(app, url, **kwargs):
    return sync_nvd_modified_window(app, last_mod_start=START, last_mod_end=END,
        api_url=url, results_per_page=1, delay_seconds=0, **kwargs)


def test_full_pages_are_saved_without_refetch_and_replay_preserves_record_ids(tmp_path):
    app = make_test_app(tmp_path)
    original = app.import_osv_payload(osv_fixture())
    with upstream(lambda q, n: (200, page(int(q["startIndex"][0])), {})) as (url, calls):
        result = collect(app, url)
        with app.db.connect() as conn:
            before = [tuple(r) for r in conn.execute("SELECT id,advisory_id FROM advisories ORDER BY id")]
        replay = collect(app, url)
        with app.db.connect() as conn:
            after = [tuple(r) for r in conn.execute("SELECT id,advisory_id FROM advisories ORDER BY id")]
    assert result.processed == replay.processed == 2
    assert result.failed == 0 and result.pages == 2
    assert before == after and original["imported"] == 1
    assert len(calls) == 4 and all("cveId" not in call for call in calls)
    assert [q["startIndex"][0] for q in calls] == ["0", "1", "0", "1"]
    assert state(app)["cursor"] == END and state(app)["status"] == "ok"


def test_failed_second_page_keeps_completed_cursor_and_committed_data_then_resumes(tmp_path):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("NVD", "ok", None, None, cursor=START)
    failed = [True]

    def respond(query, number):
        index = int(query["startIndex"][0])
        if index == 1 and failed[0]:
            return 403, {"message": "denied"}, {}
        return 200, page(index), {}

    with upstream(respond) as (url, calls):
        with pytest.raises(HTTPError):
            collect(app, url)
        assert state(app)["cursor"] == START
        assert state(app)["status"] == "partial"
        assert app.get_advisory("CVE-2026-0001")["advisory"]["raw_payload"]["id"] == "CVE-2026-0001"
        failed[0] = False
        assert collect(app, url).processed == 2
    assert state(app)["cursor"] == END


def test_cancelled_page_preserves_pending_window_and_releases_source_lock(tmp_path):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("NVD", "ok", None, None, cursor=START)

    def cancelled(progress):
        if progress["event"] == "nvd_page":
            raise KeyboardInterrupt()

    with upstream(lambda q, n: (200, page(int(q["startIndex"][0])), {})) as (url, calls):
        with pytest.raises(KeyboardInterrupt):
            collect(app, url, progress=cancelled)
        saved = state(app)
        assert saved["cursor"] == START and saved["lock_owner"] is None
        assert saved["status"] == "partial" and saved["records_processed"] == 1
        assert collect(app, url).processed == 2


@pytest.mark.parametrize("payload", [
    {"startIndex": 0, "resultsPerPage": 0, "totalResults": 2, "vulnerabilities": []},
    {"startIndex": 99, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []},
    {"startIndex": 0, "resultsPerPage": 0, "totalResults": 0},
])
def test_incomplete_pages_never_advance_cursor(tmp_path, payload):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("NVD", "ok", None, None, cursor=START)
    with upstream(lambda q, n: (200, payload, {})) as (url, calls):
        with pytest.raises(ValueError):
            collect(app, url)
    assert state(app)["cursor"] == START and state(app)["status"] == "error"


def test_empty_completed_window_can_advance_without_creating_advisories(tmp_path):
    app = make_test_app(tmp_path)
    payload = {"startIndex": 0, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    with upstream(lambda q, n: (200, payload, {})) as (url, calls):
        result = collect(app, url)
    assert result.processed == 0 and state(app)["cursor"] == END


def test_http_429_and_503_retry_then_success_without_real_sleep():
    waits = []

    def respond(query, number):
        return (429 if number == 1 else 503 if number == 2 else 200), {"ok": number == 3}, {"Retry-After": "0"}

    with upstream(respond) as (url, calls):
        result = NvdAPIClient(delay_seconds=0, sleep_func=waits.append).fetch(Request(url))
    assert result == {"ok": True} and len(calls) == 3
    assert 6 in waits and 12 in waits


def test_http_denial_is_not_retried():
    with upstream(lambda q, n: (403, {"message": "denied"}, {})) as (url, calls):
        with pytest.raises(HTTPError):
            NvdAPIClient(delay_seconds=0, sleep_func=lambda n: None).fetch(Request(url))
    assert len(calls) == 1


def test_partial_osv_dump_does_not_publish_per_record_success(tmp_path):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("OSV", "ok", None, None)
    with app.db.connect() as conn:
        old_success = conn.execute("SELECT last_success_at FROM advisory_sync_state WHERE source='OSV'").fetchone()[0]
    path = tmp_path / "partial.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.json", json.dumps(osv_fixture()))
        archive.writestr("b.json", json.dumps({"id": "OSV-EMPTY"}))
    result = sync_osv_ecosystem_dump(app, "npm", zip_path=path)
    assert result.failed == 1 and result.imported_rows == 1
    with app.db.connect() as conn:
        saved = conn.execute("SELECT status,last_success_at,imported_count FROM advisory_sync_state WHERE source='OSV'").fetchone()
    assert saved["status"] == "partial" and saved["last_success_at"] == old_success
    assert saved["imported_count"] == 1


def test_source_refresh_preserves_nvd_evidence_and_unchanged_aliases(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(nvd_cve_fixture()))
    sync_nvd_cve(app, "CVE-2026-0001", json_path=path)
    before = app.get_advisory("OSV-TEST-0001")["advisory"]
    result = app.import_osv_payload(osv_fixture())
    after = app.get_advisory("OSV-TEST-0001")["advisory"]
    assert result["changed"] == 0
    assert before["raw_payload"]["_nvd_enrichment"] == after["raw_payload"]["_nvd_enrichment"]
    assert before["id"] == after["id"] and before["aliases"] == after["aliases"]


def test_multi_version_cpe_conditions_are_preserved_without_repeated_product_updates(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    payload = nvd_cve_fixture()
    matches = payload["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]["cpeMatch"]
    extra = json.loads(json.dumps(matches[0]))
    extra["versionEndExcluding"] = "9.0.0"
    matches.append(extra)
    parsed = parse_nvd_cve_vulnerability(payload["vulnerabilities"][0])
    assert len(parsed) == 1 and len(parsed[0].affected_ranges) == 2
    assert parsed[0].advisory_id == "CVE-2026-0001:example/example-server"
    path = tmp_path / "multi-cpe.json"
    path.write_text(json.dumps(payload))
    assert sync_nvd_cve(app, "CVE-2026-0001", json_path=path).imported_rows == 1
    saved = app.get_advisory(parsed[0].advisory_id)["advisory"]
    assert saved["affected_ranges"] == matches
    assert saved["raw_payload"] == payload["vulnerabilities"][0]["cve"]
    enriched = app.get_advisory("OSV-TEST-0001")["advisory"]["raw_payload"]["_nvd_enrichment"]
    assert enriched["cve_id"] == "CVE-2026-0001" and enriched["cpe_matches"] == matches


def test_wal_batches_remain_full_durability_and_visible_to_independent_readers(tmp_path):
    app = make_test_app(tmp_path)
    with app.db.connect() as setup:
        assert setup.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    with _collector_connection(app) as writer:
        assert writer.execute("PRAGMA synchronous").fetchone()[0] == 2
        with _committed_batch(app, writer):
            result = app.import_osv_payload(osv_fixture(), record_state=False, connection=writer)
        assert result["changed"] == 1
        # The reader sees the commit before the collector closes/checkpoints.
        saved = app.get_advisory("OSV-TEST-0001")["advisory"]
        assert saved["raw_payload"]["id"] == "OSV-TEST-0001"
    with app.db.connect() as reopened:
        assert reopened.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_overlapping_osv_and_openssf_feeds_do_not_rewrite_mal_records_each_cycle(tmp_path):
    app = make_test_app(tmp_path)
    path = tmp_path / "overlap.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("normal.json", json.dumps(osv_fixture()))
        archive.writestr("malicious.json", json.dumps(malicious_osv_fixture()))
    assert sync_osv_ecosystem_dump(app, "npm", zip_path=path).failed == 0
    before = app.get_advisory("MAL-2026-0001")["advisory"]
    assert before["source"] == "OpenSSF"
    assert sync_osv_ecosystem_dump(app, "npm", zip_path=path, source="OpenSSF", malicious_only=True).failed == 0
    assert sync_osv_ecosystem_dump(app, "npm", zip_path=path).failed == 0
    after = app.get_advisory("MAL-2026-0001")["advisory"]
    assert before == after


def test_online_backup_includes_open_wal_follows_symlink_and_preserves_previous_backup(tmp_path, monkeypatch):
    from scripts.backup_database import backup_database
    from scripts.verify_backup_restore import verify_backup_restore
    app = make_test_app(tmp_path)
    alias = tmp_path / "active.sqlite3"
    alias.symlink_to(app.db.path)
    monkeypatch.setenv("SCA_MONITOR_DATABASE_URL", "sqlite:///" + str(alias))
    with app.db.connect() as setup:
        setup.execute("PRAGMA journal_mode=WAL")
    with _collector_connection(app) as writer:
        with _committed_batch(app, writer):
            app.import_osv_payload(osv_fixture(), record_state=False, connection=writer)
        first = backup_database(backup_dir=tmp_path / "backups", required=True)
        from pathlib import Path
        first_path = Path(first["backup_path"])
        before = first_path.read_bytes()
        with sqlite3.connect(first_path) as restored:
            assert restored.execute("SELECT COUNT(*) FROM advisories WHERE advisory_id='OSV-TEST-0001'").fetchone()[0] == 1
        assert stat.S_IMODE(first_path.stat().st_mode) == 0o600
        second = backup_database(backup_dir=tmp_path / "backups", required=True)
        assert first["backup_path"] != second["backup_path"]
        assert first_path.read_bytes() == before
        assert verify_backup_restore(first_path)["status"] == "ok"


def test_nvd_gzip_and_plain_responses_preserve_complete_json_and_retry_truncation():
    encodings = []
    value = nvd_cve_fixture()
    truncated = gzip.compress(json.dumps(value).encode())[:-8]

    def respond(query, number):
        return 200, truncated if number == 1 else value, {"Content-Encoding": "gzip"}

    with upstream(respond, encodings) as (url, calls):
        client = NvdAPIClient(delay_seconds=0, sleep_func=lambda n: None)
        actual = client.fetch(Request(url))
    assert actual == value and len(calls) == 2
    assert client.last_response == {"http_status": 200, "content_encoding": "gzip"}
    assert encodings == ["gzip", "gzip"]
    with upstream(lambda q, n: (200, value, {})) as (url, calls):
        assert NvdAPIClient(delay_seconds=0).fetch(Request(url)) == value


def test_nvd_refresh_keeps_independent_kev_evidence_without_changing_official_raw_json(tmp_path):
    app = make_test_app(tmp_path)
    payload = nvd_cve_fixture()
    original = payload["vulnerabilities"][0]["cve"]
    original.pop("cisaExploitAdd")
    nvd = tmp_path / "nvd-without-kev.json"
    nvd.write_text(json.dumps(payload))
    sync_nvd_cve(app, "CVE-2026-0001", json_path=nvd)
    assert app.get_advisory("CVE-2026-0001")["advisory"]["is_known_exploited"] is False
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps(cisa_kev_fixture()))
    sync_cisa_kev_catalog(app, json_path=kev)
    before = app.get_advisory("CVE-2026-0001")["advisory"]
    assert before["is_known_exploited"] is True
    sync_nvd_cve(app, "CVE-2026-0001", json_path=nvd)
    after = app.get_advisory("CVE-2026-0001")["advisory"]
    assert after["id"] == before["id"] and after["is_known_exploited"] is True
    assert after["raw_payload"] == original


@pytest.mark.parametrize("always_changes", [False, True])
def test_cli_live_window_drift_retries_are_bounded_and_never_skip_data(tmp_path, always_changes):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("NVD", "ok", None, None, cursor=START)

    def respond(query, number):
        index = int(query["startIndex"][0])
        total = 3 if index == 0 and (always_changes or number == 1) else 2
        return 200, page(index, total=total), {}

    with upstream(respond) as (url, calls):
        result = subprocess.run([sys.executable, "scripts/nvd_cve_sync.py",
            "--api-url", url, "--last-mod-start", START, "--last-mod-end", END,
            "--modified-results-per-page", "1", "--delay-seconds", "0.001"],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
            env={"PATH": os.environ.get("PATH", ""),
                "SCA_MONITOR_DATABASE_URL": str(app.db.path),
                "SCA_MONITOR_DATA_DIR": str(tmp_path), "SCA_MONITOR_AUTO_MIGRATE": "false"},
            timeout=20)
    assert '"event": "nvd_window_retry"' in result.stdout
    if always_changes:
        assert result.returncode != 0 and len(calls) == 6
        assert state(app)["cursor"] == START and state(app)["status"] == "partial"
    else:
        assert result.returncode == 0 and len(calls) == 4
        assert state(app)["cursor"] == END and state(app)["status"] == "ok"
        assert app.get_advisory("CVE-2026-0001")["advisory"]["raw_payload"]["id"] == "CVE-2026-0001"
        assert app.get_advisory("CVE-2026-0002")["advisory"]["raw_payload"]["id"] == "CVE-2026-0002"
