import json
import os
import subprocess
import tomllib
import threading
import zipfile
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from backend.sca_monitor.alert_dispatch import alert_payload, dispatch_alert_batches, dispatch_pending_alerts
from backend.sca_monitor.advisory_sync import (
    parse_ghsa_advisory,
    parse_cisa_kev_vulnerability,
    parse_nvd_cve_vulnerability,
    load_nvd_modified_cve_ids,
    nvd_cve_ids_from_payload,
    sync_github_advisories,
    sync_cisa_kev_catalog,
    sync_nvd_cve,
    sync_nvd_cves,
    sync_osv_ecosystem_dump,
)
from backend.sca_monitor.endpoint_poll import endpoint_poll_lock, poll_configured_endpoints
from backend.sca_monitor.db import Database, PostgresConnectionAdapter, canonical_package_name, json_column, postgres_sql, row_to_dict
from backend.sca_monitor.migrations import REQUIRED_MIGRATION_VERSION
from backend.sca_monitor.app import ScaMonitorApp, advisory_import_from_row
from backend.sca_monitor.config import Settings, load_settings, runtime_database_url_summary
from backend.sca_monitor.osv import parse_osv_advisories
from backend.sca_monitor.postgres_cutover import assess_cutover, summarize_preflight
from backend.sca_monitor.versioning import version_is_affected
from scripts.nvd_cve_sync import nvd_cursor_or_fallback_start


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_pypi_canonical_name():
    assert canonical_package_name("PyPI", "Django_REST.Framework") == "django-rest-framework"


def test_npm_canonical_name():
    assert canonical_package_name("npm", "Lodash") == "lodash"


def test_json_column_accepts_sqlite_and_postgres_values():
    assert json_column('["CVE-2026-0001"]', []) == ["CVE-2026-0001"]
    assert json_column(["CVE-2026-0001"], []) == ["CVE-2026-0001"]
    assert json_column('{"source":"OSV"}', {}) == {"source": "OSV"}
    assert json_column({"source": "OSV"}, {}) == {"source": "OSV"}
    assert json_column(None, []) == []
    assert json_column("", {}) == {}


def test_alert_payload_accepts_postgres_jsonb_dict():
    payload = alert_payload(
        {
            "payload": {"existing": "value"},
            "id": "alert-1",
            "impact_pk": "impact-1",
            "alert_suppression_key": "svc:prod:adv:pkg:high:open",
            "reason": "new impact",
            "service_id": "svc",
            "service_name": "Service",
            "environment": "prod",
            "advisory_id": "OSV-2026-0001",
            "summary": "Reported malicious package",
            "risk_level": "critical",
            "package_name": "left-pad",
            "resolved_version": "1.0.0",
        }
    )

    assert payload["existing"] == "value"
    assert payload["alert_event_id"] == "alert-1"
    assert payload["advisory_id"] == "OSV-2026-0001"


def test_advisory_import_from_row_accepts_postgres_jsonb_values():
    advisory = advisory_import_from_row(
        {
            "advisory_id": "OSV-2026-0001",
            "source": "OSV",
            "summary": "Reported malicious package",
            "severity": "critical",
            "ecosystem": "npm",
            "package_name": "left-pad",
            "canonical_package_name": "left-pad",
            "affected_versions": ["1.0.0"],
            "affected_ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            "fixed_version": None,
            "is_known_exploited": False,
            "is_malicious_package": True,
            "published_at": "2026-06-01T00:00:00+00:00",
            "modified_at": "2026-06-02T00:00:00+00:00",
            "raw_payload": {"id": "OSV-2026-0001"},
        }
    )

    assert advisory.affected_versions == ["1.0.0"]
    assert advisory.affected_ranges[0]["type"] == "SEMVER"
    assert advisory.raw_payload == {"id": "OSV-2026-0001"}


def test_sqlite_migration_records_version(tmp_path):
    database = Database(tmp_path / "sca-monitor.sqlite3")

    database.migrate()

    assert database.current_migration_version() == REQUIRED_MIGRATION_VERSION
    readiness = database.readiness()
    assert readiness["database"] == "ok"
    assert readiness["database_backend"] == "sqlite"
    assert readiness["migration"]["compatible"] is True
    with database.connect() as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_logs'").fetchone()
        snapshot_columns = {row["name"] for row in conn.execute("PRAGMA table_info(dependency_snapshots)").fetchall()}
        assert "last_confirmed_at" in snapshot_columns
        assert conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'snapshot_push_rate_limits'").fetchone()
        assert conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'advisory_aliases'").fetchone()
        sync_columns = {row["name"] for row in conn.execute("PRAGMA table_info(advisory_sync_state)").fetchall()}
        assert {"cursor", "last_run_at", "records_processed"}.issubset(sync_columns)


def test_sqlite_connections_wait_for_short_lived_locks(tmp_path):
    database = Database(tmp_path / "busy-timeout.sqlite3")

    with database.connect() as conn:
        busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]

    assert busy_timeout >= 30000


def test_load_settings_selects_component_database_urls(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SCA_MONITOR_DATABASE_URL", raising=False)
    monkeypatch.setenv("API_DATABASE_URL", "sqlite:////tmp/sca-api.sqlite3")
    monkeypatch.setenv("WORKER_DATABASE_URL", "sqlite:////tmp/sca-worker.sqlite3")
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "sqlite:////tmp/sca-migration.sqlite3")

    assert load_settings(component="api").database_url == "sqlite:////tmp/sca-api.sqlite3"
    assert load_settings(component="api").database_url_source == "API_DATABASE_URL"
    assert load_settings(component="worker").database_url == "sqlite:////tmp/sca-worker.sqlite3"
    assert load_settings(component="worker").database_url_source == "WORKER_DATABASE_URL"
    assert load_settings(component="migration").database_url == "sqlite:////tmp/sca-migration.sqlite3"
    assert load_settings(component="migration").database_url_source == "MIGRATION_DATABASE_URL"

    monkeypatch.delenv("WORKER_DATABASE_URL", raising=False)
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)

    assert load_settings(component="worker").database_url == "sqlite:////tmp/sca-api.sqlite3"
    assert load_settings(component="worker").database_url_source == "API_DATABASE_URL"
    assert load_settings(component="migration").database_url == "sqlite:////tmp/sca-api.sqlite3"
    assert load_settings(component="migration").database_url_source == "API_DATABASE_URL"


def test_load_settings_global_database_url_overrides_component_urls(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SCA_MONITOR_DATABASE_URL", "sqlite:////tmp/sca-global.sqlite3")
    monkeypatch.setenv("API_DATABASE_URL", "sqlite:////tmp/sca-api.sqlite3")
    monkeypatch.setenv("WORKER_DATABASE_URL", "sqlite:////tmp/sca-worker.sqlite3")

    assert load_settings(component="api").database_url == "sqlite:////tmp/sca-global.sqlite3"
    assert load_settings(component="api").database_url_source == "SCA_MONITOR_DATABASE_URL"
    assert load_settings(component="worker").database_url == "sqlite:////tmp/sca-global.sqlite3"
    assert load_settings(component="worker").database_url_source == "SCA_MONITOR_DATABASE_URL"
    assert load_settings(component="migration").database_url == "sqlite:////tmp/sca-global.sqlite3"
    assert load_settings(component="migration").database_url_source == "SCA_MONITOR_DATABASE_URL"


def test_load_settings_reports_legacy_or_default_database_url_source(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SCA_MONITOR_DATABASE_URL", raising=False)
    monkeypatch.delenv("API_DATABASE_URL", raising=False)
    monkeypatch.delenv("WORKER_DATABASE_URL", raising=False)
    monkeypatch.delenv("SCA_MONITOR_DB", raising=False)

    default_settings = load_settings(component="api")

    assert default_settings.database_url_source == "default_sqlite"
    assert default_settings.database_url.endswith("/sca-monitor.sqlite3")

    legacy_path = tmp_path / "legacy.sqlite3"
    monkeypatch.setenv("SCA_MONITOR_DB", str(legacy_path))

    legacy_settings = load_settings(component="api")

    assert legacy_settings.database_url_source == "SCA_MONITOR_DB"
    assert legacy_settings.database_url == f"sqlite:///{legacy_path.resolve()}"


def test_runtime_database_url_summary_reports_split_sources_without_values(monkeypatch, tmp_path):
    monkeypatch.delenv("SCA_MONITOR_DATABASE_URL", raising=False)
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "postgresql://migration:secret@db.example.com/sca")
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://api:secret@db.example.com/sca")
    monkeypatch.setenv("WORKER_DATABASE_URL", "postgresql://worker:secret@db.example.com/sca")
    settings = Settings(
        app_env="test",
        host="127.0.0.1",
        port=0,
        data_dir=tmp_path,
        database_url="postgresql://api:secret@db.example.com/sca",
        database_path=tmp_path / "sca-monitor.sqlite3",
        frontend_dir=tmp_path,
        smoke_token="test",
        database_url_source="API_DATABASE_URL",
    )

    summary = runtime_database_url_summary(settings)

    assert summary == {
        "api": {"source": "API_DATABASE_URL", "backend": "postgres", "configured": True},
        "worker": {"source": "WORKER_DATABASE_URL", "backend": "postgres", "configured": True},
        "migration": {"source": "MIGRATION_DATABASE_URL", "backend": "postgres", "configured": True},
    }
    assert "secret" not in json.dumps(summary)
    assert "db.example.com" not in json.dumps(summary)


def test_load_settings_supports_component_auto_migrate_flags(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SCA_MONITOR_AUTO_MIGRATE", "true")
    monkeypatch.setenv("SCA_MONITOR_WORKER_AUTO_MIGRATE", "false")

    assert load_settings(component="api").auto_migrate is True
    assert load_settings(component="worker").auto_migrate is False


def test_load_settings_supports_advisory_sync_stale_threshold(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SCA_MONITOR_ADVISORY_SYNC_STALE_AFTER_SECONDS", "3600")

    settings = load_settings(component="api")

    assert settings.advisory_sync_stale_after_seconds == 3600


def test_load_settings_supports_strict_snapshot_push_flag(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SCA_MONITOR_STRICT_SNAPSHOT_PUSH", raising=False)

    assert load_settings(component="api").strict_snapshot_push is False

    monkeypatch.setenv("SCA_MONITOR_STRICT_SNAPSHOT_PUSH", "true")

    assert load_settings(component="api").strict_snapshot_push is True


def test_sca_monitor_app_can_skip_runtime_migration(tmp_path):
    settings = Settings(
        app_env="test",
        host="127.0.0.1",
        port=0,
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'no-auto-migrate.sqlite3'}",
        database_path=tmp_path / "no-auto-migrate.sqlite3",
        frontend_dir=tmp_path,
        smoke_token="test",
        auto_migrate=False,
    )

    app = ScaMonitorApp(settings)

    assert app.db.current_migration_version() == 0


def test_install_systemd_units_dry_run_writes_worker_units(tmp_path):
    unit_dir = tmp_path / "systemd"

    result = subprocess.run(
        [
            "bash",
            "scripts/install_systemd_units.sh",
            "--dry-run",
            "--unit-dir",
            str(unit_dir),
            "--repo-dir",
            str(REPO_ROOT),
            "--python",
            "/usr/bin/python3",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "dry-run: systemctl was not called" in result.stdout
    expected_units = {
        "sca-monitor-api.service",
        "sca-monitor-endpoint-poller.service",
        "sca-monitor-alert-dispatcher.service",
        "sca-monitor-alert-dispatcher-dry-run.service",
        "sca-monitor-accepted-risk-expiry.service",
        "sca-monitor-accepted-risk-expiry.timer",
        "sca-monitor-sla-escalation.service",
        "sca-monitor-sla-escalation.timer",
        "sca-monitor-advisory-freshness.service",
        "sca-monitor-advisory-freshness.timer",
        "sca-monitor-daily-digest.service",
        "sca-monitor-daily-digest.timer",
        "sca-monitor-cisa-kev-sync.service",
        "sca-monitor-cisa-kev-sync.timer",
        "sca-monitor-ghsa-sync.service",
        "sca-monitor-ghsa-sync.timer",
        "sca-monitor-nvd-cve-sync.service",
        "sca-monitor-nvd-cve-sync.timer",
        "sca-monitor-osv-npm-sync.service",
        "sca-monitor-osv-npm-sync.timer",
        "sca-monitor-openssf-malicious-sync.service",
        "sca-monitor-openssf-malicious-sync.timer",
        "sca-monitor-canonical-advisory-merge.service",
        "sca-monitor-canonical-advisory-merge.timer",
    }
    assert {path.name for path in unit_dir.iterdir()} == expected_units
    poller = (unit_dir / "sca-monitor-endpoint-poller.service").read_text(encoding="utf-8")
    assert f"WorkingDirectory={REPO_ROOT}" in poller
    assert f"EnvironmentFile=-{REPO_ROOT}/.env" in poller
    assert "Environment=SCA_MONITOR_AUTO_MIGRATE=false" in poller
    assert "scripts/poll_endpoints.py --limit 50 --iterations 0" in poller
    api = (unit_dir / "sca-monitor-api.service").read_text(encoding="utf-8")
    assert "Environment=SCA_MONITOR_AUTO_MIGRATE=false" in api
    expiry_timer = (unit_dir / "sca-monitor-accepted-risk-expiry.timer").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=15min" in expiry_timer
    ghsa = (unit_dir / "sca-monitor-ghsa-sync.service").read_text(encoding="utf-8")
    assert "scripts/ghsa_sync.py --lock-owner systemd-ghsa-sync" in ghsa
    nvd = (unit_dir / "sca-monitor-nvd-cve-sync.service").read_text(encoding="utf-8")
    assert "scripts/nvd_cve_sync.py --use-cursor --lookback-hours 24" in nvd
    assert "--modified-results-per-page 2000 --limit 100" in nvd
    assert "--lock-owner systemd-nvd-cve-sync --lock-ttl-seconds 3600" in nvd
    nvd_timer = (unit_dir / "sca-monitor-nvd-cve-sync.timer").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=6h" in nvd_timer
    assert "Unit=sca-monitor-nvd-cve-sync.service" in nvd_timer
    sla_service = (unit_dir / "sca-monitor-sla-escalation.service").read_text(encoding="utf-8")
    assert "scripts/evaluate_sla_escalations.py --limit 100 --actor sla-scheduler" in sla_service
    sla_timer = (unit_dir / "sca-monitor-sla-escalation.timer").read_text(encoding="utf-8")
    assert "Unit=sca-monitor-sla-escalation.service" in sla_timer
    advisory_freshness = (unit_dir / "sca-monitor-advisory-freshness.service").read_text(encoding="utf-8")
    assert "scripts/evaluate_advisory_sync_freshness.py --actor freshness-scheduler" in advisory_freshness
    advisory_freshness_timer = (unit_dir / "sca-monitor-advisory-freshness.timer").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=15min" in advisory_freshness_timer
    assert "Unit=sca-monitor-advisory-freshness.service" in advisory_freshness_timer
    digest_service = (unit_dir / "sca-monitor-daily-digest.service").read_text(encoding="utf-8")
    assert "scripts/create_daily_digest.py --limit 100 --timezone Asia/Seoul --actor digest-scheduler" in digest_service
    digest_timer = (unit_dir / "sca-monitor-daily-digest.timer").read_text(encoding="utf-8")
    assert "OnCalendar=*-*-* 09:00:00" in digest_timer
    openssf = (unit_dir / "sca-monitor-openssf-malicious-sync.service").read_text(encoding="utf-8")
    assert "scripts/osv_sync.py --ecosystem npm --source OpenSSF --malicious-only" in openssf
    canonical_merge = (unit_dir / "sca-monitor-canonical-advisory-merge.service").read_text(encoding="utf-8")
    assert "scripts/merge_canonical_advisories.py --limit 500 --actor canonical-merge-scheduler" in canonical_merge
    canonical_merge_timer = (unit_dir / "sca-monitor-canonical-advisory-merge.timer").read_text(encoding="utf-8")
    assert "Unit=sca-monitor-canonical-advisory-merge.service" in canonical_merge_timer
    dispatcher_dry_run = (unit_dir / "sca-monitor-alert-dispatcher-dry-run.service").read_text(encoding="utf-8")
    assert "Environment=SCA_MONITOR_AUTO_MIGRATE=false" in dispatcher_dry_run
    assert "scripts/dispatch_alerts.py --limit 50 --iterations 0" in dispatcher_dry_run
    assert "--lock-owner systemd-alert-dispatcher-dry-run --dry-run" in dispatcher_dry_run


def test_systemd_scheduler_status_reports_generated_units(tmp_path):
    unit_dir = tmp_path / "systemd"
    subprocess.run(
        [
            "bash",
            "scripts/install_systemd_units.sh",
            "--dry-run",
            "--unit-dir",
            str(unit_dir),
            "--repo-dir",
            str(REPO_ROOT),
            "--python",
            "/usr/bin/python3",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        ["python3", "scripts/systemd_scheduler_status.py", "--unit-dir", str(unit_dir), "--json"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["summary"] == {"expected": 24, "present": 24, "valid": 24, "missing": 0, "invalid": 0}
    assert payload["units"]["sca-monitor-api.service"]["valid"] is True
    assert payload["units"]["sca-monitor-daily-digest.timer"]["valid"] is True
    assert payload["units"]["sca-monitor-cisa-kev-sync.timer"]["valid"] is True
    assert payload["units"]["sca-monitor-ghsa-sync.timer"]["valid"] is True
    assert payload["units"]["sca-monitor-nvd-cve-sync.timer"]["valid"] is True
    assert payload["units"]["sca-monitor-openssf-malicious-sync.timer"]["valid"] is True
    assert payload["units"]["sca-monitor-advisory-freshness.timer"]["valid"] is True
    assert payload["units"]["sca-monitor-canonical-advisory-merge.timer"]["valid"] is True


def test_systemd_scheduler_status_can_require_active_units(tmp_path):
    unit_dir = tmp_path / "systemd"
    bin_dir = tmp_path / "bin"
    log_path = tmp_path / "systemctl.log"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        f"""#!/bin/sh
echo "$@" >> "{log_path}"
case " $* " in
  *" is-enabled "*) echo enabled ;;
  *" is-active "*) echo active ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    subprocess.run(
        [
            "bash",
            "scripts/install_systemd_units.sh",
            "--dry-run",
            "--unit-dir",
            str(unit_dir),
            "--repo-dir",
            str(REPO_ROOT),
            "--python",
            "/usr/bin/python3",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/systemd_scheduler_status.py",
            "--unit-dir",
            str(unit_dir),
            "--systemctl",
            "--require-active-unit",
            "sca-monitor-accepted-risk-expiry.timer",
            "--json",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["required_active_units"] == [
        {
            "unit": "sca-monitor-accepted-risk-expiry.timer",
            "enabled": "enabled",
            "active": "active",
            "ok": True,
        }
    ]


def test_systemd_scheduler_status_fails_when_required_unit_is_not_active(tmp_path):
    unit_dir = tmp_path / "systemd"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        """#!/bin/sh
case " $* " in
  *" is-enabled "*) echo disabled ;;
  *" is-active "*) echo inactive ;;
esac
exit 3
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    subprocess.run(
        [
            "bash",
            "scripts/install_systemd_units.sh",
            "--dry-run",
            "--unit-dir",
            str(unit_dir),
            "--repo-dir",
            str(REPO_ROOT),
            "--python",
            "/usr/bin/python3",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/systemd_scheduler_status.py",
            "--unit-dir",
            str(unit_dir),
            "--systemctl",
            "--require-active-unit",
            "sca-monitor-accepted-risk-expiry.timer",
            "--json",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "not_ready"
    assert payload["required_active_units"] == [
        {
            "unit": "sca-monitor-accepted-risk-expiry.timer",
            "enabled": "disabled",
            "active": "inactive",
            "ok": False,
        }
    ]


def test_http_smoke_checks_read_only_endpoints():
    seen_paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen_paths.append(self.path)
            if self.path in {"/health", "/ready", "/api/v1/overview", "/api/v1/operations/cutover-readiness-report"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>SCA Monitor</html>")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/http_smoke.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert [check["path"] for check in payload["checks"]] == [
        "/health",
        "/ready",
        "/api/v1/overview",
        "/api/v1/operations/cutover-readiness-report",
        "/",
    ]
    assert all(check["ok"] for check in payload["checks"])
    assert seen_paths == [
        "/health",
        "/ready",
        "/api/v1/overview",
        "/api/v1/operations/cutover-readiness-report",
        "/",
    ]


def test_http_smoke_can_require_postgres_split_metrics():
    seen_paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen_paths.append(self.path)
            if self.path in {"/health", "/ready", "/api/v1/overview", "/api/v1/operations/cutover-readiness-report"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
                return
            if self.path == "/metrics":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(
                    b"sca_monitor_postgres_split_required 0\n"
                    b"sca_monitor_postgres_split_ready 0\n"
                )
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>SCA Monitor</html>")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/http_smoke.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--require-postgres-split-metrics",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert "/metrics" in [check["path"] for check in payload["checks"]]
    assert payload["postgres_split_metrics"] == {
        "required_metric_present": True,
        "ready_metric_present": True,
    }
    assert seen_paths[:5] == ["/health", "/ready", "/api/v1/overview", "/api/v1/operations/cutover-readiness-report", "/"]
    assert "/metrics" in seen_paths


def test_http_smoke_can_expect_postgres_split_required_value():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ready":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "status": "ready",
                            "cutover_required": {"require_split": True},
                            "postgres_preflight": {"split_ready": False},
                        }
                    ).encode("utf-8")
                )
                return
            if self.path in {"/health", "/api/v1/overview", "/api/v1/operations/cutover-readiness-report"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
                return
            if self.path == "/metrics":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(
                    b"sca_monitor_postgres_split_required 1\n"
                    b"sca_monitor_postgres_split_ready 0\n"
                )
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>SCA Monitor</html>")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/http_smoke.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--expect-postgres-split-required",
                "true",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["postgres_split_consistency"] == {
        "expected_split_required": True,
        "ready_require_split": True,
        "metric_split_required": 1,
        "ok": True,
    }


def test_http_smoke_can_expect_database_backend():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ready":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "status": "ready",
                            "database_backend": "sqlite",
                            "migration": {"current": 17, "required": 17},
                        }
                    ).encode("utf-8")
                )
                return
            if self.path in {"/health", "/api/v1/overview", "/api/v1/operations/cutover-readiness-report"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>SCA Monitor</html>")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/http_smoke.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--expect-database-backend",
                "sqlite",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["database_backend"] == {
        "expected": "sqlite",
        "actual": "sqlite",
        "ok": True,
    }


def test_http_smoke_fails_when_database_backend_differs():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ready":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ready", "database_backend": "sqlite"}).encode("utf-8"))
                return
            if self.path in {"/health", "/api/v1/overview"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>SCA Monitor</html>")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/http_smoke.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--expect-database-backend",
                "postgres",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "failed"
    assert payload["database_backend"] == {
        "expected": "postgres",
        "actual": "sqlite",
        "ok": False,
    }


def test_http_smoke_can_expect_advisory_sync_ready():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/v1/overview":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "status": "ok",
                            "advisory_sync_readiness": {
                                "status": "ready",
                                "freshness": {"status": "fresh"},
                                "required_count": 3,
                                "initialized_count": 3,
                            },
                        }
                    ).encode("utf-8")
                )
                return
            if self.path in {"/health", "/ready", "/api/v1/operations/cutover-readiness-report"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>SCA Monitor</html>")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/http_smoke.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--expect-advisory-sync-ready",
                "true",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["advisory_sync_readiness"] == {
        "expected_ready": True,
        "overview_status": "ready",
        "freshness_status": "fresh",
        "initialized_count": 3,
        "required_count": 3,
        "ok": True,
    }


def test_http_smoke_can_expect_advisory_source_statuses(monkeypatch):
    import scripts.http_smoke as http_smoke

    def fake_smoke_url(base_url, path, timeout):
        return http_smoke.CheckResult(path=path, url=f"{base_url}{path}", ok=True, status=200, elapsed_ms=1, json_ok=path in http_smoke.JSON_PATHS)

    def fake_fetch_json(base_url, path, timeout):
        assert path == "/api/v1/overview"
        return 200, {
            "advisory_sync": {
                "OSV": "ok",
                "CISA_KEV": "ok",
                "OpenSSF": "ok",
                "GHSA": "pending",
            }
        }

    monkeypatch.setattr(http_smoke, "smoke_url", fake_smoke_url)
    monkeypatch.setattr(http_smoke, "fetch_json", fake_fetch_json)

    payload = http_smoke.run_smoke(
        "http://example.test",
        list(http_smoke.DEFAULT_PATHS),
        1.0,
        expect_advisory_source_statuses={"OSV": "ok", "CISA_KEV": "ok", "OpenSSF": "ok"},
    )

    assert payload["status"] == "ok"
    assert payload["advisory_source_statuses"] == {
        "expected": {"OSV": "ok", "CISA_KEV": "ok", "OpenSSF": "ok"},
        "actual": {"OSV": "ok", "CISA_KEV": "ok", "OpenSSF": "ok"},
        "ok": True,
    }


def test_http_smoke_fails_when_advisory_source_status_differs(monkeypatch):
    import scripts.http_smoke as http_smoke

    def fake_smoke_url(base_url, path, timeout):
        return http_smoke.CheckResult(path=path, url=f"{base_url}{path}", ok=True, status=200, elapsed_ms=1, json_ok=path in http_smoke.JSON_PATHS)

    def fake_fetch_json(base_url, path, timeout):
        assert path == "/api/v1/overview"
        return 200, {"advisory_sync": {"OSV": "ok", "NVD": "pending"}}

    monkeypatch.setattr(http_smoke, "smoke_url", fake_smoke_url)
    monkeypatch.setattr(http_smoke, "fetch_json", fake_fetch_json)

    payload = http_smoke.run_smoke(
        "http://example.test",
        list(http_smoke.DEFAULT_PATHS),
        1.0,
        expect_advisory_source_statuses={"OSV": "ok", "NVD": "ok"},
    )

    assert payload["status"] == "failed"
    assert payload["advisory_source_statuses"] == {
        "expected": {"OSV": "ok", "NVD": "ok"},
        "actual": {"OSV": "ok", "NVD": "pending"},
        "ok": False,
    }


def test_http_smoke_can_expect_cutover_report_status(monkeypatch):
    import scripts.http_smoke as http_smoke

    def fake_smoke_url(base_url, path, timeout):
        return http_smoke.CheckResult(path=path, url=f"{base_url}{path}", ok=True, status=200, elapsed_ms=1, json_ok=path in http_smoke.JSON_PATHS)

    def fake_fetch_json(base_url, path, timeout):
        assert path == "/api/v1/operations/cutover-readiness-report"
        return 200, {
            "artifact": {"status": "available", "path": "configured"},
            "report": {"status": "ok", "summary": {"ok": 2, "blockers": 0}},
        }

    monkeypatch.setattr(http_smoke, "smoke_url", fake_smoke_url)
    monkeypatch.setattr(http_smoke, "fetch_json", fake_fetch_json)

    payload = http_smoke.run_smoke(
        "http://example.test",
        list(http_smoke.DEFAULT_PATHS),
        1.0,
        expect_cutover_report_status="ok",
    )
    assert payload["status"] == "ok"
    assert payload["cutover_readiness_report"] == {
        "expected_status": "ok",
        "artifact_status": "available",
        "report_status": "ok",
        "report_expected_status": None,
        "report_expectation_met": None,
        "expected_production_preflight_status": None,
        "production_preflight_status": None,
        "required_expectation_met": False,
        "ok": True,
    }


def test_http_smoke_fails_when_cutover_report_status_differs(monkeypatch):
    import scripts.http_smoke as http_smoke

    def fake_smoke_url(base_url, path, timeout):
        return http_smoke.CheckResult(path=path, url=f"{base_url}{path}", ok=True, status=200, elapsed_ms=1, json_ok=path in http_smoke.JSON_PATHS)

    def fake_fetch_json(base_url, path, timeout):
        assert path == "/api/v1/operations/cutover-readiness-report"
        return 200, {
            "artifact": {"status": "available", "path": "configured"},
            "report": {"status": "blocked", "summary": {"blockers": 1}},
        }

    monkeypatch.setattr(http_smoke, "smoke_url", fake_smoke_url)
    monkeypatch.setattr(http_smoke, "fetch_json", fake_fetch_json)

    payload = http_smoke.run_smoke(
        "http://example.test",
        list(http_smoke.DEFAULT_PATHS),
        1.0,
        expect_cutover_report_status="ok",
    )
    assert payload["status"] == "failed"
    assert payload["cutover_readiness_report"] == {
        "expected_status": "ok",
        "artifact_status": "available",
        "report_status": "blocked",
        "report_expected_status": None,
        "report_expectation_met": None,
        "expected_production_preflight_status": None,
        "production_preflight_status": None,
        "required_expectation_met": False,
        "ok": False,
    }


def test_http_smoke_can_expect_cutover_report_expectation_met(monkeypatch):
    import scripts.http_smoke as http_smoke

    def fake_smoke_url(base_url, path, timeout):
        return http_smoke.CheckResult(path=path, url=f"{base_url}{path}", ok=True, status=200, elapsed_ms=1, json_ok=path in http_smoke.JSON_PATHS)

    def fake_fetch_json(base_url, path, timeout):
        assert path == "/api/v1/operations/cutover-readiness-report"
        return 200, {
            "artifact": {"status": "available", "path": "configured"},
            "report": {
                "status": "blocked",
                "expected_status": "blocked",
                "expectation_met": True,
                "summary": {"blockers": 1},
            },
        }

    monkeypatch.setattr(http_smoke, "smoke_url", fake_smoke_url)
    monkeypatch.setattr(http_smoke, "fetch_json", fake_fetch_json)

    payload = http_smoke.run_smoke(
        "http://example.test",
        list(http_smoke.DEFAULT_PATHS),
        1.0,
        expect_cutover_report_status="blocked",
        expect_cutover_report_expected_status="blocked",
        require_cutover_report_expectation_met=True,
    )

    assert payload["status"] == "ok"
    assert payload["cutover_readiness_report"] == {
        "expected_status": "blocked",
        "artifact_status": "available",
        "report_status": "blocked",
        "report_expected_status": "blocked",
        "report_expectation_met": True,
        "expected_production_preflight_status": None,
        "production_preflight_status": None,
        "required_expectation_met": True,
        "ok": True,
    }


def test_http_smoke_can_expect_cutover_report_production_preflight_status(monkeypatch):
    import scripts.http_smoke as http_smoke

    def fake_smoke_url(base_url, path, timeout):
        return http_smoke.CheckResult(path=path, url=f"{base_url}{path}", ok=True, status=200, elapsed_ms=1, json_ok=path in http_smoke.JSON_PATHS)

    def fake_fetch_json(base_url, path, timeout):
        assert path == "/api/v1/operations/cutover-readiness-report"
        return 200, {
            "artifact": {"status": "available", "path": "configured"},
            "report": {
                "status": "ok",
                "production_preflight": {"status": "ok", "checks": {"migration": {"status": "ok"}}},
            },
        }

    monkeypatch.setattr(http_smoke, "smoke_url", fake_smoke_url)
    monkeypatch.setattr(http_smoke, "fetch_json", fake_fetch_json)

    payload = http_smoke.run_smoke(
        "http://example.test",
        list(http_smoke.DEFAULT_PATHS),
        1.0,
        expect_cutover_report_status="ok",
        expect_cutover_report_production_preflight_status="ok",
    )

    assert payload["status"] == "ok"
    assert payload["cutover_readiness_report"]["production_preflight_status"] == "ok"
    assert payload["cutover_readiness_report"]["expected_production_preflight_status"] == "ok"


def test_http_smoke_fails_when_advisory_sync_not_ready_but_expected():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/v1/overview":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "status": "ok",
                            "advisory_sync_readiness": {
                                "status": "initializing",
                                "required_count": 3,
                                "initialized_count": 1,
                            },
                        }
                    ).encode("utf-8")
                )
                return
            if self.path in {"/health", "/ready"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>SCA Monitor</html>")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/http_smoke.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}",
                "--expect-advisory-sync-ready",
                "true",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "failed"
    assert payload["advisory_sync_readiness"] == {
        "expected_ready": True,
        "overview_status": "initializing",
        "freshness_status": None,
        "initialized_count": 1,
        "required_count": 3,
        "ok": False,
    }


def test_systemd_scheduler_status_fails_when_units_are_missing(tmp_path):
    result = subprocess.run(
        ["python3", "scripts/systemd_scheduler_status.py", "--unit-dir", str(tmp_path), "--json"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "not_ready"
    assert payload["summary"]["missing"] == 24


def test_deploy_systemd_gate_validates_generated_units():
    env = {
        **os.environ,
        "SCA_MONITOR_SYSTEMD_MODE": "validate",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["summary"] == {"expected": 24, "present": 24, "valid": 24, "missing": 0, "invalid": 0}


def test_deploy_systemd_gate_rejects_invalid_mode():
    env = {
        **os.environ,
        "SCA_MONITOR_SYSTEMD_MODE": "sometimes",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "invalid SCA_MONITOR_SYSTEMD_MODE" in result.stderr


def test_deploy_systemd_gate_install_mode_writes_user_units(tmp_path):
    home_dir = tmp_path / "home"
    env = {
        **os.environ,
        "HOME": str(home_dir),
        "SCA_MONITOR_SYSTEMD_MODE": "install",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    unit_dir = home_dir / ".config/systemd/user"
    assert payload["status"] == "ok"
    assert payload["summary"]["valid"] == 24
    assert (unit_dir / "sca-monitor-api.service").exists()
    assert "unit files installed" in result.stdout


def test_deploy_systemd_gate_enable_mode_requires_systemctl(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    env = {
        **os.environ,
        "PATH": str(bin_dir),
        "HOME": str(tmp_path / "home"),
        "SCA_MONITOR_SYSTEMD_MODE": "enable",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["/bin/bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "systemd enable preflight failed: systemctl not found" in result.stderr


def test_deploy_systemd_gate_enable_mode_reports_systemctl_status(tmp_path):
    home_dir = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    log_path = tmp_path / "systemctl.log"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        f"""#!/bin/sh
echo "$@" >> "{log_path}"
case " $* " in
  *" is-enabled "*) echo enabled ;;
  *" is-active "*) echo active ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(home_dir),
        "SCA_MONITOR_SYSTEMD_MODE": "enable",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    api_status = payload["systemctl"]["sca-monitor-api.service"]
    assert payload["status"] == "ok"
    assert payload["summary"]["valid"] == 24
    assert api_status == {"enabled": "enabled", "active": "active"}
    log_text = log_path.read_text(encoding="utf-8")
    assert "--user list-unit-files" in log_text
    assert "sca-monitor-canonical-advisory-merge.timer" in enabled_now_lines(log_text)
    assert "sca-monitor-advisory-freshness.timer" in enabled_now_lines(log_text)
    assert "sca-monitor-nvd-cve-sync.timer" in enabled_now_lines(log_text)
    assert "sca-monitor-canonical-advisory-merge.timer" in restart_lines(log_text)
    assert "sca-monitor-advisory-freshness.timer" in restart_lines(log_text)
    assert "sca-monitor-nvd-cve-sync.timer" in restart_lines(log_text)


def test_deploy_systemd_gate_can_require_active_systemd_units(tmp_path):
    home_dir = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        """#!/bin/sh
case " $* " in
  *" is-enabled "*) echo enabled ;;
  *" is-active "*) echo active ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(home_dir),
        "SCA_MONITOR_SYSTEMD_MODE": "enable",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
        "SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS": "sca-monitor-accepted-risk-expiry.timer,sca-monitor-sla-escalation.timer",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    assert payload["status"] == "ok"
    assert payload["required_active_units"] == [
        {
            "unit": "sca-monitor-accepted-risk-expiry.timer",
            "enabled": "enabled",
            "active": "active",
            "ok": True,
        },
        {
            "unit": "sca-monitor-sla-escalation.timer",
            "enabled": "enabled",
            "active": "active",
            "ok": True,
        },
    ]


def test_deploy_systemd_gate_enable_api_mode_only_enables_api_service(tmp_path):
    home_dir = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    log_path = tmp_path / "systemctl.log"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        f"""#!/bin/sh
echo "$@" >> "{log_path}"
case " $* " in
  *" is-enabled "*) echo enabled ;;
  *" is-active "*) echo active ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(home_dir),
        "SCA_MONITOR_SYSTEMD_MODE": "enable-api",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    log_text = log_path.read_text(encoding="utf-8")
    assert payload["status"] == "ok"
    assert payload["systemctl"]["sca-monitor-api.service"] == {"enabled": "enabled", "active": "active"}
    assert "--user enable --now sca-monitor-api.service" in log_text
    assert "--user restart sca-monitor-api.service" in restart_lines(log_text)
    assert "--user enable --now sca-monitor-endpoint-poller.service" not in log_text
    assert "--user enable --now sca-monitor-alert-dispatcher.service" not in log_text


def test_deploy_systemd_gate_enable_poller_mode_enables_api_and_poller_only(tmp_path):
    home_dir = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    log_path = tmp_path / "systemctl.log"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        f"""#!/bin/sh
echo "$@" >> "{log_path}"
case " $* " in
  *" is-enabled "*) echo enabled ;;
  *" is-active "*) echo active ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(home_dir),
        "SCA_MONITOR_SYSTEMD_MODE": "enable-poller",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    log_text = log_path.read_text(encoding="utf-8")
    assert payload["status"] == "ok"
    assert payload["systemctl"]["sca-monitor-api.service"] == {"enabled": "enabled", "active": "active"}
    assert payload["systemctl"]["sca-monitor-endpoint-poller.service"] == {"enabled": "enabled", "active": "active"}
    assert "--user enable --now sca-monitor-api.service sca-monitor-endpoint-poller.service" in log_text
    assert "--user restart sca-monitor-api.service sca-monitor-endpoint-poller.service" in restart_lines(log_text)
    assert "sca-monitor-alert-dispatcher.service" not in enabled_now_lines(log_text)


def test_deploy_systemd_gate_enable_dispatcher_dry_run_mode_does_not_enable_live_dispatcher(tmp_path):
    home_dir = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    log_path = tmp_path / "systemctl.log"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        f"""#!/bin/sh
echo "$@" >> "{log_path}"
case " $* " in
  *" is-enabled "*) echo enabled ;;
  *" is-active "*) echo active ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(home_dir),
        "SCA_MONITOR_SYSTEMD_MODE": "enable-dispatcher-dry-run",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    log_text = log_path.read_text(encoding="utf-8")
    assert payload["status"] == "ok"
    assert payload["systemctl"]["sca-monitor-alert-dispatcher-dry-run.service"] == {"enabled": "enabled", "active": "active"}
    assert "sca-monitor-alert-dispatcher-dry-run.service" in enabled_now_lines(log_text)
    assert "sca-monitor-alert-dispatcher.service" not in enabled_now_lines(log_text)
    assert "sca-monitor-advisory-freshness.timer" not in enabled_now_lines(log_text)
    assert "sca-monitor-nvd-cve-sync.timer" not in enabled_now_lines(log_text)
    assert "sca-monitor-api.service" in restart_lines(log_text)
    assert "sca-monitor-endpoint-poller.service" in restart_lines(log_text)
    assert "sca-monitor-alert-dispatcher-dry-run.service" in restart_lines(log_text)
    assert "sca-monitor-alert-dispatcher.service" not in restart_lines(log_text)
    assert "sca-monitor-advisory-freshness.timer" not in restart_lines(log_text)
    assert "sca-monitor-nvd-cve-sync.timer" not in restart_lines(log_text)


def test_deploy_systemd_gate_enable_advisory_sync_dry_run_mode_keeps_live_dispatcher_disabled(tmp_path):
    home_dir = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    log_path = tmp_path / "systemctl.log"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        f"""#!/bin/sh
echo "$@" >> "{log_path}"
case " $* " in
  *" is-enabled "*) echo enabled ;;
  *" is-active "*) echo active ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(home_dir),
        "SCA_MONITOR_SYSTEMD_MODE": "enable-advisory-sync-dry-run",
        "SCA_MONITOR_SYSTEMD_REPO_DIR": str(REPO_ROOT),
        "SCA_MONITOR_SYSTEMD_PYTHON": "/usr/bin/python3",
    }

    result = subprocess.run(
        ["bash", "scripts/deploy_systemd_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    log_text = log_path.read_text(encoding="utf-8")
    enabled_lines = enabled_now_lines(log_text)
    restarted_lines = restart_lines(log_text)
    stopped_lines = stop_lines(log_text)
    assert payload["status"] == "ok"
    assert payload["systemctl"]["sca-monitor-alert-dispatcher-dry-run.service"] == {
        "enabled": "enabled",
        "active": "active",
    }
    assert "sca-monitor-alert-dispatcher-dry-run.service" in enabled_lines
    assert "sca-monitor-alert-dispatcher.service" not in enabled_lines
    assert "sca-monitor-advisory-freshness.timer" in enabled_lines
    assert "sca-monitor-osv-npm-sync.timer" in enabled_lines
    assert "sca-monitor-cisa-kev-sync.timer" in enabled_lines
    assert "sca-monitor-openssf-malicious-sync.timer" in enabled_lines
    assert "sca-monitor-canonical-advisory-merge.timer" in enabled_lines
    assert "sca-monitor-api.service" in restarted_lines
    assert "sca-monitor-endpoint-poller.service" in restarted_lines
    assert "sca-monitor-alert-dispatcher-dry-run.service" in restarted_lines
    assert "sca-monitor-alert-dispatcher.service" not in restarted_lines
    assert "sca-monitor-advisory-freshness.timer" in restarted_lines
    assert "sca-monitor-osv-npm-sync.timer" in restarted_lines
    assert "sca-monitor-osv-npm-sync.service" in stopped_lines
    assert "sca-monitor-openssf-malicious-sync.service" in stopped_lines
    assert "sca-monitor-cisa-kev-sync.service" in stopped_lines
    assert "sca-monitor-ghsa-sync.service" in stopped_lines
    assert "sca-monitor-nvd-cve-sync.service" in stopped_lines
    assert "sca-monitor-advisory-freshness.service" in stopped_lines
    assert "sca-monitor-canonical-advisory-merge.service" in stopped_lines
    assert "reset-failed sca-monitor-advisory-freshness.service sca-monitor-cisa-kev-sync.service sca-monitor-ghsa-sync.service sca-monitor-nvd-cve-sync.service sca-monitor-osv-npm-sync.service sca-monitor-openssf-malicious-sync.service sca-monitor-canonical-advisory-merge.service" in log_text


def test_db_smoke_cli_checks_sqlite_without_persisting_write(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}"
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": database_url,
    }
    subprocess.run(
        ["python3", "scripts/migrate.py"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        ["python3", "scripts/db_smoke.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["database_backend"] == "sqlite"
    assert payload["checks"]["services_readable"] is True
    assert payload["checks"]["advisory_sync_state_readable"] is True
    assert payload["checks"]["alert_events_readable"] is True
    assert payload["checks"]["audit_log_write_rollback"] is True
    assert payload["checks"]["audit_log_rollback_clean"] is True
    database = Database(database_url)
    with database.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM audit_logs WHERE action = 'db.smoke.write'").fetchone()["c"] == 0


def test_backup_database_cli_copies_sqlite_without_leaking_paths(tmp_path):
    database_path = tmp_path / "sca-monitor.sqlite3"
    database_url = f"sqlite:///{database_path}"
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": database_url,
    }
    subprocess.run(
        ["python3", "scripts/migrate.py"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        ["python3", "scripts/backup_database.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    backup_path = Path(payload["backup_path"])
    assert payload["status"] == "ok"
    assert payload["database_backend"] == "sqlite"
    assert payload["database_url_source"] == "SCA_MONITOR_DATABASE_URL"
    assert payload["backup_path"].startswith(str(tmp_path / "backups"))
    assert backup_path.exists()
    assert backup_path.stat().st_size == database_path.stat().st_size
    assert "sqlite:///" not in result.stdout


def test_verify_backup_restore_cli_checks_sqlite_backup_copy_without_mutating_backup(tmp_path):
    database_path = tmp_path / "sca-monitor.sqlite3"
    database_url = f"sqlite:///{database_path}"
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": database_url,
    }
    subprocess.run(
        ["python3", "scripts/migrate.py"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    backup_result = subprocess.run(
        ["python3", "scripts/backup_database.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    backup_path = Path(json.loads(backup_result.stdout)["backup_path"])
    backup_mtime_ns = backup_path.stat().st_mtime_ns
    backup_size = backup_path.stat().st_size

    result = subprocess.run(
        ["python3", "scripts/verify_backup_restore.py", "--backup-path", str(backup_path), "--json"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["database_backend"] == "sqlite"
    assert payload["backup_path"] == "configured"
    assert payload["restore_copy_path"] == "temporary"
    assert payload["smoke"]["status"] == "ok"
    assert payload["smoke"]["checks"]["services_readable"] is True
    assert "audit_log_write_rollback" not in payload["smoke"]["checks"]
    assert backup_path.stat().st_size == backup_size
    assert backup_path.stat().st_mtime_ns == backup_mtime_ns
    assert str(backup_path) not in result.stdout
    assert "sqlite:///" not in result.stdout


def test_deploy_db_gate_runs_sqlite_smoke(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}"
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": database_url,
    }
    subprocess.run(
        ["python3", "scripts/migrate.py"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        ["bash", "scripts/deploy_db_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "db smoke ok: backend=sqlite" in result.stdout


def test_deploy_db_gate_checks_worker_database_url_when_split(tmp_path):
    api_database_url = f"sqlite:///{tmp_path / 'sca-api.sqlite3'}"
    worker_database_url = f"sqlite:///{tmp_path / 'sca-worker.sqlite3'}"
    base_env = {**os.environ, "SCA_MONITOR_DATA_DIR": str(tmp_path)}
    for database_url in (api_database_url, worker_database_url):
        subprocess.run(
            ["python3", "scripts/migrate.py"],
            cwd=REPO_ROOT,
            env={**base_env, "SCA_MONITOR_DATABASE_URL": database_url},
            check=True,
            capture_output=True,
            text=True,
        )

    result = subprocess.run(
        ["bash", "scripts/deploy_db_gate.sh"],
        cwd=REPO_ROOT,
        env={
            **base_env,
            "API_DATABASE_URL": api_database_url,
            "WORKER_DATABASE_URL": worker_database_url,
        },
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.count("db smoke ok: backend=sqlite") == 2


def test_deploy_db_gate_rejects_invalid_postgres_smoke_mode(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}"
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": database_url,
        "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE": "sometimes",
    }
    subprocess.run(
        ["python3", "scripts/migrate.py"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        ["bash", "scripts/deploy_db_gate.sh"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "invalid SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE" in result.stderr


def test_postgres_cutover_readiness_allows_sqlite_fallback(tmp_path):
    result = subprocess.run(
        ["python3", "scripts/postgres_cutover_readiness.py", "--json"],
        cwd=REPO_ROOT,
        env={
            "PATH": os.environ["PATH"],
            "SCA_MONITOR_DATA_DIR": str(tmp_path),
        },
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "sqlite_fallback"
    assert payload["mode"] == "sqlite_fallback"
    assert any(check["id"] == "database_url_mode" for check in payload["checks"])


def test_postgres_cutover_readiness_requires_postgres_url(tmp_path):
    result = subprocess.run(
        ["python3", "scripts/postgres_cutover_readiness.py", "--require-postgres", "--json"],
        cwd=REPO_ROOT,
        env={
            "PATH": os.environ["PATH"],
            "SCA_MONITOR_DATA_DIR": str(tmp_path),
        },
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert any(check["id"] == "database_url_mode" and check["status"] == "blocker" for check in payload["checks"])


def test_postgres_cutover_readiness_accepts_split_postgres_urls(tmp_path):
    result = subprocess.run(
        ["python3", "scripts/postgres_cutover_readiness.py", "--require-postgres", "--require-split", "--json"],
        cwd=REPO_ROOT,
        env={
            "PATH": os.environ["PATH"],
            "SCA_MONITOR_DATA_DIR": str(tmp_path),
            "MIGRATION_DATABASE_URL": "postgresql://migrator:secret@db/sca",
            "API_DATABASE_URL": "postgresql://api:secret@db/sca",
            "WORKER_DATABASE_URL": "postgresql://worker:secret@db/sca",
            "SCA_MONITOR_AUTO_MIGRATE": "false",
            "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE": "required",
        },
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ready"
    assert payload["mode"] == "split"
    assert payload["postgres_configured"] is True


def test_deployment_input_readiness_allows_sqlite_fallback_env_file(tmp_path):
    env_file = tmp_path / "sca.env"
    env_file.write_text(
        "\n".join(
            [
                "APP_ENV=prod",
                "SCA_MONITOR_PORT=18780",
                "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net",
                "SCA_MONITOR_DATABASE_URL=sqlite:////tmp/sca-monitor.sqlite3",
                "SCA_MONITOR_SYSTEMD_MODE=enable-dispatcher-dry-run",
                "SMOKE_TEST_TOKEN=dev-smoke-token",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["python3", "scripts/deployment_input_readiness.py", "--env-file", str(env_file), "--json"],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["postgres"]["status"] == "sqlite_fallback"
    assert any(check["id"] == "public_url" and check["status"] == "ok" for check in payload["checks"])
    assert any(check["id"] == "postgres_cutover" and check["status"] == "ok" for check in payload["checks"])
    assert "sqlite:////tmp" not in result.stdout


def test_deployment_input_readiness_allows_advisory_sync_dry_run_mode(tmp_path):
    env_file = tmp_path / "sca.env"
    env_file.write_text(
        "\n".join(
            [
                "APP_ENV=prod",
                "SCA_MONITOR_PORT=18780",
                "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net",
                "SCA_MONITOR_DATABASE_URL=sqlite:////tmp/sca-monitor.sqlite3",
                "SCA_MONITOR_SYSTEMD_MODE=enable-advisory-sync-dry-run",
                "SMOKE_TEST_TOKEN=dev-smoke-token",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["python3", "scripts/deployment_input_readiness.py", "--env-file", str(env_file), "--json"],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    systemd_check = next(check for check in payload["checks"] if check["id"] == "systemd_mode")
    assert payload["status"] == "ok"
    assert systemd_check == {
        "id": "systemd_mode",
        "status": "ok",
        "detail": "SCA_MONITOR_SYSTEMD_MODE=enable-advisory-sync-dry-run",
    }


def test_deployment_input_readiness_requires_split_postgres_inputs(tmp_path):
    env_file = tmp_path / "sca.env"
    env_file.write_text(
        "\n".join(
            [
                "APP_ENV=prod",
                "SCA_MONITOR_PORT=18780",
                "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net",
                "SCA_MONITOR_DATABASE_URL=sqlite:////tmp/sca-monitor.sqlite3",
                "SCA_MONITOR_SYSTEMD_MODE=enable-dispatcher-dry-run",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/deployment_input_readiness.py",
            "--env-file",
            str(env_file),
            "--require-postgres",
            "--require-split",
            "--json",
        ],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert payload["postgres"]["status"] == "blocked"
    assert any(check["id"] == "postgres_cutover" and check["status"] == "blocker" for check in payload["checks"])
    assert "sqlite:////tmp" not in result.stdout


def test_deployment_input_readiness_requires_runtime_inputs(tmp_path):
    env_file = tmp_path / "sca.env"
    env_file.write_text(
        "\n".join(
            [
                "APP_ENV=prod",
                "SCA_MONITOR_PORT=18780",
                "SCA_MONITOR_DATABASE_URL=sqlite:////tmp/sca-monitor.sqlite3",
                "SCA_MONITOR_SYSTEMD_MODE=enable-dispatcher-dry-run",
                "SMOKE_TEST_TOKEN=change-me",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/deployment_input_readiness.py",
            "--env-file",
            str(env_file),
            "--require-runtime-inputs",
            "--json",
        ],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert any(check["id"] == "public_url" and check["status"] == "blocker" for check in payload["checks"])
    assert any(check["id"] == "smoke_token" and check["status"] == "blocker" for check in payload["checks"])
    assert "sqlite:////tmp" not in result.stdout


def test_deployment_input_readiness_env_overrides_env_file(tmp_path):
    env_file = tmp_path / "sca.env"
    env_file.write_text(
        "\n".join(
            [
                "SCA_MONITOR_PORT=18780",
                "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net",
                "SCA_MONITOR_SYSTEMD_MODE=validate",
                "SMOKE_TEST_TOKEN=dev-smoke-token",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["python3", "scripts/deployment_input_readiness.py", "--env-file", str(env_file), "--json"],
        cwd=REPO_ROOT,
        env={
            "PATH": os.environ["PATH"],
            "SCA_MONITOR_SYSTEMD_MODE": "enable-dispatcher-dry-run",
        },
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    systemd_check = next(check for check in payload["checks"] if check["id"] == "systemd_mode")
    assert systemd_check["detail"] == "SCA_MONITOR_SYSTEMD_MODE=enable-dispatcher-dry-run"


def test_configure_runtime_inputs_updates_public_url_and_generates_smoke_token(tmp_path):
    env_file = tmp_path / "sca.env"
    env_file.write_text(
        "\n".join(
            [
                "APP_ENV=prod",
                "SCA_MONITOR_PORT=18780",
                "SMOKE_TEST_TOKEN=change-me",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/configure_runtime_inputs.py",
            "--env-file",
            str(env_file),
            "--public-url",
            "https://monitoring.fin-ally.net",
            "--generate-smoke-token",
            "--json",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    env_text = env_file.read_text(encoding="utf-8")
    token_line = next(line for line in env_text.splitlines() if line.startswith("SMOKE_TEST_TOKEN="))
    token = token_line.split("=", 1)[1]
    assert payload["status"] == "ok"
    assert payload["updated"] == ["SCA_MONITOR_PUBLIC_URL", "SMOKE_TEST_TOKEN"]
    assert "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net" in env_text
    assert token != "change-me"
    assert len(token) >= 32
    assert token not in result.stdout


def test_configure_runtime_inputs_merges_database_env_file_without_leaking_urls(tmp_path):
    env_file = tmp_path / "sca.env"
    database_env_file = tmp_path / "database.env"
    env_file.write_text("APP_ENV=prod\nSCA_MONITOR_PORT=18780\n", encoding="utf-8")
    database_env_file.write_text(
        "\n".join(
            [
                "MIGRATION_DATABASE_URL=postgresql://migration:secret@db.internal:5432/sca",
                "API_DATABASE_URL=postgresql://api:secret@db.internal:5432/sca",
                "WORKER_DATABASE_URL=postgresql://worker:secret@db.internal:5432/sca",
                "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=required",
                "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true",
                "SCA_MONITOR_API_AUTO_MIGRATE=false",
                "IGNORED_DATABASE_PASSWORD=do-not-copy",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/configure_runtime_inputs.py",
            "--env-file",
            str(env_file),
            "--database-env-file",
            str(database_env_file),
            "--json",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    env_text = env_file.read_text(encoding="utf-8")
    assert payload["status"] == "ok"
    assert payload["updated"] == [
        "MIGRATION_DATABASE_URL",
        "API_DATABASE_URL",
        "WORKER_DATABASE_URL",
        "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE",
        "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT",
        "SCA_MONITOR_API_AUTO_MIGRATE",
    ]
    assert "postgresql://migration:secret@db.internal:5432/sca" in env_text
    assert "IGNORED_DATABASE_PASSWORD" not in env_text
    assert "postgresql://migration:secret" not in result.stdout
    assert "postgresql://api:secret" not in result.stdout
    assert "postgresql://worker:secret" not in result.stdout


def test_validate_database_env_file_accepts_split_postgres_without_leaking_urls(tmp_path):
    database_env_file = tmp_path / "postgres.env"
    database_env_file.write_text(
        "\n".join(
            [
                "MIGRATION_DATABASE_URL=postgresql://migration:secret@db.internal:5432/sca",
                "API_DATABASE_URL=postgresql://api:secret@db.internal:5432/sca",
                "WORKER_DATABASE_URL=postgresql://worker:secret@db.internal:5432/sca",
                "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=required",
                "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true",
                "SCA_MONITOR_API_AUTO_MIGRATE=false",
                "SCA_MONITOR_WORKER_AUTO_MIGRATE=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    database_env_file.chmod(0o600)

    result = subprocess.run(
        ["python3", "scripts/validate_database_env_file.py", "--database-env-file", str(database_env_file), "--json"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["cutover"]["status"] == "ready"
    assert payload["summary"]["allowed_keys"] == 7
    assert "postgresql://migration:secret" not in result.stdout
    assert "postgresql://api:secret" not in result.stdout
    assert "postgresql://worker:secret" not in result.stdout


def test_validate_database_env_file_rejects_group_readable_secret_file_without_leaking_urls(tmp_path):
    database_env_file = tmp_path / "postgres.env"
    database_env_file.write_text(
        "\n".join(
            [
                "MIGRATION_DATABASE_URL=postgresql://migration:secret@db.internal:5432/sca",
                "API_DATABASE_URL=postgresql://api:secret@db.internal:5432/sca",
                "WORKER_DATABASE_URL=postgresql://worker:secret@db.internal:5432/sca",
                "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=required",
                "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true",
                "SCA_MONITOR_API_AUTO_MIGRATE=false",
                "SCA_MONITOR_WORKER_AUTO_MIGRATE=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    database_env_file.chmod(0o640)

    result = subprocess.run(
        ["python3", "scripts/validate_database_env_file.py", "--database-env-file", str(database_env_file), "--json"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert any(check["id"] == "file_permissions" and check["status"] == "blocker" for check in payload["checks"])
    assert "postgresql://migration:secret" not in result.stdout
    assert "postgresql://api:secret" not in result.stdout
    assert "postgresql://worker:secret" not in result.stdout


def test_cutover_readiness_report_combines_inputs_without_leaking_secrets(tmp_path):
    env_file = tmp_path / "runtime.env"
    database_env_file = tmp_path / "postgres.env"
    database_path = tmp_path / "sca-monitor.sqlite3"
    sqlite_env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": f"sqlite:///{database_path}",
    }
    env_file.write_text(
        "\n".join(
            [
                "APP_ENV=prod",
                "SCA_MONITOR_PORT=18780",
                "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net",
                "SCA_MONITOR_SYSTEMD_MODE=enable-dispatcher-dry-run",
                "SMOKE_TEST_TOKEN=stage-smoke-token",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    database_env_file.write_text(
        "\n".join(
            [
                "MIGRATION_DATABASE_URL=postgresql://migration:secret@db.internal:5432/sca",
                "API_DATABASE_URL=postgresql://api:secret@db.internal:5432/sca",
                "WORKER_DATABASE_URL=postgresql://worker:secret@db.internal:5432/sca",
                "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=required",
                "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true",
                "SCA_MONITOR_API_AUTO_MIGRATE=false",
                "SCA_MONITOR_WORKER_AUTO_MIGRATE=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    database_env_file.chmod(0o600)
    subprocess.run(
        ["python3", "scripts/migrate.py"],
        cwd=REPO_ROOT,
        env=sqlite_env,
        check=True,
        capture_output=True,
        text=True,
    )
    backup_result = subprocess.run(
        ["python3", "scripts/backup_database.py", "--json"],
        cwd=REPO_ROOT,
        env=sqlite_env,
        check=True,
        capture_output=True,
        text=True,
    )
    backup_path = Path(json.loads(backup_result.stdout)["backup_path"])

    result = subprocess.run(
        [
            "python3",
            "scripts/cutover_readiness_report.py",
            "--env-file",
            str(env_file),
            "--database-env-file",
            str(database_env_file),
            "--backup-path",
            str(backup_path),
            "--require-postgres",
            "--require-split",
            "--require-runtime-inputs",
            "--json",
        ],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["deployment_inputs"]["status"] == "ok"
    assert payload["database_env"]["status"] == "ok"
    assert payload["backup_restore"]["status"] == "ok"
    assert payload["production_preflight"]["status"] == "skipped"
    assert payload["summary"]["blockers"] == 0
    assert payload["summary"]["ok"] >= 3
    assert "postgresql://migration:secret" not in result.stdout
    assert "postgresql://api:secret" not in result.stdout
    assert "postgresql://worker:secret" not in result.stdout
    assert str(backup_path) not in result.stdout
    assert "sqlite:///" not in result.stdout

    output_path = tmp_path / "cutover-report.json"
    output_result = subprocess.run(
        [
            "python3",
            "scripts/cutover_readiness_report.py",
            "--env-file",
            str(env_file),
            "--database-env-file",
            str(database_env_file),
            "--backup-path",
            str(backup_path),
            "--require-postgres",
            "--require-split",
            "--require-runtime-inputs",
            "--json",
            "--output",
            str(output_path),
        ],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        check=True,
        capture_output=True,
        text=True,
    )

    written_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert written_payload == json.loads(output_result.stdout)
    assert output_path.stat().st_mode & 0o777 == 0o600
    assert "postgresql://migration:secret" not in output_path.read_text(encoding="utf-8")
    assert str(backup_path) not in output_path.read_text(encoding="utf-8")


def test_cutover_readiness_report_can_expect_blocked_and_write_sanitized_artifact(tmp_path):
    env_file = tmp_path / "runtime.env"
    database_env_file = tmp_path / "postgres.env"
    output_path = tmp_path / "blocked-cutover-report.json"
    env_file.write_text(
        "\n".join(
            [
                "APP_ENV=prod",
                "SCA_MONITOR_PORT=18780",
                "SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net",
                "SCA_MONITOR_SYSTEMD_MODE=enable-dispatcher-dry-run",
                "SMOKE_TEST_TOKEN=stage-smoke-token",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    database_env_file.write_text(
        "\n".join(
            [
                "MIGRATION_DATABASE_URL=postgresql://<migration_user>:<password>@<host>:5432/<database>",
                "API_DATABASE_URL=postgresql://<api_user>:<password>@<host>:5432/<database>",
                "WORKER_DATABASE_URL=postgresql://<worker_user>:<password>@<host>:5432/<database>",
                "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=required",
                "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true",
                "SCA_MONITOR_AUTO_MIGRATE=false",
                "SCA_MONITOR_API_AUTO_MIGRATE=false",
                "SCA_MONITOR_WORKER_AUTO_MIGRATE=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    database_env_file.chmod(0o600)

    result = subprocess.run(
        [
            "python3",
            "scripts/cutover_readiness_report.py",
            "--env-file",
            str(env_file),
            "--database-env-file",
            str(database_env_file),
            "--require-postgres",
            "--require-split",
            "--require-runtime-inputs",
            "--expect-status",
            "blocked",
            "--output",
            str(output_path),
            "--json",
        ],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    written_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "blocked"
    assert payload["expected_status"] == "blocked"
    assert payload["expectation_met"] is True
    assert written_payload == payload
    assert output_path.stat().st_mode & 0o777 == 0o600
    assert "postgresql://<migration_user>" not in result.stdout
    assert "<password>" not in result.stdout
    assert "postgresql://<migration_user>" not in output_path.read_text(encoding="utf-8")
    assert "<password>" not in output_path.read_text(encoding="utf-8")


def test_prepare_database_env_file_creates_protected_placeholder_without_overwrite(tmp_path):
    target = tmp_path / ".secrets" / "postgres.env"

    result = subprocess.run(
        [
            "python3",
            "scripts/prepare_database_env_file.py",
            "--database-env-file",
            str(target),
            "--json",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    text = target.read_text(encoding="utf-8")
    assert payload["status"] == "created"
    assert payload["database_env_file"] == "configured"
    assert payload["mode"] == "0o600"
    assert payload["validator"]["status"] == "blocked"
    assert target.stat().st_mode & 0o777 == 0o600
    assert "MIGRATION_DATABASE_URL=postgresql://<migration_user>:<password>@<host>:5432/<database>" in text
    assert "postgresql://<migration_user>" not in result.stdout
    assert "<password>" not in result.stdout

    second = subprocess.run(
        [
            "python3",
            "scripts/prepare_database_env_file.py",
            "--database-env-file",
            str(target),
            "--json",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    second_payload = json.loads(second.stdout)
    assert second.returncode == 2
    assert second_payload["status"] == "blocked"
    assert any(check["id"] == "existing_file" and check["status"] == "blocker" for check in second_payload["checks"])


def test_postgres_env_example_is_placeholder_and_blocked_by_validator():
    example = (REPO_ROOT / "deploy" / "postgres.env.example").read_text(encoding="utf-8")
    assert "MIGRATION_DATABASE_URL=postgresql://<migration_user>:<password>@<host>:5432/<database>" in example
    assert "API_DATABASE_URL=postgresql://<api_user>:<password>@<host>:5432/<database>" in example
    assert "WORKER_DATABASE_URL=postgresql://<worker_user>:<password>@<host>:5432/<database>" in example
    assert "SCA_MONITOR_AUTO_MIGRATE=false" in example

    result = subprocess.run(
        [
            "python3",
            "scripts/validate_database_env_file.py",
            "--database-env-file",
            "deploy/postgres.env.example",
            "--json",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert any(check["id"] == "placeholder_values" and check["status"] == "blocker" for check in payload["checks"])
    assert "postgresql://<migration_user>" not in result.stdout


def test_database_env_dry_run_gate_accepts_synthetic_split_without_leaking_urls():
    result = subprocess.run(
        ["python3", "scripts/database_env_dry_run_gate.py", "--json"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mode"] == "synthetic_split"
    assert payload["validator"]["status"] == "ok"
    assert payload["configure"]["status"] == "ok"
    assert payload["deployment_readiness"]["status"] == "ok"
    assert "MIGRATION_DATABASE_URL" in payload["configure"]["updated"]
    assert "postgresql://migration:synthetic" not in result.stdout
    assert "postgresql://api:synthetic" not in result.stdout
    assert "postgresql://worker:synthetic" not in result.stdout
    assert "synthetic-secret" not in result.stdout


def test_database_env_dry_run_gate_rejects_placeholder_template_without_leaking_urls():
    result = subprocess.run(
        [
            "python3",
            "scripts/database_env_dry_run_gate.py",
            "--database-env-file",
            "deploy/postgres.env.example",
            "--json",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert payload["mode"] == "provided_file"
    assert payload["validator"]["status"] == "blocked"
    assert any(check["id"] == "placeholder_values" and check["status"] == "blocker" for check in payload["validator"]["checks"])
    assert "postgresql://<migration_user>" not in result.stdout
    assert "<password>" not in result.stdout


def test_database_env_dry_run_gate_allows_expected_blocked_placeholder_without_leaking_urls():
    result = subprocess.run(
        [
            "python3",
            "scripts/database_env_dry_run_gate.py",
            "--database-env-file",
            "deploy/postgres.env.example",
            "--expect-status",
            "blocked",
            "--json",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["expected_status"] == "blocked"
    assert payload["expectation_met"] is True
    assert payload["validator"]["status"] == "blocked"
    assert any(check["id"] == "placeholder_values" and check["status"] == "blocker" for check in payload["validator"]["checks"])
    assert "postgresql://<migration_user>" not in result.stdout
    assert "<password>" not in result.stdout


def test_advisory_source_preflight_lists_required_outbound_domains():
    result = subprocess.run(
        ["python3", "scripts/advisory_source_preflight.py", "--list-only", "--json"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    sources = {source["id"]: source for source in payload["sources"]}
    assert payload["status"] == "configured"
    assert sources["OSV_API"]["host"] == "api.osv.dev"
    assert sources["OSV_DUMP"]["host"] == "osv-vulnerabilities.storage.googleapis.com"
    assert sources["CISA_KEV"]["host"] == "www.cisa.gov"
    assert sources["GHSA"]["host"] == "api.github.com"
    assert sources["NVD"]["host"] == "services.nvd.nist.gov"
    assert sources["OpenSSF"]["host"] == "github.com"
    assert all(source["port"] == 443 for source in sources.values())
    assert all(source["required_by"] for source in sources.values())


def test_advisory_source_preflight_checks_local_sources_without_secret_output(tmp_path):
    seen_paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen_paths.append(self.path)
            if self.path.startswith("/ok"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
                return
            self.send_response(503)
            self.end_headers()

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source_spec = tmp_path / "sources.json"
    source_spec.write_text(
        json.dumps(
            [
                {
                    "id": "TEST_OK",
                    "url": f"http://127.0.0.1:{server.server_port}/ok?token=super-secret",
                    "required_by": ["FR-009"],
                    "required": True,
                },
                {
                    "id": "TEST_FAIL",
                    "url": f"http://127.0.0.1:{server.server_port}/fail?token=super-secret",
                    "required_by": ["FR-010"],
                    "required": True,
                },
            ]
        ),
        encoding="utf-8",
    )

    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/advisory_source_preflight.py",
                "--source-spec",
                str(source_spec),
                "--check",
                "--timeout",
                "2",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    payload = json.loads(result.stdout)
    checks = {check["id"]: check for check in payload["checks"]}
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert checks["TEST_OK"]["status"] == "ok"
    assert checks["TEST_FAIL"]["status"] == "blocker"
    assert checks["TEST_OK"]["url"] == f"http://127.0.0.1:{server.server_port}/ok"
    assert "super-secret" not in result.stdout
    assert seen_paths == ["/ok?token=super-secret", "/fail?token=super-secret"]


def test_postgres_preflight_summary_reports_blockers_and_split_ready():
    sqlite_cutover = assess_cutover({})
    sqlite_required = assess_cutover({}, require_postgres=True)

    sqlite_summary = summarize_preflight(sqlite_cutover, sqlite_required)

    assert sqlite_summary["status"] == "blocked"
    assert sqlite_summary["current_mode"] == "sqlite_fallback"
    assert sqlite_summary["blockers"] == 1
    assert sqlite_summary["warnings"] == 0
    assert sqlite_summary["ok"] == 1
    assert sqlite_summary["split_ready"] is False
    assert sqlite_summary["next_action"] == "no PostgreSQL database URL configured"

    split_env = {
        "MIGRATION_DATABASE_URL": "postgresql://migrator:secret@db/sca",
        "API_DATABASE_URL": "postgresql://api:secret@db/sca",
        "WORKER_DATABASE_URL": "postgresql://worker:secret@db/sca",
        "SCA_MONITOR_AUTO_MIGRATE": "false",
        "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE": "required",
    }
    split_cutover = assess_cutover(split_env)
    split_required = assess_cutover(split_env, require_postgres=True, require_split=True)

    split_summary = summarize_preflight(split_cutover, split_required)

    assert split_summary["status"] == "ready"
    assert split_summary["required_mode"] == "split"
    assert split_summary["postgres_configured"] is True
    assert split_summary["split_ready"] is True
    assert split_summary["blockers"] == 0
    assert split_summary["warnings"] == 0
    assert split_summary["next_action"] == "ready for split credential PostgreSQL cutover"


def test_database_readiness_endpoint_exposes_migration_and_cutover(tmp_path):
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/operations/database-readiness")

    assert payload["status"] == "ready"
    assert payload["database"] == "ok"
    assert payload["database_backend"] == "sqlite"
    assert payload["database_url_source"] == "default_sqlite"
    assert payload["migration"]["compatible"] is True
    assert payload["cutover"]["status"] == "sqlite_fallback"
    assert payload["cutover_required"]["status"] == "blocked"
    assert payload["postgres_preflight"]["blockers"] == 1
    assert payload["postgres_preflight"]["next_action"] == "no PostgreSQL database URL configured"
    assert any(check["id"] == "database_url_mode" for check in payload["cutover_required"]["checks"])


def test_cutover_readiness_report_endpoint_exposes_sanitized_artifact(monkeypatch, tmp_path):
    report_path = tmp_path / "cutover-readiness-report.json"
    report_path.write_text(
        json.dumps(
            {
                "status": "action_required",
                "summary": {"ok": 2, "action_required": 1, "skipped": 1, "blockers": 0},
                "inputs": {"env_file": "configured", "database_env_file": "not_configured"},
                "deployment_inputs": {"status": "action_required"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SCA_MONITOR_CUTOVER_READINESS_REPORT_PATH", str(report_path))
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/operations/cutover-readiness-report")

    assert payload["artifact"] == {"status": "available", "path": "configured"}
    assert payload["report"]["status"] == "action_required"
    assert payload["report"]["summary"]["action_required"] == 1
    assert str(tmp_path) not in json.dumps(payload)


def test_cutover_readiness_report_endpoint_handles_missing_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_CUTOVER_READINESS_REPORT_PATH", str(tmp_path / "missing.json"))
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/operations/cutover-readiness-report")

    assert payload == {
        "artifact": {"status": "not_configured", "path": "not_configured"},
        "report": None,
    }


def test_ready_endpoint_exposes_postgres_cutover_summary(tmp_path):
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/ready")

    assert payload["status"] == "ready"
    assert payload["database"] == "ok"
    assert payload["database_backend"] == "sqlite"
    assert payload["database_url_source"] == "default_sqlite"
    assert payload["migration"]["compatible"] is True
    assert payload["cutover"]["status"] == "sqlite_fallback"
    assert payload["cutover_required"]["status"] == "blocked"
    assert payload["postgres_preflight"]["blockers"] == 1
    assert payload["postgres_preflight"]["next_action"] == "no PostgreSQL database URL configured"


def test_ready_endpoint_exposes_advisory_sync_readiness_without_blocking_db_readiness(tmp_path):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "error", "catalog:test", "upstream unavailable", imported_count=0)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/ready")

    assert payload["status"] == "ready"
    assert payload["database"] == "ok"
    readiness = payload["advisory_sync_readiness"]
    assert readiness["status"] == "degraded"
    assert readiness["required_count"] == 3
    assert readiness["initialized_count"] == 1
    assert readiness["freshness"]["failed_count"] == 1
    sources = {item["source"]: item for item in readiness["sources"]}
    assert sources["OSV"]["initialized"] is True
    assert sources["CISA_KEV"]["freshness_status"] == "failed"


def test_ready_endpoint_reflects_required_split_cutover(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_POSTGRES_REQUIRE_SPLIT", "true")
    monkeypatch.setenv("SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE", "required")
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/ready")

    assert payload["status"] == "ready"
    assert payload["cutover_required"]["require_postgres"] is True
    assert payload["cutover_required"]["require_split"] is True
    assert payload["postgres_preflight"]["status"] == "blocked"
    assert payload["postgres_preflight"]["split_ready"] is False


def test_ready_endpoint_exposes_role_database_url_sources_without_secrets(monkeypatch, tmp_path):
    monkeypatch.delenv("SCA_MONITOR_DATABASE_URL", raising=False)
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "postgresql://migration:secret@db.example.com/sca")
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://api:secret@db.example.com/sca")
    monkeypatch.setenv("WORKER_DATABASE_URL", "postgresql://worker:secret@db.example.com/sca")
    app = make_test_app(tmp_path, database_url_source="API_DATABASE_URL")

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/ready")

    assert payload["runtime_database_urls"] == {
        "api": {"source": "API_DATABASE_URL", "backend": "sqlite", "configured": True},
        "worker": {"source": "WORKER_DATABASE_URL", "backend": "postgres", "configured": True},
        "migration": {"source": "MIGRATION_DATABASE_URL", "backend": "postgres", "configured": True},
    }
    assert "db.example.com" not in json.dumps(payload)
    assert "secret" not in json.dumps(payload)


def test_ready_endpoint_exposes_runtime_auto_migrate_flags(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_AUTO_MIGRATE", "true")
    monkeypatch.setenv("SCA_MONITOR_API_AUTO_MIGRATE", "false")
    monkeypatch.setenv("SCA_MONITOR_WORKER_AUTO_MIGRATE", "false")
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/ready")

    assert payload["runtime_auto_migrate"] == {
        "api": {"enabled": False, "source": "SCA_MONITOR_API_AUTO_MIGRATE"},
        "worker": {"enabled": False, "source": "SCA_MONITOR_WORKER_AUTO_MIGRATE"},
    }


def test_ready_endpoint_reports_invalid_split_flag_as_preflight_blocker(monkeypatch, tmp_path):
    monkeypatch.setenv("SCA_MONITOR_POSTGRES_REQUIRE_SPLIT", "sometimes")
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/ready")

    assert payload["status"] == "ready"
    assert payload["cutover_required"]["status"] == "blocked"
    assert payload["postgres_preflight"]["status"] == "blocked"
    assert payload["postgres_preflight"]["blockers"] == 2
    assert any(check["id"] == "postgres_require_split_flag" for check in payload["cutover_required"]["checks"])


def test_canonicalization_endpoint_reports_ready_without_candidates(tmp_path):
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/operations/canonicalization?limit=10")

    assert payload["status"] == "ready"
    assert payload["limit"] == 10
    assert payload["pending_advisory_merges"] == 0
    assert payload["pending_impact_updates"] == 0
    assert payload["advisory_merge"]["dry_run"] is True
    assert payload["impact_backfill"]["dry_run"] is True


def test_canonicalization_endpoint_reports_advisory_merge_candidates(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")
    sync_github_advisories(app, json_path=ghsa_path, limit=1)

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/operations/canonicalization?limit=10")

    assert payload["status"] == "action_required"
    assert payload["pending_advisory_merges"] == 1
    assert payload["advisory_merge"]["items"][0]["target_advisory_id"] == "OSV-TEST-0001"
    assert payload["advisory_merge"]["items"][0]["source_advisory_ids"] == ["GHSA-xxxx-yyyy-zzzz"]


def test_canonicalization_apply_endpoint_merges_candidates_and_audits(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")
    sync_github_advisories(app, json_path=ghsa_path, limit=1)

    with run_test_server(app) as base_url:
        result = http_json(
            f"{base_url}/api/v1/operations/canonicalization/apply",
            method="POST",
            body={"limit": 10, "actor": "operator", "reason": "manual merge"},
        )
        readiness = http_json(f"{base_url}/api/v1/operations/canonicalization?limit=10")

    assert result["status"] == "ok"
    assert result["merged_advisories"] == 1
    assert result["updated_impacts"] == 0
    assert result["readiness"]["status"] == "ready"
    assert readiness["status"] == "ready"
    with app.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM advisories WHERE advisory_id = 'GHSA-xxxx-yyyy-zzzz'").fetchone()["c"] == 0
    audit = app.search_audit_logs({"action": ["canonicalization.apply"]})
    assert audit["pagination"]["total"] == 1
    assert audit["audit_logs"][0]["actor"] == "operator"
    assert audit["audit_logs"][0]["reason"] == "manual merge"


def test_canonicalization_apply_endpoint_requires_admin_in_header_auth(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    owner_headers = {"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"}
    admin_headers = {"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"}

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/operations/canonicalization/apply",
            method="POST",
            body={"limit": 10},
            headers=owner_headers,
            expect_status=403,
        )
        allowed = http_json(
            f"{base_url}/api/v1/operations/canonicalization/apply",
            method="POST",
            body={"limit": 10, "actor": "spoofed"},
            headers=admin_headers,
        )

    assert "admin role" in forbidden["error"]
    assert allowed["actor"] == "admin@example.test"


def test_remote_deploy_uses_db_gate():
    script = (REPO_ROOT / "scripts" / "deploy_remote.sh").read_text(encoding="utf-8")

    assert "bash scripts/deploy_db_gate.sh" in script
    assert "bash scripts/deploy_systemd_gate.sh" in script
    assert 'SYSTEMD_MODE_OVERRIDE="${SCA_MONITOR_SYSTEMD_MODE:-}"' in script
    assert 'SYSTEMD_SCOPE_OVERRIDE="${SCA_MONITOR_SYSTEMD_SCOPE:-}"' in script
    assert 'SYSTEMD_PREFIX_OVERRIDE="${SCA_MONITOR_SYSTEMD_PREFIX:-}"' in script
    assert 'SYSTEMD_PYTHON_OVERRIDE="${SCA_MONITOR_SYSTEMD_PYTHON:-}"' in script
    assert 'SYSTEMD_REQUIRE_ACTIVE_UNITS_OVERRIDE="${SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS:-}"' in script
    assert 'SCA_MONITOR_SYSTEMD_MODE=\\"\\$SYSTEMD_MODE_OVERRIDE\\"' in script
    assert 'SCA_MONITOR_SYSTEMD_SCOPE=\\"\\$SYSTEMD_SCOPE_OVERRIDE\\"' in script
    assert 'SCA_MONITOR_SYSTEMD_PREFIX=\\"\\$SYSTEMD_PREFIX_OVERRIDE\\"' in script
    assert 'SCA_MONITOR_SYSTEMD_PYTHON=\\"\\$SYSTEMD_PYTHON_OVERRIDE\\"' in script
    assert 'SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS=\\"\\$SYSTEMD_REQUIRE_ACTIVE_UNITS_OVERRIDE\\"' in script
    assert 'SYSTEMD_MODE=\\"\\${SCA_MONITOR_SYSTEMD_MODE:-validate}\\"' in script
    assert "stop_systemd_workers_for_migration() {" in script
    assert "restart_systemd_workers_after_migration() {" in script
    assert "enable-dispatcher-dry-run|enable-advisory-sync-dry-run" in script
    assert "-endpoint-poller.service" in script
    assert "-alert-dispatcher-dry-run.service" in script
    stop_call = script.index("stop_systemd_workers_for_migration\n  trap")
    restart_call = script.index("restart_systemd_workers_after_migration\n  trap - EXIT")
    assert stop_call < script.index("python3 scripts/migrate.py")
    assert script.index("python3 scripts/migrate.py") < script.index("bash scripts/deploy_db_gate.sh")
    assert script.index("bash scripts/deploy_db_gate.sh") < restart_call
    assert 'SCA_MONITOR_SYSTEMD_SCOPE=\\"\\${SCA_MONITOR_SYSTEMD_SCOPE:-user}\\"' in script
    assert 'SCA_MONITOR_SYSTEMD_PREFIX=\\"\\${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}\\"' in script
    assert 'SCA_MONITOR_SYSTEMD_PYTHON=\\"\\${SCA_MONITOR_SYSTEMD_PYTHON:-python3}\\"' in script
    assert 'SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS=\\"\\${SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS:-}\\"' in script
    assert "start_legacy_api() {" in script
    assert "systemd deploy gate failed; restarting legacy API runtime" in script
    assert "systemd deploy gate failed but API health check passed; keeping systemd runtime" in script
    assert 'if [ \\"\\$SYSTEMD_MODE\\" = ' in script
    assert '"\\$SYSTEMD_MODE\\" = ' in script and "enable-api" in script and "enable-poller" in script
    assert "enable-dispatcher-dry-run" in script
    assert "rm -f .data/sca-monitor.pid" in script
    assert "nohup python3 -m backend.sca_monitor" in script


def test_deploy_db_gate_uses_migration_api_and_worker_postgres_urls():
    script = (REPO_ROOT / "scripts" / "deploy_db_gate.sh").read_text(encoding="utf-8")

    assert "scripts/postgres_cutover_readiness.py" in script
    assert "readiness_args+=(--require-postgres)" in script
    assert "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT" in script
    assert "readiness_args+=(--require-split)" in script
    assert 'MIGRATION_URL="${MIGRATION_DATABASE_URL:-$DATABASE_URL}"' in script
    assert 'run_postgres_smoke "$MIGRATION_URL" migration' in script
    assert 'run_postgres_smoke "${API_DATABASE_URL:-}" api "--skip-migrate"' in script
    assert 'run_postgres_smoke "$WORKER_URL" worker "--skip-migrate --read-only"' in script
    assert "postgres integration smoke required for $label but database URL is not configured" in script


def test_deploy_db_gate_requires_split_when_configured(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}"
    result = subprocess.run(
        ["/bin/bash", "scripts/deploy_db_gate.sh"],
        cwd=REPO_ROOT,
        env={
            "PATH": os.environ["PATH"],
            "SCA_MONITOR_DATA_DIR": str(tmp_path),
            "SCA_MONITOR_DATABASE_URL": database_url,
            "SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE": "required",
            "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT": "true",
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "postgres cutover readiness: blocked" in result.stdout
    assert "split credential cutover" in result.stdout


def test_deploy_db_gate_rejects_invalid_split_mode(tmp_path):
    result = subprocess.run(
        ["/bin/bash", "scripts/deploy_db_gate.sh"],
        cwd=REPO_ROOT,
        env={
            "PATH": os.environ["PATH"],
            "SCA_MONITOR_DATA_DIR": str(tmp_path),
            "SCA_MONITOR_POSTGRES_REQUIRE_SPLIT": "sometimes",
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "invalid SCA_MONITOR_POSTGRES_REQUIRE_SPLIT" in result.stderr


def test_postgres_docker_smoke_gate_skips_when_docker_missing(tmp_path):
    result = subprocess.run(
        ["/bin/bash", "scripts/postgres_docker_smoke_gate.sh"],
        cwd=REPO_ROOT,
        env={
            "PATH": str(tmp_path),
            "SCA_MONITOR_POSTGRES_DOCKER_SMOKE": "auto",
        },
        check=True,
        capture_output=True,
        text=True,
    )

    assert "postgres docker smoke skipped: docker executable not found" in result.stdout


def test_postgres_docker_smoke_gate_requires_docker_when_required(tmp_path):
    result = subprocess.run(
        ["/bin/bash", "scripts/postgres_docker_smoke_gate.sh"],
        cwd=REPO_ROOT,
        env={
            "PATH": str(tmp_path),
            "SCA_MONITOR_POSTGRES_DOCKER_SMOKE": "required",
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "postgres docker smoke required but docker executable was not found" in result.stderr


def test_postgres_docker_smoke_gate_skips_when_docker_daemon_unavailable(tmp_path):
    docker = tmp_path / "docker"
    docker.write_text("#!/usr/bin/env bash\necho 'docker daemon unavailable' >&2\nexit 1\n", encoding="utf-8")
    docker.chmod(0o755)

    result = subprocess.run(
        ["/bin/bash", "scripts/postgres_docker_smoke_gate.sh"],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "SCA_MONITOR_POSTGRES_DOCKER_SMOKE": "auto",
        },
        check=True,
        capture_output=True,
        text=True,
    )

    assert "postgres docker smoke skipped: docker daemon is not available" in result.stdout
    assert "docker daemon unavailable" in result.stdout


def test_postgres_docker_smoke_gate_requires_docker_daemon_when_required(tmp_path):
    docker = tmp_path / "docker"
    docker.write_text("#!/usr/bin/env bash\necho 'docker daemon unavailable' >&2\nexit 1\n", encoding="utf-8")
    docker.chmod(0o755)

    result = subprocess.run(
        ["/bin/bash", "scripts/postgres_docker_smoke_gate.sh"],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "SCA_MONITOR_POSTGRES_DOCKER_SMOKE": "required",
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "postgres docker smoke required but docker daemon is not available" in result.stderr
    assert "docker daemon unavailable" in result.stderr


def test_postgres_docker_smoke_gate_documents_docker_workflow():
    script = (REPO_ROOT / "scripts" / "postgres_docker_smoke_gate.sh").read_text(encoding="utf-8")

    assert "SCA_MONITOR_POSTGRES_DOCKER_SMOKE" in script
    assert "SCA_MONITOR_POSTGRES_DOCKER_API_WORKFLOW" in script
    assert "--use-docker" in script
    assert "--with-api-workflow" in script
    assert "--json" in script


def test_ci_smoke_runs_core_gates():
    script = (REPO_ROOT / "scripts" / "ci_smoke.sh").read_text(encoding="utf-8")

    assert "python3 -m pytest tests" in script
    assert "scripts/deployment_input_readiness.py" in script
    assert "scripts/validate_database_env_file.py" in script
    assert "scripts/prepare_database_env_file.py" in script
    assert "scripts/database_env_dry_run_gate.py" in script
    assert "scripts/backup_database.py" in script
    assert "scripts/verify_backup_restore.py" in script
    assert "scripts/cutover_readiness_report.py" in script
    assert "scripts/advisory_source_preflight.py" in script
    assert "SCA_MONITOR_DEPLOYMENT_ENV_FILE" in script
    assert "SCA_MONITOR_REQUIRE_RUNTIME_INPUTS" in script
    assert "node --check frontend/app.js" in script
    assert "bash scripts/deploy_db_gate.sh" in script
    assert "bash scripts/deploy_systemd_gate.sh" in script
    assert "bash scripts/postgres_docker_smoke_gate.sh" in script
    assert "scripts/http_smoke.py" in script
    assert "--base-url" in script
    assert "SCA_MONITOR_CI_HTTP_SMOKE" in script
    assert "SCA_MONITOR_EXPECT_POSTGRES_SPLIT_REQUIRED" in script
    assert "--expect-postgres-split-required" in script
    assert "SCA_MONITOR_EXPECT_ADVISORY_SYNC_READY" in script
    assert "--expect-advisory-sync-ready" in script
    assert "SCA_MONITOR_EXPECT_DATABASE_BACKEND" in script
    assert "--expect-database-backend" in script
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_STATUS" in script
    assert "--expect-cutover-report-status" in script
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_EXPECTED_STATUS" in script
    assert "--expect-cutover-report-expected-status" in script
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS" in script
    assert "--expect-cutover-report-production-preflight-status" in script
    assert "SCA_MONITOR_REQUIRE_CUTOVER_REPORT_EXPECTATION_MET" in script
    assert "--require-cutover-report-expectation-met" in script


def test_deploy_remote_runs_deployment_input_readiness_before_migration():
    script = (REPO_ROOT / "scripts" / "deploy_remote.sh").read_text(encoding="utf-8")

    assert "scripts/configure_runtime_inputs.py" in script
    assert "SCA_MONITOR_GENERATE_SMOKE_TOKEN" in script
    assert "SCA_MONITOR_DATABASE_ENV_FILE" in script
    assert "SCA_MONITOR_PREPARE_DATABASE_ENV_FILE" in script
    assert "SCA_MONITOR_DATABASE_ENV_DRY_RUN" in script
    assert "SCA_MONITOR_DATABASE_ENV_PREFLIGHT_ONLY" in script
    assert "SCA_MONITOR_DATABASE_ENV_PREFLIGHT_EXPECT" in script
    assert "SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT" in script
    assert "SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT_TIMEOUT" in script
    assert "SCA_MONITOR_BOOTSTRAP_READINESS" in script
    assert "SCA_MONITOR_POST_DEPLOY_HTTP_SMOKE" in script
    assert "SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS" in script
    assert "SCA_MONITOR_EXPECT_ADVISORY_SOURCE_STATUS" in script
    assert "SCA_MONITOR_EXPECT_DATABASE_BACKEND" in script
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_STATUS" in script
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_EXPECTED_STATUS" in script
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS" in script
    assert "SCA_MONITOR_REQUIRE_CUTOVER_REPORT_EXPECTATION_MET" in script
    assert "SCA_MONITOR_GHSA_BOOTSTRAP" in script
    assert "SCA_MONITOR_GHSA_BOOTSTRAP_LIMIT" in script
    assert "SCA_MONITOR_BACKUP_BEFORE_MIGRATION" in script
    assert "SCA_MONITOR_VERIFY_BACKUP_RESTORE" in script
    assert "SCA_MONITOR_POSTGRES_PRODUCTION_PREFLIGHT" in script
    assert "SCA_MONITOR_CUTOVER_READINESS_REPORT" in script
    assert "SCA_MONITOR_CUTOVER_READINESS_REPORT_PATH" in script
    assert "--database-env-file" in script
    assert "scripts/prepare_database_env_file.py --database-env-file" in script
    assert "database env file prepared; edit it before enabling PostgreSQL cutover" in script
    assert "scripts/validate_database_env_file.py" in script
    assert "scripts/database_env_dry_run_gate.py --json" in script
    assert "scripts/database_env_dry_run_gate.py --database-env-file" in script
    assert "--expect-status" in script
    assert "--expect-status blocked" in script
    assert "database env preflight matched expected status: blocked" in script
    assert "database env preflight completed; deployment stopped before runtime changes" in script
    assert "scripts/advisory_source_preflight.py --check" in script
    assert "scripts/bootstrap_readiness_check.py --json --skip-alert-activation" in script
    assert "scripts/bootstrap_readiness_check.py --json --skip-alert-activation --require-advisory-freshness" in script
    assert "scripts/bootstrap_readiness_check.py --json" in script
    assert "advisory-freshness|freshness|advisory-freshness-only" in script
    assert "--expect-advisory-source-status" in script
    assert "scripts/http_smoke.py" in script
    assert "scripts/backup_database.py --json" in script
    assert "scripts/verify_backup_restore.py --backup-path" in script
    assert "scripts/postgres_integration_smoke.py --production-preflight --json" in script
    assert "scripts/ghsa_sync.py --limit" in script
    assert "--lock-owner deploy-ghsa-bootstrap" in script
    assert "scripts/cutover_readiness_report.py" in script
    assert "--output" in script
    assert 'if [ -n \\"\\$DATABASE_ENV_FILE\\" ]; then' in script
    assert "cutover_report_args+=(--require-postgres --require-split)" in script
    assert "cutover report with SCA_MONITOR_DATABASE_ENV_FILE requires PostgreSQL split readiness" in script
    assert "--expect-database-backend" in script
    assert "--expect-cutover-report-status" in script
    assert "--expect-cutover-report-expected-status" in script
    assert "--expect-cutover-report-production-preflight-status" in script
    assert "--require-cutover-report-expectation-met" in script
    assert "python3 scripts/deployment_input_readiness.py --env-file .env --json" in script
    assert "SCA_MONITOR_REQUIRE_RUNTIME_INPUTS" in script
    assert "--require-runtime-inputs" in script
    assert script.index("scripts/validate_database_env_file.py") < script.index("scripts/configure_runtime_inputs.py")
    assert script.index('case \\"\\$DATABASE_ENV_PREFLIGHT_ONLY\\"') < script.index('python3 scripts/validate_database_env_file.py --database-env-file \\"\\$DATABASE_ENV_FILE\\" --json')
    assert script.index("scripts/prepare_database_env_file.py --database-env-file") < script.index("set -a")
    assert script.index("scripts/configure_runtime_inputs.py") < script.index("set -a")
    assert script.index("SCA_MONITOR_DATABASE_ENV_PREFLIGHT_ONLY") < script.index("set -a")
    assert script.index("python3 scripts/deployment_input_readiness.py") < script.index("python3 scripts/migrate.py")
    assert script.index("scripts/advisory_source_preflight.py --check") < script.index("python3 scripts/migrate.py")
    assert script.index("scripts/backup_database.py --json") < script.index("python3 scripts/migrate.py")
    assert script.index("scripts/verify_backup_restore.py --backup-path") < script.index("python3 scripts/migrate.py")
    assert script.index("scripts/postgres_integration_smoke.py --production-preflight --json") < script.index("python3 scripts/migrate.py")
    assert script.index("scripts/ghsa_sync.py --limit") < script.index("bash scripts/deploy_systemd_gate.sh")
    assert script.index("scripts/cutover_readiness_report.py") < script.index("python3 scripts/migrate.py")
    assert script.index("python3 scripts/migrate.py") < script.index("scripts/bootstrap_readiness_check.py --json")
    assert script.index("bash scripts/deploy_systemd_gate.sh") < script.index("scripts/http_smoke.py")


def test_harness_documents_deployment_input_readiness():
    database_doc = (REPO_ROOT / "harness" / "database-deployment.md").read_text(encoding="utf-8")
    backend_doc = (REPO_ROOT / "harness" / "backend-deployment.md").read_text(encoding="utf-8")
    cicd_doc = (REPO_ROOT / "harness" / "cicd-automation.md").read_text(encoding="utf-8")
    operations_doc = (REPO_ROOT / "harness" / "operations-runbook.md").read_text(encoding="utf-8")
    requirements_doc = (REPO_ROOT / "harness" / "requirements.md").read_text(encoding="utf-8")
    secrets_doc = (REPO_ROOT / "harness" / "secrets-and-config.md").read_text(encoding="utf-8")
    values_doc = (REPO_ROOT / "harness" / "values" / "deployment-inputs.md").read_text(encoding="utf-8")
    env_example = (REPO_ROOT / "deploy" / "sca-monitor.env.example").read_text(encoding="utf-8")

    for text in (database_doc, cicd_doc, values_doc):
        assert "scripts/deployment_input_readiness.py" in text
    assert "--require-postgres --require-split" in values_doc
    assert "SCA_MONITOR_DATABASE_ENV_FILE" in database_doc
    assert "SCA_MONITOR_PREPARE_DATABASE_ENV_FILE" in database_doc
    assert "deploy/postgres.env.example" in database_doc
    assert "scripts/prepare_database_env_file.py" in database_doc
    assert "scripts/validate_database_env_file.py" in database_doc
    assert "scripts/database_env_dry_run_gate.py" in database_doc
    assert "scripts/verify_backup_restore.py" in database_doc
    assert "scripts/cutover_readiness_report.py" in database_doc
    assert "stop gate로 먼저 실행" in database_doc
    assert "DB URL 원문을 출력하지" in database_doc
    assert "DB URL 원문이나 password를 포함하지" in values_doc
    assert "SCA_MONITOR_DATABASE_ENV_DRY_RUN=synthetic" in database_doc
    assert "SCA_MONITOR_DATABASE_ENV_DRY_RUN=provided" in database_doc
    assert "SCA_MONITOR_DATABASE_ENV_PREFLIGHT_ONLY=true" in database_doc
    assert "SCA_MONITOR_DATABASE_ENV_PREFLIGHT_EXPECT=blocked" in database_doc
    assert "SCA_MONITOR_BACKUP_BEFORE_MIGRATION=required" in database_doc
    assert "SCA_MONITOR_VERIFY_BACKUP_RESTORE=required" in database_doc
    assert "SCA_MONITOR_POSTGRES_PRODUCTION_PREFLIGHT=required" in database_doc
    assert "SCA_MONITOR_CUTOVER_READINESS_REPORT=required" in database_doc
    assert "SCA_MONITOR_CUTOVER_READINESS_REPORT_PATH" in database_doc
    assert "자동으로 `--require-postgres --require-split`" in database_doc
    assert "SCA_MONITOR_DATABASE_ENV_DRY_RUN=synthetic" in cicd_doc
    assert "SCA_MONITOR_EXPECT_DATABASE_BACKEND=sqlite" in cicd_doc
    assert "SCA_MONITOR_EXPECT_ADVISORY_SOURCE_STATUS=OSV=ok,CISA_KEV=ok,OpenSSF=ok" in cicd_doc
    assert "SCA_MONITOR_GHSA_BOOTSTRAP=required" in cicd_doc
    assert "SCA_MONITOR_GHSA_BOOTSTRAP_LIMIT=1" in cicd_doc
    assert "--expect-advisory-source-status OSV=ok" in cicd_doc
    assert "SCA_MONITOR_EXPECT_DATABASE_BACKEND=postgres" in cicd_doc
    assert "SCA_MONITOR_POST_DEPLOY_HTTP_SMOKE=required" in cicd_doc
    assert "--expect-cutover-report-expected-status blocked" in cicd_doc
    assert "--require-cutover-report-expectation-met" in cicd_doc
    assert "--expect-cutover-report-expected-status" in operations_doc
    assert "--expect-cutover-report-production-preflight-status" in operations_doc
    assert "--require-cutover-report-expectation-met" in operations_doc
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_STATUS=ok" in cicd_doc
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_EXPECTED_STATUS=ok" in cicd_doc
    assert "SCA_MONITOR_EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS=ok" in cicd_doc
    assert "--expect-cutover-report-status ok" in cicd_doc
    assert "--expect-cutover-report-production-preflight-status ok" in cicd_doc
    assert "/api/v1/operations/cutover-readiness-report" in cicd_doc
    assert "SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS=sca-monitor-accepted-risk-expiry.timer" in cicd_doc
    assert "SCA_MONITOR_SYSTEMD_MODE=enable-advisory-sync-dry-run" in backend_doc
    assert "SCA_MONITOR_SYSTEMD_MODE=enable-advisory-sync-dry-run" in cicd_doc
    assert "SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS=sca-monitor-osv-npm-sync.timer,sca-monitor-advisory-freshness.timer" in cicd_doc
    assert "enable-advisory-sync-dry-run" in operations_doc
    assert "--require-active-unit sca-monitor-accepted-risk-expiry.timer" in backend_doc
    assert "SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS" in backend_doc
    assert "/api/v1/operations/cutover-readiness-report" in operations_doc
    assert "--expect-database-backend sqlite" in operations_doc
    assert "--require-active-unit sca-monitor-accepted-risk-expiry.timer" in operations_doc
    assert "SCA_MONITOR_AUTH_PROXY_SHARED_SECRET" in env_example
    assert "SCA_MONITOR_AUTH_PROXY_SHARED_SECRET" in secrets_doc
    assert "X-SCA-Proxy-Secret" in secrets_doc
    assert "SCA_MONITOR_AUTH_PROXY_SHARED_SECRET" in requirements_doc
    assert "viewer" in requirements_doc
    assert "view_console=true" in requirements_doc


def test_harness_documents_advisory_source_preflight():
    network_doc = (REPO_ROOT / "harness" / "network-and-ports.md").read_text(encoding="utf-8")
    cicd_doc = (REPO_ROOT / "harness" / "cicd-automation.md").read_text(encoding="utf-8")

    assert "scripts/advisory_source_preflight.py --list-only --json" in network_doc
    assert "scripts/advisory_source_preflight.py --check --json" in network_doc
    assert "SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT=required" in network_doc
    assert "osv-vulnerabilities.storage.googleapis.com" in network_doc
    assert "REQ-NET-006" in network_doc
    assert "scripts/advisory_source_preflight.py --list-only --json" in cicd_doc
    assert "SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT=required" in cicd_doc


def test_harness_documents_bootstrap_readiness_deploy_gate():
    bootstrap_doc = (REPO_ROOT / "harness" / "bootstrap.md").read_text(encoding="utf-8")
    cicd_doc = (REPO_ROOT / "harness" / "cicd-automation.md").read_text(encoding="utf-8")

    assert "SCA_MONITOR_BOOTSTRAP_READINESS=advisory" in bootstrap_doc
    assert "SCA_MONITOR_BOOTSTRAP_READINESS=advisory-freshness" in bootstrap_doc
    assert "--require-advisory-freshness" in bootstrap_doc
    assert "SCA_MONITOR_BOOTSTRAP_READINESS=required" in bootstrap_doc
    assert "SCA_MONITOR_BOOTSTRAP_READINESS=advisory" in cicd_doc
    assert "SCA_MONITOR_BOOTSTRAP_READINESS=advisory-freshness" in cicd_doc


def test_ci_smoke_requires_base_url_when_http_smoke_required(tmp_path):
    result = subprocess.run(
        ["/bin/bash", "scripts/ci_smoke.sh"],
        cwd=REPO_ROOT,
        env={
            "PATH": str(tmp_path),
            "SCA_MONITOR_CI_HTTP_SMOKE": "required",
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "http smoke required but SCA_MONITOR_SMOKE_BASE_URL or SCA_MONITOR_PUBLIC_URL is not configured" in result.stderr


def test_github_actions_ci_runs_ci_smoke_with_postgres_service_smoke():
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "branches:" in workflow and "main" in workflow
    assert "actions/checkout@v4" in workflow
    assert "actions/setup-python@v5" in workflow
    assert "actions/setup-node@v4" in workflow
    assert "SCA_MONITOR_POSTGRES_DOCKER_SMOKE: disabled" in workflow
    assert "SCA_MONITOR_CI_HTTP_SMOKE: disabled" in workflow
    assert "postgres:16" in workflow
    assert "POSTGRES_SMOKE_DATABASE_URL" in workflow
    assert "python -m pip install -e . pytest" in workflow
    assert "bash scripts/ci_smoke.sh" in workflow
    assert 'postgres_integration_smoke.py --database-url "$POSTGRES_SMOKE_DATABASE_URL" --with-api-workflow --json' in workflow


def test_pyproject_limits_setuptools_package_discovery():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    find_config = pyproject["tool"]["setuptools"]["packages"]["find"]

    assert find_config["include"] == ["backend*"]
    assert "frontend*" in find_config["exclude"]
    assert "harness*" in find_config["exclude"]
    assert "migrations*" in find_config["exclude"]


def test_web_console_renders_database_readiness_panel():
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "app.js").read_text(encoding="utf-8")

    assert 'id="database-readiness"' in html
    assert 'id="canonicalization-status"' in html
    assert 'name="system_only"' in html
    assert '<option value="resolved">resolved</option>' in html
    assert 'name="requeue_reason"' in html
    assert "/api/v1/operations/database-readiness" in script
    assert "/api/v1/operations/cutover-readiness-report" in script
    assert "/api/v1/operations/canonicalization" in script
    assert "/api/v1/operations/canonicalization/apply" in script
    assert "System Alerts" in script
    assert "event.reason" in script
    assert "event.alert_suppression_key" in script
    assert "renderAlertEventPayloadSummary" in script
    assert "renderAlertEventPayloadDetails" in script
    assert "event.payload" in script
    assert "JSON.stringify(payload, null, 2)" in script
    assert "alertEventRequeueReason" in script
    assert "form.requeue_reason" in script
    assert "focusRequeueAuditLogs" in script
    assert "view_console" in script
    assert "Audit filter updated to alert_event.requeue" in script
    assert "renderDatabaseReadiness" in script
    assert "renderCanonicalizationStatus" in script
    assert "applyCanonicalization" in script
    assert "URL Source" in script
    assert "Runtime URLs" in script
    assert "API DB" in script
    assert "Worker DB" in script
    assert "Migration DB" in script
    assert "Split Ready" in script
    assert "Split Required" in script
    assert "Runtime Migration" in script
    assert "API Auto-Migrate" in script
    assert "Worker Auto-Migrate" in script
    assert "Cutover Report" in script
    assert "renderCutoverReadinessReport" in script
    assert "Advisory Freshness" in script
    assert "Advisory Sources" in script
    assert "readiness.advisory_sync_readiness" in script
    assert "Preflight Checks" in script
    assert "Next Action" in script
    assert "renderPostgresPreflightSummary" in script
    assert "postgres-preflight-summary" in script
    assert "Cutover blocked" in script
    assert "Cutover ready" in script
    assert "renderPostgresCutoverCheckGroups" in script
    assert "cutover-check-group" in script
    assert "Blocking checks" in script
    assert "Warning checks" in script
    assert "Passing checks" in script


def test_web_console_guides_service_scoped_snapshot_push():
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "app.js").read_text(encoding="utf-8")

    assert "POST /api/v1/services/{service_id}/status" in html
    assert "Authorization: Bearer ${PUSH_TOKEN}" in html
    assert "Idempotency-Key" in html
    assert "generated_at" in html
    assert "dependencies" in html
    assert "pkg:npm/lodash@4.17.20" not in html
    assert "/api/v1/snapshots" not in html
    assert "/api/v1/snapshots" not in script
    assert "/api/v1/services/${encodeURIComponent(form.service_id)}/status" in script


def test_web_console_push_credential_result_includes_ready_to_copy_curl():
    script = (REPO_ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    styles = (REPO_ROOT / "frontend" / "styles.css").read_text(encoding="utf-8")

    assert "function renderPushCredentialResult(data, actionLabel)" in script
    assert "snapshotPushCurlSnippet(data)" in script
    assert "curl -sS -X POST" in script
    assert "/api/v1/services/${encodeURIComponent(data.credential.service_id)}/status" in script
    assert "shellQuote(`Authorization: Bearer ${data.token}`)" in script
    assert "shellQuote(`Idempotency-Key: ${idempotencyKey}`)" in script
    assert "generated_at" in script
    assert "service_id" in script
    assert "environment" in script
    assert "credential-snippet" in script
    assert ".credential-snippet" in styles


def test_web_console_push_credential_snippet_can_be_copied():
    script = (REPO_ROOT / "frontend" / "app.js").read_text(encoding="utf-8")

    assert "data-copy-snippet" in script
    assert "function attachCredentialSnippetCopyHandler()" in script
    assert "navigator.clipboard.writeText(snippet)" in script
    assert "Copy curl" in script
    assert "Copied" in script
    assert "Copy failed" in script
    assert "attachCredentialSnippetCopyHandler();" in script


def test_web_console_gates_impact_status_options_by_role():
    script = (REPO_ROOT / "frontend" / "app.js").read_text(encoding="utf-8")

    assert "function canImpactStatusTarget(status, impact)" in script
    assert '["acknowledged", "in_progress", "fixed", "not_affected"].includes(status)' in script
    assert "currentSession.owner_teams?.includes(impact.owner_team)" in script
    assert "option.disabled = !canImpactStatusTarget(option.value, currentImpact)" in script
    assert "statusButton.disabled = !can(\"update_impacts\") || !canImpactStatusTarget(statusSelect?.value, currentImpact)" in script
    assert "!canImpactStatusTarget(body.status, currentImpact)" in script


def enabled_now_lines(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if " enable --now " in line)


def restart_lines(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if " restart " in line)


def stop_lines(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if " stop " in line)


def test_postgres_sql_translates_placeholders_outside_string_literals():
    sql = "SELECT * FROM services WHERE service_id = ? AND note = '?' AND environment = ?"

    assert postgres_sql(sql) == "SELECT * FROM services WHERE service_id = %s AND note = '?' AND environment = %s"
    assert postgres_sql("BEGIN IMMEDIATE") == "-- transaction already managed by psycopg adapter"
    assert "enabled AND is_default" in (REPO_ROOT / "backend" / "sca_monitor" / "alert_preflight.py").read_text(
        encoding="utf-8"
    )
    assert "WHERE enabled = 1 AND is_default = 1" not in (
        REPO_ROOT / "backend" / "sca_monitor" / "alert_preflight.py"
    ).read_text(encoding="utf-8")


def test_postgres_connection_adapter_executes_translated_sql():
    class FakeCursor:
        rowcount = 1

        def fetchone(self):
            return {"c": 1}

        def fetchall(self):
            return [{"c": 1}]

    class FakeConnection:
        def __init__(self):
            self.calls = []

        def execute(self, sql, params=()):
            self.calls.append((sql, params))
            return FakeCursor()

    fake = FakeConnection()
    cursor = PostgresConnectionAdapter(fake).execute("SELECT COUNT(*) AS c FROM services WHERE service_id = ?", ("svc",))

    assert fake.calls == [("SELECT COUNT(*) AS c FROM services WHERE service_id = %s", ("svc",))]
    assert cursor.fetchone()["c"] == 1


def test_db_smoke_runs_postgres_runtime_adapter_path():
    from scripts.db_smoke import run_smoke

    missing = object()

    class FakeCursor:
        rowcount = 1

        def __init__(self, row=missing):
            self.row = {"c": 0} if row is missing else row

        def fetchone(self):
            return self.row

    class FakeConnection:
        def __init__(self):
            self.inserted_audit_id = None

        def execute(self, sql, params=()):
            if sql.startswith("SELECT COUNT(*)"):
                return FakeCursor({"c": 0})
            if sql.startswith("BEGIN"):
                return FakeCursor()
            if "INSERT INTO audit_logs" in sql:
                self.inserted_audit_id = params[0]
                return FakeCursor()
            if "SELECT id FROM audit_logs" in sql:
                return FakeCursor({"id": self.inserted_audit_id}) if self.inserted_audit_id == params[0] else FakeCursor(None)
            raise AssertionError(f"unexpected SQL: {sql}")

        def rollback(self):
            self.inserted_audit_id = None

    class FakePostgresDatabase:
        backend = "postgres"

        def __init__(self):
            self.connection = FakeConnection()

        def readiness(self):
            return {
                "database": "ok",
                "database_backend": "postgres",
                "migration": {"current": REQUIRED_MIGRATION_VERSION, "required": REQUIRED_MIGRATION_VERSION, "minimum_supported": 1, "compatible": True},
            }

        @contextmanager
        def connect(self):
            yield self.connection

    result = run_smoke(FakePostgresDatabase())

    assert result["status"] == "ok"
    assert result["database_backend"] == "postgres"
    assert result["checks"]["audit_log_write_rollback"] is True
    assert result["checks"]["audit_log_rollback_clean"] is True


def test_postgres_integration_smoke_helpers():
    from scripts.postgres_integration_smoke import docker_database_url

    assert docker_database_url(55432, "user", "pass", "db") == "postgresql://user:pass@127.0.0.1:55432/db"


def test_postgres_integration_smoke_can_skip_migrate_and_write(monkeypatch):
    import scripts.postgres_integration_smoke as pg_smoke

    calls = {"migrate": 0, "write_check": None}

    class FakeDatabase:
        def __init__(self, database_url):
            self.database_url = database_url

        def migrate(self):
            calls["migrate"] += 1

    def fake_run_smoke(database, *, write_check=True):
        calls["write_check"] = write_check
        return {"status": "ok", "database_url": database.database_url}

    monkeypatch.setattr(pg_smoke, "Database", FakeDatabase)
    monkeypatch.setattr(pg_smoke, "run_smoke", fake_run_smoke)

    result = pg_smoke.run_postgres_smoke("postgresql://runtime/db", migrate=False, write_check=False)

    assert result["status"] == "ok"
    assert calls == {"migrate": 0, "write_check": False}


def test_postgres_container_readiness_waits_for_pg_isready(monkeypatch):
    import scripts.postgres_integration_smoke as pg_smoke

    calls = []

    class Result:
        def __init__(self, returncode):
            self.returncode = returncode
            self.stdout = ""
            self.stderr = ""

    def fake_run_command(args, *, check=True):
        calls.append(args)
        return Result(1 if len(calls) == 1 else 0)

    monkeypatch.setattr(pg_smoke, "run_command", fake_run_command)
    monkeypatch.setattr(pg_smoke.time, "sleep", lambda _: None)

    assert pg_smoke.wait_for_postgres_container("pg", "user", "db", 5) is True
    assert calls == [
        ["docker", "exec", "pg", "pg_isready", "-U", "user", "-d", "db"],
        ["docker", "exec", "pg", "pg_isready", "-U", "user", "-d", "db"],
    ]


def test_postgres_production_preflight_checks_split_roles(monkeypatch):
    import scripts.postgres_integration_smoke as pg_smoke

    calls = []

    def fake_run_postgres_smoke(database_url, *, migrate=True, write_check=True):
        calls.append({"database_url": database_url, "migrate": migrate, "write_check": write_check})
        return {"status": "ok", "database_url": database_url}

    monkeypatch.setattr(pg_smoke, "run_postgres_smoke", fake_run_postgres_smoke)

    result = pg_smoke.run_production_preflight(
        {
            "MIGRATION_DATABASE_URL": "postgresql://migrator/db",
            "API_DATABASE_URL": "postgresql://api/db",
            "WORKER_DATABASE_URL": "postgresql://worker/db",
        }
    )

    assert result["status"] == "ok"
    assert calls == [
        {"database_url": "postgresql://migrator/db", "migrate": True, "write_check": True},
        {"database_url": "postgresql://api/db", "migrate": False, "write_check": False},
        {"database_url": "postgresql://worker/db", "migrate": False, "write_check": False},
    ]


def test_postgres_production_preflight_fails_when_role_urls_missing():
    from scripts.postgres_integration_smoke import run_production_preflight

    result = run_production_preflight({"MIGRATION_DATABASE_URL": "sqlite:///tmp/sca.sqlite3"})

    assert result["status"] == "failed"
    assert result["checks"]["migration"]["status"] == "failed"
    assert "MIGRATION_DATABASE_URL is not PostgreSQL" in result["checks"]["migration"]["error"]
    assert result["checks"]["api"]["status"] == "failed"
    assert "API_DATABASE_URL is not configured" in result["checks"]["api"]["error"]
    assert result["checks"]["worker"]["status"] == "failed"


def test_postgres_production_preflight_cli_fails_without_split_urls(tmp_path):
    result = subprocess.run(
        ["python3", "scripts/postgres_integration_smoke.py", "--production-preflight", "--json"],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"], "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "failed"
    assert set(payload["checks"]) == {"migration", "api", "worker"}


def test_postgres_integration_api_workflow_smoke_uses_app_flow(tmp_path):
    from scripts.postgres_integration_smoke import run_api_workflow_smoke

    database_url = f"sqlite:///{tmp_path / 'workflow.sqlite3'}"

    result = run_api_workflow_smoke(database_url)

    assert result["service_id"].startswith("pg-smoke-")
    assert result["snapshot_id"] == "postgres-smoke"
    assert result["service_count_after"] == result["service_count_before"] + 1


def test_postgres_integration_smoke_skips_without_database_url_or_docker():
    result = subprocess.run(
        ["python3", "scripts/postgres_integration_smoke.py", "--json"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "skipped"
    assert "--database-url or --use-docker" in payload["reason"]


def test_push_credential_issue_and_bound_snapshot_push(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service({"service_id": "credential-service", "environment": "prod", "owner_team": "platform"})

    issued = app.create_push_credential("credential-service", {"environment": "prod", "ttl_days": 30})
    token = issued["token"]

    assert token.startswith("sca_")
    assert issued["credential"]["token_prefix"] == token[:12]
    credentials = app.list_push_credentials("credential-service", {"environment": ["prod"]})
    assert credentials[0]["token_prefix"] == token[:12]
    assert "token" not in credentials[0]
    with app.db.connect() as conn:
        row = conn.execute("SELECT token_hash, last_used_at FROM push_credentials").fetchone()
        assert row["token_hash"] != token
        assert row["last_used_at"] is None

    result = app.push_snapshot(
        {
            "service_id": "credential-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        },
        f"Bearer {token}",
    )

    assert result["impacts_created_or_updated"] == 0
    with app.db.connect() as conn:
        assert conn.execute("SELECT last_used_at FROM push_credentials").fetchone()["last_used_at"] is not None


def test_snapshot_push_rejects_too_many_dependencies(tmp_path):
    app = make_test_app(tmp_path, max_snapshot_dependencies=1)

    with pytest.raises(ValueError, match="dependencies exceed maximum count of 1"):
        app.push_snapshot(
            {
                "service_id": "limited-service",
                "environment": "prod",
                "dependencies": [
                    {"ecosystem": "npm", "name": "first-package", "version": "1.0.0"},
                    {"ecosystem": "npm", "name": "second-package", "version": "1.0.0"},
                ],
            }
        )


def test_snapshot_push_route_rejects_oversized_payload(tmp_path):
    app = make_test_app(tmp_path, max_snapshot_payload_bytes=120)

    with run_test_server(app) as base_url:
        response = http_json(
            f"{base_url}/api/v1/snapshots",
            method="POST",
            body={
                "service_id": "payload-limited-service",
                "environment": "prod",
                "dependencies": [{"ecosystem": "npm", "name": "large-package-name", "version": "1.0.0"}],
            },
            expect_status=413,
        )

    assert response["error"] == "payload exceeds maximum size of 120 bytes"


def test_snapshot_push_idempotent_replay_updates_last_confirmed(tmp_path):
    app = make_test_app(tmp_path)
    body = {
        "service_id": "idempotent-service",
        "environment": "prod",
        "snapshot_id": "build-2026-06-11",
        "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
    }

    created = app.push_snapshot(body)
    with app.db.connect() as conn:
        snapshot_pk = conn.execute(
            "SELECT id FROM dependency_snapshots WHERE snapshot_id = ?",
            (body["snapshot_id"],),
        ).fetchone()["id"]
        conn.execute("UPDATE dependency_snapshots SET last_confirmed_at = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", snapshot_pk))

    confirmed = app.push_snapshot(body)

    assert created["idempotency_status"] == "created"
    assert confirmed["idempotency_status"] == "confirmed"
    assert confirmed["impacts_created_or_updated"] == 0
    with app.db.connect() as conn:
        snapshot = conn.execute("SELECT content_hash, last_confirmed_at FROM dependency_snapshots WHERE id = ?", (snapshot_pk,)).fetchone()
        dependency_count = conn.execute("SELECT COUNT(*) AS c FROM dependencies WHERE snapshot_pk = ?", (snapshot_pk,)).fetchone()["c"]
    assert snapshot["content_hash"] == created["content_hash"]
    assert snapshot["last_confirmed_at"] != "2000-01-01T00:00:00+00:00"
    assert dependency_count == 1


def test_snapshot_push_conflicts_on_same_snapshot_id_with_different_hash(tmp_path):
    app = make_test_app(tmp_path)
    body = {
        "service_id": "conflict-service",
        "environment": "prod",
        "snapshot_id": "build-2026-06-11",
        "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
    }
    app.push_snapshot(body)

    with pytest.raises(ValueError, match="snapshot_id already exists with different content_hash"):
        app.push_snapshot(
            {
                **body,
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "2.0.0"}],
            }
        )


def test_snapshot_push_route_returns_200_for_replay_and_409_for_conflict(tmp_path):
    app = make_test_app(tmp_path)
    body = {
        "service_id": "route-idempotent-service",
        "environment": "prod",
        "snapshot_id": "route-build-2026-06-11",
        "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
    }

    with run_test_server(app) as base_url:
        created = http_json(f"{base_url}/api/v1/snapshots", method="POST", body=body, expect_status=201)
        confirmed = http_json(f"{base_url}/api/v1/snapshots", method="POST", body=body, expect_status=200)
        conflict = http_json(
            f"{base_url}/api/v1/snapshots",
            method="POST",
            body={
                **body,
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "2.0.0"}],
            },
            expect_status=409,
        )

    assert created["idempotency_status"] == "created"
    assert confirmed["idempotency_status"] == "confirmed"
    assert conflict["error"] == "snapshot_id already exists with different content_hash"


def test_service_status_push_route_binds_service_id_from_path(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service({"service_id": "status-service", "environment": "prod"})
    issued = app.create_push_credential("status-service", {"environment": "prod"})

    with run_test_server(app) as base_url:
        created = http_json(
            f"{base_url}/api/v1/services/status-service/status",
            method="POST",
            body={
                "schema_version": "1.0",
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            },
            headers={"Authorization": f"Bearer {issued['token']}"},
            expect_status=201,
        )
        mismatch = http_json(
            f"{base_url}/api/v1/services/status-service/status",
            method="POST",
            body={
                "service_id": "spoofed-service",
                "schema_version": "1.0",
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            },
            headers={"Authorization": f"Bearer {issued['token']}"},
            expect_status=400,
        )

    assert created["service_id"] == "status-service"
    assert created["environment"] == "prod"
    assert created["idempotency_status"] == "created"
    assert "must match route service_id" in mismatch["error"]
    with app.db.connect() as conn:
        row = conn.execute(
            """
            SELECT s.service_id, ds.environment
            FROM dependency_snapshots ds
            JOIN services s ON s.id = ds.service_pk
            WHERE ds.snapshot_id = ?
            """,
            (created["snapshot_id"],),
        ).fetchone()
    assert row["service_id"] == "status-service"
    assert row["environment"] == "prod"


def test_service_status_push_route_requires_schema_fields(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service({"service_id": "strict-status-service", "environment": "prod"})
    issued = app.create_push_credential("strict-status-service", {"environment": "prod"})
    valid_dependency = {"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}

    with run_test_server(app) as base_url:
        missing_schema = http_json(
            f"{base_url}/api/v1/services/strict-status-service/status",
            method="POST",
            body={
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [valid_dependency],
            },
            headers={"Authorization": f"Bearer {issued['token']}"},
            expect_status=400,
        )
        unsupported_schema = http_json(
            f"{base_url}/api/v1/services/strict-status-service/status",
            method="POST",
            body={
                "schema_version": "2.0",
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [valid_dependency],
            },
            headers={"Authorization": f"Bearer {issued['token']}"},
            expect_status=400,
        )
        missing_generated_at = http_json(
            f"{base_url}/api/v1/services/strict-status-service/status",
            method="POST",
            body={
                "schema_version": "1.0",
                "environment": "prod",
                "dependencies": [valid_dependency],
            },
            headers={"Authorization": f"Bearer {issued['token']}"},
            expect_status=400,
        )
        missing_dependency_version = http_json(
            f"{base_url}/api/v1/services/strict-status-service/status",
            method="POST",
            body={
                "schema_version": "1.0",
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [{"ecosystem": "npm", "name": "example-package"}],
            },
            headers={"Authorization": f"Bearer {issued['token']}"},
            expect_status=400,
        )

    assert "schema_version required" in missing_schema["error"]
    assert unsupported_schema["error"] == "unsupported schema_version"
    assert "generated_at required" in missing_generated_at["error"]
    assert "version required" in missing_dependency_version["error"]


def test_legacy_snapshot_push_strict_mode_requires_schema_fields(tmp_path):
    app = make_test_app(tmp_path, strict_snapshot_push=True)

    with pytest.raises(ValueError, match="schema_version required"):
        app.push_snapshot(
            {
                "service_id": "strict-legacy-service",
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            }
        )

    with pytest.raises(ValueError, match="unsupported schema_version"):
        app.push_snapshot(
            {
                "service_id": "strict-legacy-service",
                "schema_version": "2.0",
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            }
        )

    with pytest.raises(ValueError, match="generated_at required"):
        app.push_snapshot(
            {
                "service_id": "strict-legacy-service",
                "schema_version": "1.0",
                "environment": "prod",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            }
        )


def test_legacy_snapshot_push_strict_mode_route_rejects_invalid_schema(tmp_path):
    app = make_test_app(tmp_path, strict_snapshot_push=True)

    with run_test_server(app) as base_url:
        response = http_json(
            f"{base_url}/api/v1/snapshots",
            method="POST",
            body={
                "service_id": "strict-route-service",
                "environment": "prod",
                "generated_at": "2026-06-12T00:00:00+00:00",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            },
            expect_status=400,
        )

    assert response["error"] == "schema_version required"


def test_snapshot_push_rate_limit_rejects_excess_service_pushes(tmp_path):
    app = make_test_app(tmp_path, max_snapshot_pushes_per_minute=2)

    app.push_snapshot(
        {
            "service_id": "rate-limited-service",
            "environment": "prod",
            "snapshot_id": "first",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    app.push_snapshot(
        {
            "service_id": "rate-limited-service",
            "environment": "prod",
            "snapshot_id": "second",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.2"}],
        }
    )

    with pytest.raises(ValueError, match="snapshot push rate limit exceeded: 2 requests per minute"):
        app.push_snapshot(
            {
                "service_id": "rate-limited-service",
                "environment": "prod",
                "snapshot_id": "third",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.3"}],
            }
        )


def test_snapshot_push_rate_limit_is_scoped_to_push_credential(tmp_path):
    app = make_test_app(tmp_path, max_snapshot_pushes_per_minute=1)
    app.create_service({"service_id": "credential-rate-a", "environment": "prod", "owner_team": "platform"})
    app.create_service({"service_id": "credential-rate-b", "environment": "prod", "owner_team": "platform"})
    token_a = app.create_push_credential("credential-rate-a", {"environment": "prod"})["token"]
    token_b = app.create_push_credential("credential-rate-b", {"environment": "prod"})["token"]

    app.push_snapshot(
        {
            "service_id": "credential-rate-a",
            "environment": "prod",
            "snapshot_id": "first",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        },
        f"Bearer {token_a}",
    )
    app.push_snapshot(
        {
            "service_id": "credential-rate-b",
            "environment": "prod",
            "snapshot_id": "first",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        },
        f"Bearer {token_b}",
    )

    with pytest.raises(ValueError, match="snapshot push rate limit exceeded: 1 requests per minute"):
        app.push_snapshot(
            {
                "service_id": "credential-rate-a",
                "environment": "prod",
                "snapshot_id": "second",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.2"}],
            },
            f"Bearer {token_a}",
        )


def test_snapshot_push_route_returns_429_for_rate_limit(tmp_path):
    app = make_test_app(tmp_path, max_snapshot_pushes_per_minute=1)
    body = {
        "service_id": "route-rate-limited-service",
        "environment": "prod",
        "snapshot_id": "first",
        "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
    }

    with run_test_server(app) as base_url:
        created = http_json(f"{base_url}/api/v1/snapshots", method="POST", body=body, expect_status=201)
        limited = http_json(
            f"{base_url}/api/v1/snapshots",
            method="POST",
            body={**body, "snapshot_id": "second"},
            expect_status=429,
        )

    assert created["idempotency_status"] == "created"
    assert limited["error"] == "snapshot push rate limit exceeded: 1 requests per minute"


def test_push_credential_rejects_service_environment_spoofing(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service({"service_id": "credential-service", "environment": "prod", "owner_team": "platform"})
    token = app.create_push_credential("credential-service", {"environment": "prod"})["token"]

    with pytest.raises(PermissionError, match="not bound"):
        app.push_snapshot(
            {
                "service_id": "other-service",
                "environment": "prod",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            },
            f"Bearer {token}",
        )


def test_push_credential_revoke_blocks_token_reuse(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service({"service_id": "credential-service", "environment": "prod", "owner_team": "platform"})
    issued = app.create_push_credential("credential-service", {"environment": "prod"})
    token = issued["token"]
    credential_id = issued["credential"]["id"]

    revoked = app.revoke_push_credential("credential-service", credential_id, {"environment": "prod"})

    assert revoked["credential"]["revoked_at"] is not None
    credentials = app.list_push_credentials("credential-service", {"environment": ["prod"]})
    assert credentials[0]["revoked_at"] == revoked["credential"]["revoked_at"]
    with pytest.raises(PermissionError, match="revoked"):
        app.push_snapshot(
            {
                "service_id": "credential-service",
                "environment": "prod",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            },
            f"Bearer {token}",
        )


def test_push_credential_rotate_revokes_old_token_and_issues_new(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service({"service_id": "credential-service", "environment": "prod", "owner_team": "platform"})
    issued = app.create_push_credential("credential-service", {"environment": "prod", "ttl_days": 30})
    old_token = issued["token"]
    credential_id = issued["credential"]["id"]

    rotated = app.rotate_push_credential(
        "credential-service",
        credential_id,
        {"environment": "prod", "ttl_days": 60, "actor": "security-admin", "reason": "scheduled rotation"},
    )

    assert rotated["rotated"] is True
    assert rotated["revoked_credential"]["id"] == credential_id
    assert rotated["revoked_credential"]["revoked_at"] is not None
    assert rotated["credential"]["id"] != credential_id
    assert rotated["token"].startswith("sca_")
    assert rotated["credential"]["token_prefix"] == rotated["token"][:12]
    with pytest.raises(PermissionError, match="revoked"):
        app.push_snapshot(
            {
                "service_id": "credential-service",
                "environment": "prod",
                "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
            },
            f"Bearer {old_token}",
        )

    result = app.push_snapshot(
        {
            "service_id": "credential-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        },
        f"Bearer {rotated['token']}",
    )

    assert result["impacts_created_or_updated"] == 0
    credentials = app.list_push_credentials("credential-service", {"environment": ["prod"]})
    assert {credential["revoked_at"] is None for credential in credentials} == {True, False}


def test_push_credential_rotate_rejects_revoked_credential(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service({"service_id": "credential-service", "environment": "prod", "owner_team": "platform"})
    issued = app.create_push_credential("credential-service", {"environment": "prod"})
    credential_id = issued["credential"]["id"]
    app.revoke_push_credential("credential-service", credential_id, {"environment": "prod"})

    with pytest.raises(ValueError, match="already revoked"):
        app.rotate_push_credential("credential-service", credential_id, {"environment": "prod"})


def test_alert_channel_create_list_redacts_target(tmp_path):
    app = make_test_app(tmp_path)

    created = app.create_alert_channel(
        {
            "name": "security-router",
            "channel_type": "webhook",
            "target_url": "https://alerts.example.test/hooks/secret-token",
            "is_default": True,
        }
    )

    assert created["channel"]["name"] == "security-router"
    assert created["channel"]["channel_type"] == "webhook"
    assert created["channel"]["target_configured"] is True
    assert created["channel"]["target_url_masked"] == "https://alerts.example.test/..."
    assert created["channel"]["placeholder_target"] is True
    assert "secret-token" not in json.dumps(created)
    channels = app.list_alert_channels()
    assert channels[0]["is_default"] is True
    assert channels[0]["placeholder_target"] is True
    assert "secret-token" not in json.dumps(channels)
    assert app.default_alert_webhook_url() == "https://alerts.example.test/hooks/secret-token"


def test_alert_channel_marks_non_placeholder_target_ready(tmp_path):
    app = make_test_app(tmp_path)

    created = app.create_alert_channel(
        {
            "name": "security-router",
            "channel_type": "webhook",
            "target_url": "https://alerts.internal/hooks/secret-token",
            "is_default": True,
        }
    )

    assert created["channel"]["target_url_masked"] == "https://alerts.internal/..."
    assert created["channel"]["placeholder_target"] is False


def test_alert_channel_can_target_owner_team(tmp_path):
    app = make_test_app(tmp_path)

    created = app.create_alert_channel(
        {
            "name": "platform-router",
            "channel_type": "webhook",
            "target_url": "https://alerts.internal/hooks/platform-secret",
            "is_default": False,
            "owner_team": "platform",
            "actor": "security-admin",
        }
    )

    assert created["channel"]["owner_team"] == "platform"
    assert created["channel"]["routing_scope"] == "owner_team"
    assert created["channel"]["is_default"] is False
    channels = app.list_alert_channels()
    assert channels[0]["owner_team"] == "platform"
    assert channels[0]["routing_scope"] == "owner_team"
    audit = app.search_audit_logs({"action": ["alert_channel.upsert"], "target_id": [created["channel"]["id"]]})
    assert audit["audit_logs"][0]["after"]["owner_team"] == "platform"
    assert "platform-secret" not in json.dumps(created)
    assert "platform-secret" not in json.dumps(channels)


def test_seed_default_alert_channel_cli_creates_real_default(tmp_path):
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
        "SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL": "https://alerts.internal/hooks/secret-token",
        "SCA_MONITOR_DEFAULT_ALERT_CHANNEL_NAME": "bootstrap-router",
    }

    result = subprocess.run(
        ["python3", "scripts/seed_default_alert_channel.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["before"] == {"configured": False}
    assert payload["after"]["configured"] is True
    assert payload["after"]["target_url_masked"] == "https://alerts.internal/..."
    assert payload["after"]["placeholder_target"] is False
    assert payload["channel"]["name"] == "bootstrap-router"
    assert "secret-token" not in result.stdout


def test_seed_default_alert_channel_cli_rejects_placeholder_by_default(tmp_path):
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
        "SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL": "https://alerts.example.test/hooks/secret-token",
    }

    result = subprocess.run(
        ["python3", "scripts/seed_default_alert_channel.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "error"
    assert "placeholder webhook target rejected" in payload["error"]


def test_seed_default_alert_channel_cli_allows_placeholder_for_dev(tmp_path):
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
        "SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL": "https://alerts.example.test/hooks/secret-token",
    }

    result = subprocess.run(
        ["python3", "scripts/seed_default_alert_channel.py", "--json", "--allow-placeholder"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["after"]["placeholder_target"] is True
    assert "secret-token" not in result.stdout


def test_alert_channel_only_one_default(tmp_path):
    app = make_test_app(tmp_path)

    app.create_alert_channel({"name": "first", "target_url": "https://first.example.test/webhook", "is_default": True})
    app.create_alert_channel({"name": "second", "target_url": "https://second.example.test/webhook", "is_default": True})

    channels = app.list_alert_channels()
    defaults = [channel for channel in channels if channel["is_default"]]
    assert [channel["name"] for channel in defaults] == ["second"]
    assert app.default_alert_webhook_url() == "https://second.example.test/webhook"


def test_alert_channel_update_default_and_disable(tmp_path):
    app = make_test_app(tmp_path)
    first = app.create_alert_channel({"name": "first", "target_url": "https://first.example.test/webhook", "is_default": True})["channel"]
    second = app.create_alert_channel({"name": "second", "target_url": "https://second.example.test/webhook", "is_default": False})["channel"]

    updated = app.update_alert_channel(second["id"], {"is_default": True, "enabled": True})

    assert updated["channel"]["is_default"] is True
    assert app.default_alert_webhook_url() == "https://second.example.test/webhook"
    channels = app.list_alert_channels()
    assert [channel["name"] for channel in channels if channel["is_default"]] == ["second"]

    disabled = app.update_alert_channel(second["id"], {"enabled": False})

    assert disabled["channel"]["enabled"] is False
    assert disabled["channel"]["is_default"] is False
    assert app.default_alert_webhook_url() is None
    assert app.update_alert_channel(first["id"], {"name": "first-renamed"})["channel"]["name"] == "first-renamed"


def test_alert_channel_changes_are_audited_without_secret_target(tmp_path):
    app = make_test_app(tmp_path)

    channel = app.create_alert_channel(
        {
            "name": "audit-channel",
            "target_url": "https://alerts.example.test/hooks/sensitive-token",
            "is_default": True,
            "actor": "security-admin",
            "reason": "initial setup",
        }
    )["channel"]
    app.update_alert_channel(channel["id"], {"enabled": False, "actor": "security-admin", "reason": "rotation"})

    page = app.search_audit_logs({"target_type": ["alert_channel"], "target_id": [channel["id"]]})

    assert page["pagination"]["total"] == 2
    assert [item["action"] for item in page["audit_logs"]] == ["alert_channel.update", "alert_channel.upsert"]
    assert page["audit_logs"][0]["actor"] == "security-admin"
    assert page["audit_logs"][0]["reason"] == "rotation"
    assert "sensitive-token" not in json.dumps(page)
    assert page["audit_logs"][0]["before"]["target_url_masked"] == "https://alerts.example.test/..."


def test_alert_channel_test_sends_synthetic_payload_and_audits(tmp_path):
    app = make_test_app(tmp_path)
    delivered = []
    channel = app.create_alert_channel(
        {
            "name": "smoke-channel",
            "target_url": "https://alerts.example.test/hooks/sensitive-token",
            "is_default": True,
        }
    )["channel"]

    result = app.test_alert_channel(
        channel["id"],
        {"actor": "security-admin", "reason": "pre-live dispatcher test"},
        sender=lambda url, payload, headers: delivered.append((url, payload, headers)),
    )

    assert result["status"] == "ok"
    assert result["channel"]["target_url_masked"] == "https://alerts.example.test/..."
    assert delivered[0][0] == "https://alerts.example.test/hooks/sensitive-token"
    assert delivered[0][1]["smoke"] is True
    assert delivered[0][1]["channel_name"] == "smoke-channel"
    assert delivered[0][2]["X-SCA-Alert-Channel-Test"] == "true"
    page = app.search_audit_logs({"target_type": ["alert_channel"], "target_id": [channel["id"]]})
    assert [item["action"] for item in page["audit_logs"]] == ["alert_channel.test", "alert_channel.upsert"]
    assert page["audit_logs"][0]["actor"] == "security-admin"
    assert "sensitive-token" not in json.dumps(page)


def test_alert_channel_test_rejects_disabled_channel(tmp_path):
    app = make_test_app(tmp_path)
    channel = app.create_alert_channel(
        {
            "name": "disabled-channel",
            "target_url": "https://alerts.example.test/hooks/disabled",
            "is_default": True,
        }
    )["channel"]
    app.update_alert_channel(channel["id"], {"enabled": False})

    with pytest.raises(ValueError, match="disabled"):
        app.test_alert_channel(channel["id"], {}, sender=lambda url, payload, headers: None)


def test_alert_channel_test_api_posts_to_webhook(tmp_path):
    received = []

    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.append(
                {
                    "path": self.path,
                    "payload": json.loads(body.decode("utf-8")),
                    "headers": dict(self.headers),
                }
            )
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            return

    webhook = ThreadingHTTPServer(("127.0.0.1", 0), WebhookHandler)
    thread = threading.Thread(target=webhook.serve_forever, daemon=True)
    thread.start()
    try:
        app = make_test_app(tmp_path)
        channel = app.create_alert_channel(
            {
                "name": "api-smoke-channel",
                "target_url": f"http://127.0.0.1:{webhook.server_port}/hooks/secret",
                "is_default": True,
            }
        )["channel"]
        with run_test_server(app) as base_url:
            result = http_json(
                f"{base_url}/api/v1/settings/alert-channels/{channel['id']}/test",
                method="POST",
                body={"actor": "web-console", "reason": "api smoke"},
            )
    finally:
        webhook.shutdown()
        thread.join(timeout=5)
        webhook.server_close()

    assert result["status"] == "ok"
    assert result["channel"]["target_url_masked"] == f"http://127.0.0.1:{webhook.server_port}/..."
    assert received[0]["path"] == "/hooks/secret"
    assert received[0]["payload"]["smoke"] is True
    assert received[0]["headers"]["X-Sca-Alert-Channel-Test"] == "true"


def test_service_endpoint_test_records_healthy_status(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
        }
    )

    result = app.test_service_endpoint(
        "endpoint-service",
        {"environment": "prod"},
        fetcher=lambda url, auth_header=None: {
            "schema_version": "1.0",
            "service_id": "endpoint-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
        },
    )

    assert result["collection_status"] == "ok"
    with app.db.connect() as conn:
        row = conn.execute("SELECT collection_status, freshness_status, last_successful_poll_at FROM endpoint_health").fetchone()
        assert row["collection_status"] == "ok"
        assert row["freshness_status"] == "fresh"
        assert row["last_successful_poll_at"] is not None


def test_service_endpoint_test_records_invalid_response(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
        }
    )

    with pytest.raises(ValueError, match="service_id mismatch"):
        app.test_service_endpoint(
            "endpoint-service",
            {"environment": "prod"},
            fetcher=lambda url, auth_header=None: {
                "schema_version": "1.0",
                "service_id": "other-service",
                "environment": "prod",
                "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
            },
        )

    with app.db.connect() as conn:
        row = conn.execute("SELECT collection_status, freshness_status, last_error_code FROM endpoint_health").fetchone()
        assert row["collection_status"] == "invalid_response"
        assert row["freshness_status"] == "stale"
        assert row["last_error_code"] == "invalid_response"


def test_service_endpoint_uses_saved_bearer_token_without_exposing_secret(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
            "status_bearer_token": "endpoint-secret",
        }
    )

    seen_headers = []
    result = app.test_service_endpoint(
        "endpoint-service",
        {"environment": "prod"},
        fetcher=lambda url, auth_header=None: seen_headers.append(auth_header) or {
            "schema_version": "1.0",
            "service_id": "endpoint-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
        },
    )

    assert result["collection_status"] == "ok"
    assert seen_headers == ["Bearer endpoint-secret"]
    service = app.list_services()[0]
    assert service["status_auth_type"] == "bearer_token"
    assert service["status_auth_configured"] is True
    assert "encrypted_auth_config" not in service
    assert "endpoint-secret" not in json.dumps(service)


def test_service_endpoint_missing_bearer_token_records_auth_failed(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
            "status_auth_type": "bearer_token",
        }
    )

    with pytest.raises(PermissionError, match="bearer token is not configured"):
        app.test_service_endpoint("endpoint-service", {"environment": "prod"})

    with app.db.connect() as conn:
        row = conn.execute("SELECT collection_status, last_error_code FROM endpoint_health").fetchone()
        assert row["collection_status"] == "auth_failed"
        assert row["last_error_code"] == "auth_failed"


def test_poll_configured_endpoints_pushes_endpoint_snapshot(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
            "collection_mode": "poll",
        }
    )

    result = poll_configured_endpoints(
        app,
        fetcher=lambda url, auth_header=None: {
            "schema_version": "1.0",
            "service_id": "endpoint-service",
            "environment": "prod",
            "generated_at": "2026-06-11T00:00:00Z",
            "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
        },
    )

    assert result.checked == 1
    assert result.succeeded == 1
    assert result.failed == 0
    assert result.snapshots_created_or_updated == 1
    service = app.list_services()[0]
    assert service["status_endpoint_url"] == "https://endpoint.example.test/dependencies"
    assert service["collection_status"] == "ok"
    assert app.list_impacts({"service_id": ["endpoint-service"]})[0]["package_name"] == "lodash"


def test_poll_configured_endpoints_uses_saved_bearer_token(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
            "collection_mode": "poll",
            "status_bearer_token": "endpoint-secret",
        }
    )
    seen_headers = []

    result = poll_configured_endpoints(
        app,
        fetcher=lambda url, auth_header=None: seen_headers.append(auth_header) or {
            "schema_version": "1.0",
            "service_id": "endpoint-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
        },
    )

    assert result.succeeded == 1
    assert seen_headers == ["Bearer endpoint-secret"]


def test_poll_configured_endpoints_counts_failed_endpoint(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
            "collection_mode": "poll",
        }
    )

    result = poll_configured_endpoints(
        app,
        fetcher=lambda url, auth_header=None: {
            "schema_version": "1.0",
            "service_id": "other-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
        },
    )

    assert result.checked == 1
    assert result.succeeded == 0
    assert result.failed == 1
    assert app.list_services()[0]["collection_status"] == "invalid_response"


def test_endpoint_poll_lock_releases_after_success(tmp_path):
    app = make_test_app(tmp_path)
    app.create_service(
        {
            "service_id": "endpoint-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
            "collection_mode": "poll",
        }
    )

    result = poll_configured_endpoints(
        app,
        worker_name="smoke-worker",
        lock_owner="owner-a",
        fetcher=lambda url, auth_header=None: {
            "schema_version": "1.0",
            "service_id": "endpoint-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
        },
    )

    assert result.succeeded == 1
    with app.db.connect() as conn:
        row = conn.execute("SELECT * FROM endpoint_poll_state WHERE worker_name = 'smoke-worker'").fetchone()
        assert row["status"] == "ok"
        assert row["lock_owner"] is None
        assert row["lock_expires_at"] is None
        assert row["checked_count"] == 1
        assert row["succeeded_count"] == 1
        assert row["failed_count"] == 0
        assert row["last_success_at"] is not None


def test_endpoint_poll_refuses_held_lock(tmp_path):
    app = make_test_app(tmp_path)

    with endpoint_poll_lock(app, "smoke-worker", "owner-a", ttl_seconds=60):
        with pytest.raises(RuntimeError, match="endpoint poll lock is held"):
            poll_configured_endpoints(app, worker_name="smoke-worker", lock_owner="owner-b")

    with app.db.connect() as conn:
        row = conn.execute(
            "SELECT lease_acquire_failures FROM endpoint_poll_state WHERE worker_name = 'smoke-worker'"
        ).fetchone()
    assert row["lease_acquire_failures"] == 1
    assert 'sca_monitor_worker_lease_acquire_failures{worker_type="endpoint_poll",worker="smoke-worker"} 1' in app.metrics()


def test_metrics_exposes_operational_indicators(tmp_path):
    app = make_test_app(tmp_path)
    zip_path = write_osv_fixture_zip(tmp_path)
    sync_osv_ecosystem_dump(app, "npm", zip_path=zip_path, limit=1)
    app.create_service(
        {
            "service_id": "metric-service",
            "environment": "prod",
            "owner_team": "platform",
            "status_endpoint_url": "https://endpoint.example.test/dependencies",
            "collection_mode": "poll",
        }
    )
    poll_configured_endpoints(
        app,
        worker_name="metric-worker",
        fetcher=lambda url, auth_header=None: {
            "schema_version": "1.0",
            "service_id": "metric-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        },
    )
    dispatch_pending_alerts(app, webhook_url="https://alerts.example.test/webhook", sender=lambda url, payload: None)
    with app.db.connect() as conn:
        conn.execute("UPDATE advisories SET first_seen_at = '2026-01-01T00:00:00+00:00'")
        conn.execute("UPDATE alert_events SET created_at = '2026-01-01T00:00:42+00:00' WHERE reason = 'new'")
    app.record_advisory_sync("GHSA", "error", "GHSA-TEST", "rate limit")

    metrics = app.metrics()

    assert "sca_monitor_advisory_sync_ready 0" in metrics
    assert 'sca_monitor_advisory_sync_initialized{source="OSV"} 1' in metrics
    assert 'sca_monitor_advisory_sync_initialized{source="CISA_KEV"} 0' in metrics
    assert 'sca_monitor_advisory_sync_initialized{source="OpenSSF"} 0' in metrics
    assert 'sca_monitor_advisory_sync_lag_seconds{source="OSV"}' in metrics
    assert 'sca_monitor_advisory_sync_failed{source="GHSA"} 1' in metrics
    assert 'sca_monitor_advisory_sync_last_error_age_seconds{source="GHSA"}' in metrics
    assert "new_advisory_to_alert_latency_seconds 42" in metrics
    assert 'sca_monitor_endpoint_poll_success_rate{worker="metric-worker"} 1.000000' in metrics
    assert "sca_monitor_endpoint_poll_success_rate 1.000000" in metrics
    assert "sca_monitor_alert_delivery_success_rate 1.000000" in metrics
    assert "sca_monitor_alert_outbox_pending_count 1" in metrics
    assert "sca_monitor_alert_readiness_ready 0" in metrics
    assert "sca_monitor_stale_services 0" in metrics
    assert "sca_monitor_sla_overdue_impacts 0" in metrics
    assert "sca_monitor_database_ready 1" in metrics
    assert 'sca_monitor_database_backend_info{backend="sqlite"} 1' in metrics
    assert f"sca_monitor_migration_current_version {REQUIRED_MIGRATION_VERSION}" in metrics
    assert f"sca_monitor_migration_required_version {REQUIRED_MIGRATION_VERSION}" in metrics
    assert "sca_monitor_migration_compatible 1" in metrics
    assert "sca_monitor_postgres_configured 0" in metrics
    assert 'sca_monitor_postgres_cutover_status{mode="sqlite_fallback",status="sqlite_fallback"} 1' in metrics
    assert "sca_monitor_postgres_cutover_required_ready 0" in metrics
    assert "sca_monitor_postgres_cutover_blockers 1" in metrics
    assert "sca_monitor_postgres_split_required 0" in metrics
    assert "sca_monitor_postgres_split_ready 0" in metrics


def test_advisory_sync_error_enqueues_deduplicated_system_alert(tmp_path):
    app = make_test_app(tmp_path)

    app.record_advisory_sync("GHSA", "error", "GHSA-TEST", "rate limit")
    app.record_advisory_sync("GHSA", "error", "GHSA-TEST", "rate limit")

    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT impact_pk, reason, status, alert_suppression_key, payload
            FROM alert_events
            WHERE reason = 'system_advisory_sync_failed'
            """
        ).fetchall()

    assert len(rows) == 1
    row = rows[0]
    assert row["impact_pk"] is None
    assert row["status"] == "pending"
    assert row["alert_suppression_key"] == "system:advisory_sync:GHSA:failed"
    payload = json.loads(row["payload"])
    assert payload["source"] == "GHSA"
    assert payload["advisory_id"] == "GHSA-TEST"
    assert payload["error_message"] == "rate limit"


def test_advisory_sync_success_resolves_active_system_alert_and_allows_new_failure(tmp_path):
    app = make_test_app(tmp_path)

    app.record_advisory_sync("GHSA", "error", "GHSA-TEST", "rate limit")
    app.record_advisory_sync("GHSA", "ok", "GHSA-TEST", None)
    app.record_advisory_sync("GHSA", "error", "GHSA-TEST-2", "gateway timeout")

    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT status, alert_suppression_key, payload
            FROM alert_events
            WHERE reason = 'system_advisory_sync_failed'
            ORDER BY created_at ASC
            """
        ).fetchall()

    assert [row["status"] for row in rows] == ["resolved", "pending"]
    assert all(row["alert_suppression_key"] == "system:advisory_sync:GHSA:failed" for row in rows)
    resolved_payload = json.loads(rows[0]["payload"])
    assert resolved_payload["resolved_at"] is not None
    assert resolved_payload["resolved_by_status"] == "ok"
    pending_payload = json.loads(rows[1]["payload"])
    assert pending_payload["advisory_id"] == "GHSA-TEST-2"
    assert pending_payload["error_message"] == "gateway timeout"


def test_overview_counts_pending_system_alerts(tmp_path):
    app = make_test_app(tmp_path)

    app.record_advisory_sync("GHSA", "error", "GHSA-TEST", "rate limit")

    overview = app.overview()

    assert overview["alert_readiness"]["pending_count"] == 1
    assert overview["alert_readiness"]["system_pending_count"] == 1


def test_overview_exposes_alert_readiness_summary(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default-secret", "is_default": True})

    overview = app.overview()

    assert overview["alert_readiness"]["status"] == "action_required"
    assert overview["alert_readiness"]["default_channel_configured"] is True
    assert overview["alert_readiness"]["default_channel_placeholder"] is True
    assert overview["alert_readiness"]["default_channel_target_masked"] == "https://alerts.example.test/..."
    assert overview["alert_readiness"]["pending_count"] == 1
    assert overview["alert_readiness"]["dead_letter_count"] == 0


def test_overview_alert_readiness_ready_with_real_default_channel(tmp_path):
    app = make_test_app(tmp_path)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.internal/default-secret", "is_default": True})

    overview = app.overview()

    assert overview["alert_readiness"]["status"] == "ready"
    assert overview["alert_readiness"]["default_channel_configured"] is True
    assert overview["alert_readiness"]["default_channel_placeholder"] is False
    assert overview["alert_readiness"]["pending_count"] == 0


def test_overview_exposes_advisory_sync_readiness_initializing(tmp_path):
    app = make_test_app(tmp_path)

    overview = app.overview()

    assert overview["advisory_sync"]["OSV"] == "seeded-demo"
    assert overview["advisory_sync_readiness"]["status"] == "initializing"
    assert overview["advisory_sync_readiness"]["required_count"] == 3
    assert overview["advisory_sync_readiness"]["initialized_count"] == 0
    sources = {item["source"]: item for item in overview["advisory_sync_readiness"]["sources"]}
    assert sources["OSV"]["status"] == "pending"
    assert sources["OSV"]["initialized"] is False
    assert sources["CISA_KEV"]["status"] == "pending"
    assert sources["OpenSSF"]["status"] == "pending"


def test_overview_advisory_sync_readiness_ready_when_initial_sources_succeed(tmp_path):
    app = make_test_app(tmp_path)

    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "ok", "npm:dump", None, imported_count=1)

    overview = app.overview()
    metrics = app.metrics()

    assert overview["advisory_sync_readiness"]["status"] == "ready"
    assert overview["advisory_sync_readiness"]["initialized_count"] == 3
    assert all(item["initialized"] for item in overview["advisory_sync_readiness"]["sources"])
    assert "sca_monitor_advisory_sync_ready 1" in metrics
    assert 'sca_monitor_advisory_sync_initialized{source="OpenSSF"} 1' in metrics


def test_overview_advisory_sync_readiness_summarizes_stale_and_failed_sources(tmp_path):
    app = make_test_app(tmp_path)

    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "partial", "npm:dump", "scan limit reached", imported_count=0)
    with app.db.connect() as conn:
        conn.execute("UPDATE advisory_sync_state SET last_success_at = '2026-01-01T00:00:00+00:00' WHERE source = 'OSV'")

    overview = app.overview()
    freshness = overview["advisory_sync_readiness"]["freshness"]
    sources = {item["source"]: item for item in overview["advisory_sync_readiness"]["sources"]}

    assert overview["advisory_sync_readiness"]["status"] == "degraded"
    assert freshness["status"] == "degraded"
    assert freshness["stale_after_seconds"] == 86400
    assert freshness["stale_count"] == 1
    assert freshness["partial_count"] == 1
    assert freshness["failed_count"] == 0
    assert freshness["oldest_source"] == "OSV"
    assert freshness["max_lag_seconds"] > 86400
    assert sources["OSV"]["freshness_status"] == "stale"
    assert sources["CISA_KEV"]["freshness_status"] == "fresh"
    assert sources["OpenSSF"]["freshness_status"] == "partial"


def test_overview_advisory_sync_readiness_uses_configured_stale_threshold(tmp_path):
    app = make_test_app(tmp_path, advisory_sync_stale_after_seconds=30)

    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "ok", "npm:dump", None, imported_count=1)
    with app.db.connect() as conn:
        conn.execute("UPDATE advisory_sync_state SET last_success_at = '2026-01-01T00:00:00+00:00' WHERE source = 'OSV'")

    readiness = app.overview()["advisory_sync_readiness"]
    sources = {item["source"]: item for item in readiness["sources"]}

    assert readiness["status"] == "ready"
    assert readiness["freshness"]["status"] == "stale"
    assert readiness["freshness"]["stale_after_seconds"] == 30
    assert readiness["freshness"]["stale_count"] == 1
    assert sources["OSV"]["freshness_status"] == "stale"


def test_advisory_sync_stale_alert_enqueues_once_and_resolves(tmp_path):
    app = make_test_app(tmp_path, advisory_sync_stale_after_seconds=30)
    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "ok", "npm:dump", None, imported_count=1)
    with app.db.connect() as conn:
        conn.execute("UPDATE advisory_sync_state SET last_success_at = '2026-01-01T00:00:00+00:00' WHERE source = 'OSV'")

    dry_run = app.evaluate_advisory_sync_freshness_alerts(now="2026-01-01T00:01:00+00:00", dry_run=True, actor="freshness-scheduler")
    result = app.evaluate_advisory_sync_freshness_alerts(now="2026-01-01T00:01:00+00:00", actor="freshness-scheduler")
    second = app.evaluate_advisory_sync_freshness_alerts(now="2026-01-01T00:01:00+00:00", actor="freshness-scheduler")
    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=0)
    resolved = app.evaluate_advisory_sync_freshness_alerts(now="2026-01-01T00:01:10+00:00", actor="freshness-scheduler")

    assert dry_run["stale_sources"] == ["OSV"]
    assert dry_run["enqueued"] == 0
    assert result["stale_sources"] == ["OSV"]
    assert result["enqueued"] == 1
    assert second["enqueued"] == 0
    assert resolved["resolved"] == 1
    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT impact_pk, reason, status, alert_suppression_key, payload
            FROM alert_events
            WHERE reason = 'system_advisory_sync_stale'
            """
        ).fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["impact_pk"] is None
    assert row["status"] == "resolved"
    assert row["alert_suppression_key"] == "system:advisory_sync:OSV:stale"
    payload = json.loads(row["payload"])
    assert payload["source"] == "OSV"
    assert payload["stale_after_seconds"] == 30
    assert payload["resolved_at"] is not None
    audit = app.search_audit_logs({"action": ["advisory_sync.stale.enqueue"], "target_id": ["OSV"]})
    assert audit["pagination"]["total"] == 1


def test_evaluate_advisory_sync_freshness_cli(tmp_path):
    app = make_test_app(tmp_path, advisory_sync_stale_after_seconds=30)
    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "ok", "npm:dump", None, imported_count=1)
    with app.db.connect() as conn:
        conn.execute("UPDATE advisory_sync_state SET last_success_at = '2026-01-01T00:00:00+00:00' WHERE source = 'OSV'")
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
        "SCA_MONITOR_ADVISORY_SYNC_STALE_AFTER_SECONDS": "30",
    }

    result = subprocess.run(
        ["python3", "scripts/evaluate_advisory_sync_freshness.py", "--now", "2026-01-01T00:01:00+00:00", "--actor", "freshness-scheduler"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["stale_sources"] == ["OSV"]
    assert payload["enqueued"] == 1
    with app.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM alert_events WHERE reason = 'system_advisory_sync_stale'").fetchone()["c"] == 1


def test_overview_advisory_sync_readiness_degraded_on_source_error(tmp_path):
    app = make_test_app(tmp_path)

    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "error", "catalog", "rate limited", imported_count=0)

    overview = app.overview()

    assert overview["advisory_sync_readiness"]["status"] == "degraded"
    sources = {item["source"]: item for item in overview["advisory_sync_readiness"]["sources"]}
    assert sources["OSV"]["initialized"] is True
    assert sources["CISA_KEV"]["initialized"] is False
    assert sources["CISA_KEV"]["last_error_message"] == "rate limited"


def test_bootstrap_readiness_check_cli_blocks_until_advisory_sync_ready(tmp_path):
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
    }

    result = subprocess.run(
        ["python3", "scripts/bootstrap_readiness_check.py", "--json", "--skip-alert-activation"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert payload["blocking_failures"] == ["advisory_initial_sync_ready"]
    assert payload["advisory_sync_readiness"]["status"] == "initializing"


def test_bootstrap_readiness_check_cli_ready_after_initial_sources_and_alert_channel(tmp_path):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "ok", "npm:dump", None, imported_count=1)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.internal/default-secret", "is_default": True})
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
    }

    result = subprocess.run(
        ["python3", "scripts/bootstrap_readiness_check.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ready"
    assert payload["blocking_failures"] == []
    assert payload["advisory_sync_readiness"]["status"] == "ready"
    assert payload["alert_dispatcher_activation"]["status"] == "ready"


def test_bootstrap_readiness_check_cli_can_skip_alert_activation(tmp_path):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "ok", "npm:dump", None, imported_count=1)
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
    }

    result = subprocess.run(
        ["python3", "scripts/bootstrap_readiness_check.py", "--json", "--skip-alert-activation"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ready"
    assert "alert_dispatcher_activation" not in payload


def test_bootstrap_readiness_check_cli_blocks_stale_advisory_freshness_when_required(tmp_path):
    app = make_test_app(tmp_path, advisory_sync_stale_after_seconds=30)
    app.record_advisory_sync("OSV", "ok", "npm:dump", None, imported_count=1)
    app.record_advisory_sync("CISA_KEV", "ok", "catalog:test", None, imported_count=1)
    app.record_advisory_sync("OpenSSF", "ok", "npm:dump", None, imported_count=1)
    with app.db.connect() as conn:
        conn.execute("UPDATE advisory_sync_state SET last_success_at = '2026-01-01T00:00:00+00:00' WHERE source = 'OSV'")
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
        "SCA_MONITOR_ADVISORY_SYNC_STALE_AFTER_SECONDS": "30",
    }

    result = subprocess.run(
        ["python3", "scripts/bootstrap_readiness_check.py", "--json", "--skip-alert-activation", "--require-advisory-freshness"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert payload["blocking_failures"] == ["advisory_freshness_ready"]
    assert payload["advisory_sync_readiness"]["freshness"]["status"] == "stale"


def test_bootstrap_advisory_sync_cli_initializes_required_sources(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}"
    cisa_path = tmp_path / "cisa-kev.json"
    cisa_path.write_text(json.dumps(cisa_kev_fixture()), encoding="utf-8")
    zip_path = tmp_path / "advisories.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("OSV-TEST-0001.json", json.dumps(osv_fixture()))
        archive.writestr("MAL-2026-0001.json", json.dumps(malicious_osv_fixture()))

    result = subprocess.run(
        [
            "python3",
            "scripts/bootstrap_advisory_sync.py",
            "--json",
            "--osv-zip-path",
            str(zip_path),
            "--openssf-zip-path",
            str(zip_path),
            "--cisa-json-path",
            str(cisa_path),
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert [task["status"] for task in payload["tasks"]] == ["ok", "ok", "ok"]
    assert payload["advisory_sync_readiness"]["status"] == "ready"
    app = ScaMonitorApp(
        Settings(
            app_env="test",
            host="127.0.0.1",
            port=0,
            data_dir=tmp_path,
            database_url=database_url,
            database_path=tmp_path / "sca-monitor.sqlite3",
            frontend_dir=tmp_path,
            smoke_token="test",
        )
    )
    assert app.overview()["advisory_sync_readiness"]["initialized_count"] == 3


def test_bootstrap_advisory_sync_cli_blocks_on_partial_source(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}"
    cisa_path = tmp_path / "cisa-kev.json"
    cisa_path.write_text(json.dumps(cisa_kev_fixture()), encoding="utf-8")
    zip_path = tmp_path / "advisories.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("AAA-OSV-TEST-0001.json", json.dumps(osv_fixture()))
        archive.writestr("MAL-2026-0001.json", json.dumps(malicious_osv_fixture()))

    result = subprocess.run(
        [
            "python3",
            "scripts/bootstrap_advisory_sync.py",
            "--json",
            "--osv-zip-path",
            str(zip_path),
            "--openssf-zip-path",
            str(zip_path),
            "--openssf-scan-limit",
            "1",
            "--cisa-json-path",
            str(cisa_path),
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["blocking_sources"] == ["openssf"]
    assert payload["tasks"][2]["status"] == "partial"


def test_impacts_expose_sla_deadline_and_overdue_metrics(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        impact_id = conn.execute("SELECT id FROM impacts").fetchone()["id"]
        conn.execute(
            """
            UPDATE impacts
            SET first_detected_at = '2026-01-01T00:00:00+00:00',
                risk_level = 'critical',
                status = 'open'
            WHERE id = ?
            """,
            (impact_id,),
        )

    page = app.search_impacts({})
    impact = page["impacts"][0]
    detail = app.get_impact(impact_id)
    metrics = app.metrics()

    assert impact["sla"]["policy_hours"] == 24
    assert impact["sla"]["deadline_at"] == "2026-01-02T00:00:00+00:00"
    assert impact["sla"]["overdue"] is True
    assert detail["impact"]["sla"]["overdue"] is True
    assert app.overview()["sla_overdue_impacts"] == 1
    assert "sca_monitor_sla_overdue_impacts 1" in metrics


def test_fixed_impacts_are_not_sla_overdue(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        impact_id = conn.execute("SELECT id FROM impacts").fetchone()["id"]
        conn.execute(
            """
            UPDATE impacts
            SET first_detected_at = '2026-01-01T00:00:00+00:00',
                risk_level = 'critical',
                status = 'fixed'
            WHERE id = ?
            """,
            (impact_id,),
        )

    impact = app.search_impacts({})["impacts"][0]

    assert impact["sla"]["overdue"] is False
    assert app.overview()["sla_overdue_impacts"] == 0


def test_sla_escalation_enqueues_pending_alert_once_and_audits(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        impact_id = conn.execute("SELECT id FROM impacts").fetchone()["id"]
        conn.execute(
            """
            UPDATE impacts
            SET first_detected_at = '2026-01-01T00:00:00+00:00',
                risk_level = 'critical',
                status = 'open'
            WHERE id = ?
            """,
            (impact_id,),
        )

    dry_run = app.enqueue_sla_expired_alerts(now="2026-01-03T00:00:00+00:00", dry_run=True, actor="sla-scheduler")
    result = app.enqueue_sla_expired_alerts(now="2026-01-03T00:00:00+00:00", actor="sla-scheduler")
    second = app.enqueue_sla_expired_alerts(now="2026-01-03T00:00:00+00:00", actor="sla-scheduler")

    assert dry_run["candidates"] == 1
    assert dry_run["enqueued"] == 0
    assert result["candidates"] == 1
    assert result["enqueued"] == 1
    assert second["candidates"] == 1
    assert second["enqueued"] == 0
    with app.db.connect() as conn:
        events = conn.execute("SELECT reason, status, payload FROM alert_events ORDER BY reason").fetchall()
    assert {row["reason"] for row in events} == {"new", "sla_expired"}
    sla_event = next(row for row in events if row["reason"] == "sla_expired")
    sla_payload = json.loads(sla_event["payload"])
    assert sla_payload["reason"] == "sla_expired"
    assert sla_payload["sla"]["overdue"] is True
    audit = app.search_audit_logs({"action": ["sla.escalation.enqueue"], "target_id": [impact_id]})
    assert audit["pagination"]["total"] == 1


def test_evaluate_sla_escalations_cli(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        impact_id = conn.execute("SELECT id FROM impacts").fetchone()["id"]
        conn.execute(
            """
            UPDATE impacts
            SET first_detected_at = '2026-01-01T00:00:00+00:00',
                risk_level = 'critical',
                status = 'open'
            WHERE id = ?
            """,
            (impact_id,),
        )
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
    }

    result = subprocess.run(
        ["python3", "scripts/evaluate_sla_escalations.py", "--now", "2026-01-03T00:00:00+00:00", "--actor", "sla-scheduler"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["enqueued"] == 1
    with app.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM alert_events WHERE reason = 'sla_expired'").fetchone()["c"] == 1


def test_daily_digest_enqueues_pending_alert_once_and_audits(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        impact_id = conn.execute("SELECT id FROM impacts").fetchone()["id"]
        conn.execute("UPDATE impacts SET risk_level = 'medium', status = 'open' WHERE id = ?", (impact_id,))

    dry_run = app.enqueue_daily_digest_alert(now="2026-01-03T00:00:00+00:00", dry_run=True, actor="digest-scheduler")
    result = app.enqueue_daily_digest_alert(now="2026-01-03T00:00:00+00:00", actor="digest-scheduler")
    second = app.enqueue_daily_digest_alert(now="2026-01-03T00:00:00+00:00", actor="digest-scheduler")

    assert dry_run["digest_date"] == "2026-01-03"
    assert dry_run["matched"] == 1
    assert dry_run["enqueued"] == 0
    assert result["matched"] == 1
    assert result["enqueued"] == 1
    assert second["matched"] == 1
    assert second["enqueued"] == 0
    with app.db.connect() as conn:
        row = conn.execute("SELECT impact_pk, reason, status, alert_suppression_key, payload FROM alert_events WHERE reason = 'daily_digest'").fetchone()
    assert row["impact_pk"] is None
    assert row["status"] == "pending"
    assert row["alert_suppression_key"] == "daily_digest:2026-01-03:all"
    payload = json.loads(row["payload"])
    assert payload["reason"] == "daily_digest"
    assert payload["digest"]["date"] == "2026-01-03"
    assert payload["items"][0]["impact_id"] == impact_id
    assert payload["items"][0]["risk_level"] == "medium"
    audit = app.search_audit_logs({"action": ["daily_digest.enqueue"], "target_id": ["daily_digest:2026-01-03:all"]})
    assert audit["pagination"]["total"] == 1


def test_daily_digest_includes_non_production_high_impact(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        conn.execute("UPDATE services SET environment = 'stage'")
        conn.execute("UPDATE impacts SET risk_level = 'high', environment = 'stage', status = 'open'")

    result = app.enqueue_daily_digest_alert(now="2026-01-03T00:00:00+00:00", actor="digest-scheduler")

    assert result["matched"] == 1
    assert result["enqueued"] == 1
    assert result["items"][0]["risk_level"] == "high"
    assert result["items"][0]["environment"] == "stage"


def test_daily_digest_can_scope_to_owner_team(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "platform-service",
            "service_name": "Platform Service",
            "environment": "prod",
            "owner_team": "platform",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    app.push_snapshot(
        {
            "service_id": "billing-service",
            "service_name": "Billing Service",
            "environment": "prod",
            "owner_team": "billing",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    with app.db.connect() as conn:
        conn.execute("UPDATE impacts SET risk_level = 'medium', status = 'open'")

    result = app.enqueue_daily_digest_alert(
        now="2026-01-03T00:00:00+00:00",
        owner_team="platform",
        actor="digest-scheduler",
    )

    assert result["matched"] == 1
    assert result["enqueued"] == 1
    assert result["owner_team"] == "platform"
    assert result["alert_suppression_key"] == "daily_digest:2026-01-03:team:platform"
    assert result["items"][0]["service_id"] == "platform-service"
    with app.db.connect() as conn:
        row = conn.execute("SELECT payload FROM alert_events WHERE reason = 'daily_digest'").fetchone()
    payload = json.loads(row["payload"])
    assert payload["digest"]["scope"] == "owner_team"
    assert payload["digest"]["owner_team"] == "platform"
    assert [item["service_id"] for item in payload["items"]] == ["platform-service"]


def test_create_daily_digest_cli(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        conn.execute("UPDATE impacts SET risk_level = 'low', status = 'open'")
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
    }

    result = subprocess.run(
        ["python3", "scripts/create_daily_digest.py", "--now", "2026-01-03T00:00:00+00:00", "--actor", "digest-scheduler"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["enqueued"] == 1
    assert payload["digest_date"] == "2026-01-03"
    with app.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM alert_events WHERE reason = 'daily_digest'").fetchone()["c"] == 1


def test_daily_digest_preview_route_is_dry_run(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        conn.execute("UPDATE impacts SET risk_level = 'medium', status = 'open'")

    with run_test_server(app) as base_url:
        payload = http_json(
            f"{base_url}/api/v1/alerts/daily-digest/preview",
            method="POST",
            body={"date": "2026-01-03", "timezone": "Asia/Seoul", "limit": 25},
        )

    assert payload["dry_run"] is True
    assert payload["matched"] == 1
    assert payload["enqueued"] == 0
    assert payload["alert_suppression_key"] == "daily_digest:2026-01-03:all"
    with app.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM alert_events WHERE reason = 'daily_digest'").fetchone()["c"] == 0


def test_daily_digest_preview_route_requires_admin_in_header_auth(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    create_alerting_impact(app)

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/alerts/daily-digest/preview",
            method="POST",
            body={"date": "2026-01-03"},
            headers={"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"},
            expect_status=403,
        )
        allowed = http_json(
            f"{base_url}/api/v1/alerts/daily-digest/preview",
            method="POST",
            body={"date": "2026-01-03"},
            headers={"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"},
        )

    assert "admin role" in forbidden["error"]
    assert allowed["dry_run"] is True


def test_parse_osv_advisory_fixture():
    advisories = parse_osv_advisories(osv_fixture())

    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory.advisory_id == "OSV-TEST-0001"
    assert advisory.source == "OSV"
    assert advisory.ecosystem == "npm"
    assert advisory.package_name == "example-package"
    assert advisory.affected_versions == ["1.0.0", "1.0.1"]
    assert advisory.affected_ranges == [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}]}]
    assert advisory.fixed_version == "1.0.2"


def test_version_is_affected_by_osv_range():
    affected_ranges = [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]

    assert version_is_affected("4.17.20", [], affected_ranges) is True
    assert version_is_affected("4.17.21", [], affected_ranges) is False
    assert version_is_affected("3.10.0", [], affected_ranges) is False


def test_parse_multi_package_osv_advisory_uses_package_scoped_ids():
    payload = osv_fixture()
    payload["affected"].append(
        {
            "package": {"ecosystem": "Maven", "name": "org.example:example-package"},
            "versions": ["1.0.0"],
        }
    )

    advisories = parse_osv_advisories(payload)

    assert {advisory.advisory_id for advisory in advisories} == {
        "OSV-TEST-0001:npm/example-package",
        "OSV-TEST-0001:Maven/org.example:example-package",
    }


def test_parse_osv_moderate_severity_as_medium():
    payload = osv_fixture()
    payload["affected"][0]["database_specific"]["severity"] = "MODERATE"

    advisories = parse_osv_advisories(payload)

    assert advisories[0].severity == "medium"


def test_parse_osv_uses_payload_severity_when_affected_specific_has_no_severity():
    payload = osv_fixture()
    payload["database_specific"] = {"severity": "MODERATE"}
    payload["affected"][0]["database_specific"] = {"github_reviewed": True}

    advisories = parse_osv_advisories(payload)

    assert advisories[0].severity == "medium"


def test_parse_malicious_osv_advisory_as_openssf_source():
    advisories = parse_osv_advisories(malicious_osv_fixture())

    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory.advisory_id == "MAL-2026-0001"
    assert advisory.source == "OpenSSF"
    assert advisory.is_malicious_package is True
    assert advisory.severity == "critical"


def test_import_osv_payload_updates_advisory_and_sync_state(tmp_path):
    app = make_test_app(tmp_path)

    result = app.import_osv_payload(osv_fixture())

    assert result["imported"] == 1
    assert result["changed"] == 1
    advisories = app.list_advisories({"source": ["OSV"]})
    advisory = next(advisory for advisory in advisories if advisory["advisory_id"] == "OSV-TEST-0001")
    assert advisory["affected_ranges"] == [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}]}]
    overview = app.overview()
    assert overview["advisory_sync"]["OSV"] == "ok"


def test_import_osv_payload_syncs_advisory_aliases(tmp_path):
    app = make_test_app(tmp_path)

    app.import_osv_payload(osv_fixture())

    advisory = next(item for item in app.list_advisories({"source": ["OSV"]}) if item["advisory_id"] == "OSV-TEST-0001")
    assert advisory["aliases"] == [
        {"alias_type": "CVE", "alias_value": "CVE-2026-0001"},
        {"alias_type": "OSV", "alias_value": "OSV-TEST-0001"},
    ]
    with app.db.connect() as conn:
        rows = conn.execute(
            """
            SELECT aa.alias_type, aa.alias_value
            FROM advisory_aliases aa
            JOIN advisories a ON a.id = aa.advisory_pk
            WHERE a.advisory_id = 'OSV-TEST-0001'
            ORDER BY aa.alias_type, aa.alias_value
            """
        ).fetchall()
    assert [row_to_dict(row) for row in rows] == advisory["aliases"]


def test_merge_canonical_advisory_rows_preserves_aliases_and_audit(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")
    sync_github_advisories(app, json_path=ghsa_path, limit=1)

    dry_run = app.merge_canonical_advisory_rows(limit=10, dry_run=True)
    result = app.merge_canonical_advisory_rows(limit=10, actor="test-merge")

    assert dry_run["candidates"] == 1
    assert dry_run["items"][0]["target_advisory_id"] == "OSV-TEST-0001"
    assert dry_run["items"][0]["source_advisory_ids"] == ["GHSA-xxxx-yyyy-zzzz"]
    assert result["status"] == "ok"
    assert result["merged_advisories"] == 1
    with app.db.connect() as conn:
        advisories = conn.execute(
            """
            SELECT advisory_id, source
            FROM advisories
            WHERE advisory_id IN ('OSV-TEST-0001', 'GHSA-xxxx-yyyy-zzzz')
            ORDER BY advisory_id
            """
        ).fetchall()
        aliases = conn.execute(
            """
            SELECT aa.alias_type, aa.alias_value
            FROM advisory_aliases aa
            JOIN advisories a ON a.id = aa.advisory_pk
            WHERE a.advisory_id = 'OSV-TEST-0001'
            ORDER BY aa.alias_type, aa.alias_value
            """
        ).fetchall()
        audit = conn.execute(
            """
            SELECT actor, action, target_type, target_id, reason
            FROM audit_logs
            WHERE action = 'advisory.merge'
            """
        ).fetchone()
    assert [row_to_dict(row) for row in advisories] == [{"advisory_id": "OSV-TEST-0001", "source": "OSV"}]
    assert [row_to_dict(row) for row in aliases] == [
        {"alias_type": "CVE", "alias_value": "CVE-2026-0001"},
        {"alias_type": "GHSA", "alias_value": "GHSA-XXXX-YYYY-ZZZZ"},
        {"alias_type": "OSV", "alias_value": "OSV-TEST-0001"},
    ]
    assert row_to_dict(audit) == {
        "actor": "test-merge",
        "action": "advisory.merge",
        "target_type": "advisory",
        "target_id": "OSV-TEST-0001",
        "reason": "canonical advisory alias merge",
    }


def test_range_only_osv_advisory_matches_snapshot(tmp_path):
    app = make_test_app(tmp_path)
    payload = osv_fixture()
    payload["affected"][0]["versions"] = []

    app.import_osv_payload(payload)
    result = app.push_snapshot(
        {
            "service_id": "range-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )

    assert result["impacts_created_or_updated"] == 1
    impacts = app.list_impacts({})
    assert len(impacts) == 1
    assert impacts[0]["advisory_id"] == "OSV-TEST-0001"


def test_advisory_import_rematches_existing_latest_snapshot(tmp_path):
    app = make_test_app(tmp_path)
    app.push_snapshot(
        {
            "service_id": "pre-existing-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    before = [impact for impact in app.list_impacts({}) if impact["service_id"] == "pre-existing-service"]
    assert before == []

    payload = osv_fixture()
    payload["affected"][0]["versions"] = []
    result = app.import_osv_payload(payload)

    assert result["imported"] == 1
    assert result["changed"] == 1
    assert result["rematched_impacts"] == 1
    impacts = [impact for impact in app.list_impacts({}) if impact["service_id"] == "pre-existing-service"]
    assert len(impacts) == 1
    assert impacts[0]["advisory_id"] == "OSV-TEST-0001"


def test_alias_related_advisories_share_canonical_impact_identity(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")
    sync_github_advisories(app, json_path=ghsa_path, limit=1)

    result = app.push_snapshot(
        {
            "service_id": "canonical-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )

    assert result["impacts_created_or_updated"] == 2
    impacts = app.search_impacts({"service_id": ["canonical-service"]})["impacts"]
    assert len(impacts) == 1
    assert impacts[0]["advisory_id"] == "OSV-TEST-0001"
    assert impacts[0]["alert_suppression_key"].startswith("canonical-service:prod:OSV-TEST-0001:example-package:")
    with app.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM alert_events").fetchone()["c"] == 1
        row = conn.execute("SELECT impact_identity, alert_suppression_key FROM impacts").fetchone()
    assert row["impact_identity"] == "canonical-service:prod:OSV-TEST-0001:example-package"
    assert row["alert_suppression_key"] == "canonical-service:prod:OSV-TEST-0001:example-package:high:open"


def test_backfill_canonical_impact_keys_updates_legacy_identity_and_alert(tmp_path):
    app = make_test_app(tmp_path)
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")
    sync_github_advisories(app, json_path=ghsa_path, limit=1)
    app.push_snapshot(
        {
            "service_id": "legacy-canonical-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    with app.db.connect() as conn:
        legacy = conn.execute("SELECT id, impact_identity, alert_suppression_key FROM impacts").fetchone()
        assert legacy["impact_identity"] == "legacy-canonical-service:prod:GHSA-xxxx-yyyy-zzzz:example-package"
        app.upsert_advisory(conn, parse_osv_advisories(osv_fixture())[0])

    dry_run = app.backfill_canonical_impact_keys(limit=10, dry_run=True)
    result = app.backfill_canonical_impact_keys(limit=10, actor="test-backfill")

    assert dry_run["candidates"] == 1
    assert dry_run["updated"] == 0
    assert result["status"] == "ok"
    assert result["updated"] == 1
    with app.db.connect() as conn:
        impact = conn.execute("SELECT impact_identity, alert_suppression_key FROM impacts").fetchone()
        alert = conn.execute("SELECT alert_suppression_key FROM alert_events").fetchone()
        history = conn.execute("SELECT actor, reason FROM impact_history").fetchone()
    assert impact["impact_identity"] == "legacy-canonical-service:prod:OSV-TEST-0001:example-package"
    assert impact["alert_suppression_key"] == "legacy-canonical-service:prod:OSV-TEST-0001:example-package:high:open"
    assert alert["alert_suppression_key"] == impact["alert_suppression_key"]
    assert history["actor"] == "test-backfill"
    assert history["reason"] == "canonical impact key backfill"


def test_backfill_canonical_impact_keys_merges_conflicting_legacy_impact(tmp_path):
    app = make_test_app(tmp_path)
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")
    sync_github_advisories(app, json_path=ghsa_path, limit=1)
    app.push_snapshot(
        {
            "service_id": "merge-canonical-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    with app.db.connect() as conn:
        legacy = conn.execute("SELECT id FROM impacts WHERE impact_identity LIKE '%GHSA-xxxx-yyyy-zzzz%'").fetchone()
    app.update_impact_status(legacy["id"], {"status": "acknowledged", "actor": "analyst", "reason": "triage started"})
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "merge-canonical-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )

    dry_run = app.backfill_canonical_impact_keys(limit=10, dry_run=True)
    result = app.backfill_canonical_impact_keys(limit=10, actor="merge-backfill")

    assert dry_run["candidates"] == 1
    assert dry_run["items"][0]["action"] == "merge"
    assert dry_run["merged"] == 0
    assert result["status"] == "ok"
    assert result["merged"] == 1
    assert result["conflicts"] == 0
    with app.db.connect() as conn:
        impacts = conn.execute("SELECT id, impact_identity, alert_suppression_key, status FROM impacts").fetchall()
        alert_events = conn.execute("SELECT impact_pk, alert_suppression_key FROM alert_events").fetchall()
        history = conn.execute(
            """
            SELECT actor, reason
            FROM impact_history
            ORDER BY created_at ASC
            """
        ).fetchall()
    assert len(impacts) == 1
    impact = impacts[0]
    assert impact["impact_identity"] == "merge-canonical-service:prod:OSV-TEST-0001:example-package"
    assert impact["alert_suppression_key"] == "merge-canonical-service:prod:OSV-TEST-0001:example-package:high:open"
    assert impact["status"] == "open"
    assert len(alert_events) == 2
    assert {row["impact_pk"] for row in alert_events} == {impact["id"]}
    assert {row["alert_suppression_key"] for row in alert_events} == {impact["alert_suppression_key"]}
    assert any(row["actor"] == "analyst" and row["reason"] == "triage started" for row in history)
    assert any(row["actor"] == "merge-backfill" and row["reason"].startswith("canonical impact merge from ") for row in history)


def test_service_detail_includes_snapshot_dependencies_and_impacts(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "detail-service",
            "service_name": "Detail Service",
            "environment": "prod",
            "dependencies": [
                {"ecosystem": "npm", "name": "example-package", "version": "1.0.1", "direct": True},
                {"ecosystem": "PyPI", "name": "Django_REST.Framework", "version": "3.14.0"},
            ],
        }
    )

    detail = app.get_service_detail("detail-service")

    assert detail["service"]["service_id"] == "detail-service"
    assert detail["latest_snapshot"]["snapshot_id"].startswith("detail-service-")
    assert detail["dependency_summary"] == [{"ecosystem": "PyPI", "count": 1}, {"ecosystem": "npm", "count": 1}]
    assert len(detail["dependencies"]) == 2
    npm_dep = next(dep for dep in detail["dependencies"] if dep["ecosystem"] == "npm")
    assert npm_dep["canonical_package_name"] == "example-package"
    assert npm_dep["direct_dependency"] is True
    assert len(detail["impacts"]) == 1
    assert detail["impacts"][0]["advisory_id"] == "OSV-TEST-0001"
    assert detail["impacts"][0]["risk_level"] == "high"


def test_advisory_detail_includes_raw_payload_and_related_impacts(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "advisory-detail-service",
            "service_name": "Advisory Detail Service",
            "environment": "prod",
            "owner_team": "security",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )

    detail = app.get_advisory("OSV-TEST-0001")

    assert detail["advisory"]["advisory_id"] == "OSV-TEST-0001"
    assert sorted(detail["advisory"]["affected_versions"]) == ["1.0.0", "1.0.1"]
    assert detail["advisory"]["affected_ranges"] == [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}]}]
    assert detail["advisory"]["raw_payload"]["aliases"] == ["CVE-2026-0001"]
    assert detail["advisory"]["aliases"] == [
        {"alias_type": "CVE", "alias_value": "CVE-2026-0001"},
        {"alias_type": "OSV", "alias_value": "OSV-TEST-0001"},
    ]
    assert detail["advisory"]["is_known_exploited"] is False
    assert len(detail["impacts"]) == 1
    assert detail["impacts"][0]["service_id"] == "advisory-detail-service"
    assert detail["impacts"][0]["owner_team"] == "security"


def test_advisory_detail_rejects_unknown_advisory(tmp_path):
    app = make_test_app(tmp_path)

    with pytest.raises(ValueError, match="advisory not found"):
        app.get_advisory("missing-advisory")


def test_unchanged_advisory_import_does_not_rematch(tmp_path):
    app = make_test_app(tmp_path)
    first = app.import_osv_payload(osv_fixture())
    second = app.import_osv_payload(osv_fixture())

    assert first["changed"] == 1
    assert second["changed"] == 0
    assert second["rematched_impacts"] == 0


def test_impact_detail_includes_advisory_context_and_status_history(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]

    app.update_impact_status(impact_id, {"status": "acknowledged", "actor": "tester", "reason": "triaged"})
    detail = app.get_impact(impact_id)

    assert detail["impact"]["id"] == impact_id
    assert detail["impact"]["advisory_id"] == "OSV-TEST-0001"
    assert detail["impact"]["affected_ranges"] == [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}]}]
    assert detail["history"][0]["from_status"] == "open"
    assert detail["history"][0]["to_status"] == "acknowledged"
    assert detail["history"][0]["actor"] == "tester"
    assert detail["history"][0]["reason"] == "triaged"
    audit = app.search_audit_logs({"target_type": ["impact"], "target_id": [impact_id]})
    assert audit["pagination"]["total"] == 1
    assert audit["audit_logs"][0]["action"] == "impact.status.update"
    assert audit["audit_logs"][0]["before"]["status"] == "open"
    assert audit["audit_logs"][0]["after"]["status"] == "acknowledged"


def test_impact_status_rejects_unknown_status(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]

    with pytest.raises(ValueError, match="status must be one of"):
        app.update_impact_status(impact_id, {"status": "waiting_for_magic"})


def test_accepted_risk_requires_reason_and_expiry(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]

    with pytest.raises(ValueError, match="reason is required"):
        app.update_impact_status(impact_id, {"status": "accepted_risk", "actor": "approver", "expires_at": "2026-07-10T00:00:00Z"})
    with pytest.raises(ValueError, match="expires_at is required"):
        app.update_impact_status(impact_id, {"status": "accepted_risk", "actor": "approver", "reason": "compensating control"})


def test_accepted_risk_records_approval_and_revokes_on_status_change(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]

    result = app.update_impact_status(
        impact_id,
        {
            "status": "accepted_risk",
            "actor": "security-approver",
            "reason": "compensating control",
            "expires_at": "2026-07-10T00:00:00Z",
        },
    )

    assert result["status"] == "accepted_risk"
    assert result["accepted_risk"]["approved_by"] == "security-approver"
    assert result["accepted_risk"]["reason"] == "compensating control"
    detail = app.get_impact(impact_id)
    assert detail["accepted_risk"]["expires_at"] == "2026-07-10T00:00:00Z"
    assert app.overview()["open_impacts"] == 0

    app.update_impact_status(impact_id, {"status": "in_progress", "actor": "security-approver", "reason": "risk expired"})

    assert app.get_impact(impact_id)["accepted_risk"] is None
    with app.db.connect() as conn:
        row = conn.execute("SELECT revoked_at FROM accepted_risks WHERE impact_pk = ?", (impact_id,)).fetchone()
    assert row["revoked_at"] is not None


def test_header_auth_uses_principal_for_accepted_risk_approval(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/impacts/{impact_id}/status",
            method="PATCH",
            body={
                "status": "accepted_risk",
                "actor": "spoofed-client",
                "reason": "compensating control",
                "expires_at": "2026-07-10T00:00:00Z",
            },
            headers={"X-SCA-Principal": "service-owner-a", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"},
            expect_status=403,
        )
        assert "security-approver" in forbidden["error"]

        result = http_json(
            f"{base_url}/api/v1/impacts/{impact_id}/status",
            method="PATCH",
            body={
                "status": "accepted_risk",
                "actor": "spoofed-client",
                "reason": "compensating control",
                "expires_at": "2026-07-10T00:00:00Z",
            },
            headers={"X-SCA-Principal": "approver@example.test", "X-SCA-Roles": "security-approver"},
        )

    assert result["accepted_risk"]["approved_by"] == "approver@example.test"
    assert app.get_impact(impact_id)["history"][0]["actor"] == "approver@example.test"


def test_header_auth_service_owner_can_only_update_owned_impact(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "owned-service",
            "environment": "prod",
            "owner_team": "platform",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    app.push_snapshot(
        {
            "service_id": "other-service",
            "environment": "prod",
            "owner_team": "billing",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    owned_impact_id = app.list_impacts({"service_id": ["owned-service"]})[0]["id"]
    other_impact_id = app.list_impacts({"service_id": ["other-service"]})[0]["id"]
    headers = {"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"}

    with run_test_server(app) as base_url:
        result = http_json(
            f"{base_url}/api/v1/impacts/{owned_impact_id}/status",
            method="PATCH",
            body={"status": "acknowledged", "actor": "spoofed-client", "reason": "owned triage"},
            headers=headers,
        )
        forbidden = http_json(
            f"{base_url}/api/v1/impacts/{other_impact_id}/status",
            method="PATCH",
            body={"status": "acknowledged", "reason": "wrong team"},
            headers=headers,
            expect_status=403,
        )

    assert result["status"] == "acknowledged"
    assert app.get_impact(owned_impact_id)["history"][0]["actor"] == "owner@example.test"
    assert "not authorized" in forbidden["error"]


def test_header_auth_service_owner_can_mark_owned_impact_fixed_or_not_affected(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "owned-fixed-service",
            "environment": "prod",
            "owner_team": "platform",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    app.push_snapshot(
        {
            "service_id": "owned-not-affected-service",
            "environment": "prod",
            "owner_team": "platform",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    app.push_snapshot(
        {
            "service_id": "other-service",
            "environment": "prod",
            "owner_team": "billing",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    fixed_impact_id = app.list_impacts({"service_id": ["owned-fixed-service"]})[0]["id"]
    not_affected_impact_id = app.list_impacts({"service_id": ["owned-not-affected-service"]})[0]["id"]
    other_impact_id = app.list_impacts({"service_id": ["other-service"]})[0]["id"]
    headers = {"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"}

    with run_test_server(app) as base_url:
        fixed = http_json(
            f"{base_url}/api/v1/impacts/{fixed_impact_id}/status",
            method="PATCH",
            body={"status": "fixed", "actor": "spoofed-client", "reason": "upgraded to fixed version"},
            headers=headers,
        )
        not_affected = http_json(
            f"{base_url}/api/v1/impacts/{not_affected_impact_id}/status",
            method="PATCH",
            body={"status": "not_affected", "actor": "spoofed-client", "reason": "package not loaded at runtime"},
            headers=headers,
        )
        forbidden = http_json(
            f"{base_url}/api/v1/impacts/{other_impact_id}/status",
            method="PATCH",
            body={"status": "fixed", "reason": "wrong team"},
            headers=headers,
            expect_status=403,
        )

    assert fixed["status"] == "fixed"
    assert not_affected["status"] == "not_affected"
    assert app.get_impact(fixed_impact_id)["history"][0]["actor"] == "owner@example.test"
    assert app.get_impact(not_affected_impact_id)["history"][0]["actor"] == "owner@example.test"
    assert "not authorized" in forbidden["error"]


def test_header_auth_service_owner_bulk_requires_owned_team_filter(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "owned-service",
            "environment": "prod",
            "owner_team": "platform",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    headers = {"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"}

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/impacts/status",
            method="POST",
            body={"target_status": "acknowledged", "filters": {"service_id": "owned-service"}, "reason": "missing owner_team"},
            headers=headers,
            expect_status=403,
        )
        result = http_json(
            f"{base_url}/api/v1/impacts/status",
            method="POST",
            body={"target_status": "acknowledged", "filters": {"owner_team": "platform"}, "reason": "owned bulk"},
            headers=headers,
        )

    assert "not authorized" in forbidden["error"]
    assert result["updated"] == 1


def test_header_auth_admin_required_for_service_registration_and_credentials(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    owner_headers = {"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"}
    admin_headers = {"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"}

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/services",
            method="POST",
            body={"service_id": "admin-service", "environment": "prod", "owner_team": "platform"},
            headers=owner_headers,
            expect_status=403,
        )
        created = http_json(
            f"{base_url}/api/v1/services",
            method="POST",
            body={"service_id": "admin-service", "environment": "prod", "owner_team": "platform"},
            headers=admin_headers,
            expect_status=201,
        )
        credential_forbidden = http_json(
            f"{base_url}/api/v1/services/admin-service/push-credentials",
            method="POST",
            body={"environment": "prod"},
            headers=owner_headers,
            expect_status=403,
        )
        credential = http_json(
            f"{base_url}/api/v1/services/admin-service/push-credentials",
            method="POST",
            body={"environment": "prod"},
            headers=admin_headers,
            expect_status=201,
        )
        rotate_forbidden = http_json(
            f"{base_url}/api/v1/services/admin-service/push-credentials/{credential['credential']['id']}/rotate",
            method="POST",
            body={"environment": "prod"},
            headers=owner_headers,
            expect_status=403,
        )
        rotated = http_json(
            f"{base_url}/api/v1/services/admin-service/push-credentials/{credential['credential']['id']}/rotate",
            method="POST",
            body={"environment": "prod", "actor": "spoofed"},
            headers=admin_headers,
            expect_status=201,
        )
        revoked = http_json(
            f"{base_url}/api/v1/services/admin-service/push-credentials/{rotated['credential']['id']}/revoke",
            method="POST",
            body={"environment": "prod", "actor": "spoofed"},
            headers=admin_headers,
        )

    assert "admin role" in forbidden["error"]
    assert created["service"]["service_id"] == "admin-service"
    assert "admin role" in credential_forbidden["error"]
    assert credential["credential"]["service_id"] == "admin-service"
    assert "admin role" in rotate_forbidden["error"]
    assert rotated["revoked_credential"]["id"] == credential["credential"]["id"]
    assert revoked["credential"]["revoked_at"] is not None


def test_header_auth_admin_required_for_alert_channel_changes(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    owner_headers = {"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"}
    admin_headers = {"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"}

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/settings/alert-channels",
            method="POST",
            body={"name": "ops", "target_url": "https://alerts.example.test/hooks/ops"},
            headers=owner_headers,
            expect_status=403,
        )
        created = http_json(
            f"{base_url}/api/v1/settings/alert-channels",
            method="POST",
            body={"name": "ops", "target_url": "https://alerts.example.test/hooks/ops", "actor": "spoofed"},
            headers=admin_headers,
            expect_status=201,
        )
        updated = http_json(
            f"{base_url}/api/v1/settings/alert-channels/{created['channel']['id']}",
            method="PATCH",
            body={"enabled": False, "actor": "spoofed", "reason": "header auth update"},
            headers=admin_headers,
        )

    assert "admin role" in forbidden["error"]
    assert created["channel"]["name"] == "ops"
    assert updated["channel"]["enabled"] is False
    audit = app.search_audit_logs({"target_type": ["alert_channel"], "target_id": [created["channel"]["id"]]})
    assert audit["pagination"]["total"] == 2
    assert {item["actor"] for item in audit["audit_logs"]} == {"admin@example.test"}


def test_header_auth_admin_required_for_alert_channel_test(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")
    owner_headers = {"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"}
    admin_headers = {"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"}

    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            return

    webhook = ThreadingHTTPServer(("127.0.0.1", 0), WebhookHandler)
    thread = threading.Thread(target=webhook.serve_forever, daemon=True)
    thread.start()
    try:
        channel = app.create_alert_channel({"name": "ops", "target_url": f"http://127.0.0.1:{webhook.server_port}/hooks/ops", "is_default": True})["channel"]
        with run_test_server(app) as base_url:
            forbidden = http_json(
                f"{base_url}/api/v1/settings/alert-channels/{channel['id']}/test",
                method="POST",
                body={"actor": "spoofed"},
                headers=owner_headers,
                expect_status=403,
            )
            tested = http_json(
                f"{base_url}/api/v1/settings/alert-channels/{channel['id']}/test",
                method="POST",
                body={"actor": "spoofed"},
                headers=admin_headers,
            )
    finally:
        webhook.shutdown()
        thread.join(timeout=5)
        webhook.server_close()

    assert "admin role" in forbidden["error"]
    assert tested["status"] == "ok"
    audit = app.search_audit_logs({"target_type": ["alert_channel"], "target_id": [channel["id"]]})
    assert audit["audit_logs"][0]["actor"] == "admin@example.test"


def test_session_disabled_mode_keeps_web_console_actions_enabled(tmp_path):
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        session = http_json(f"{base_url}/api/v1/session")

    assert session["auth_mode"] == "disabled"
    assert session["authenticated"] is False
    assert session["principal"] == "web-console"
    assert session["roles"] == ["admin", "security-approver", "service-owner"]
    assert all(session["capabilities"].values())


def test_header_auth_session_reports_principal_roles_and_capabilities(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")

    with run_test_server(app) as base_url:
        forbidden = http_json(f"{base_url}/api/v1/session", expect_status=403)
        owner_session = http_json(
            f"{base_url}/api/v1/session",
            headers={"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform, payments"},
        )
        approver_session = http_json(
            f"{base_url}/api/v1/session",
            headers={"X-SCA-Principal": "approver@example.test", "X-SCA-Roles": "security-approver"},
        )
        admin_session = http_json(
            f"{base_url}/api/v1/session",
            headers={"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"},
        )
        viewer_session = http_json(
            f"{base_url}/api/v1/session",
            headers={"X-SCA-Principal": "viewer@example.test", "X-SCA-Roles": "viewer"},
        )

    assert "missing authenticated principal" in forbidden["error"]
    assert owner_session["authenticated"] is True
    assert owner_session["principal"] == "owner@example.test"
    assert owner_session["roles"] == ["service-owner"]
    assert owner_session["owner_teams"] == ["payments", "platform"]
    assert owner_session["capabilities"]["update_impacts"] is True
    assert owner_session["capabilities"]["bulk_update_impacts"] is True
    assert owner_session["capabilities"]["accept_risk"] is False
    assert owner_session["capabilities"]["manage_services"] is False
    assert approver_session["capabilities"]["accept_risk"] is True
    assert approver_session["capabilities"]["manage_alert_channels"] is False
    assert admin_session["capabilities"]["manage_services"] is True
    assert admin_session["capabilities"]["manage_credentials"] is True
    assert admin_session["capabilities"]["manage_alert_channels"] is True
    assert viewer_session["authenticated"] is True
    assert viewer_session["principal"] == "viewer@example.test"
    assert viewer_session["roles"] == ["viewer"]
    assert viewer_session["capabilities"]["view_console"] is True
    assert viewer_session["capabilities"]["manage_services"] is False
    assert viewer_session["capabilities"]["update_impacts"] is False
    assert viewer_session["capabilities"]["accept_risk"] is False


def test_header_auth_requires_proxy_shared_secret_when_configured(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header", auth_proxy_shared_secret="proxy-secret")
    headers = {"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"}

    with run_test_server(app) as base_url:
        missing_secret = http_json(
            f"{base_url}/api/v1/session",
            headers=headers,
            expect_status=403,
        )
        wrong_secret = http_json(
            f"{base_url}/api/v1/session",
            headers={**headers, "X-SCA-Proxy-Secret": "wrong"},
            expect_status=403,
        )
        session = http_json(
            f"{base_url}/api/v1/session",
            headers={**headers, "X-SCA-Proxy-Secret": "proxy-secret"},
        )
        service_forbidden = http_json(
            f"{base_url}/api/v1/services",
            method="POST",
            body={"service_id": "proxy-service", "environment": "prod", "owner_team": "platform"},
            headers=headers,
            expect_status=403,
        )
        created = http_json(
            f"{base_url}/api/v1/services",
            method="POST",
            body={"service_id": "proxy-service", "environment": "prod", "owner_team": "platform"},
            headers={**headers, "X-SCA-Proxy-Secret": "proxy-secret"},
            expect_status=201,
        )

    assert "invalid auth proxy secret" in missing_secret["error"]
    assert "invalid auth proxy secret" in wrong_secret["error"]
    assert session["principal"] == "admin@example.test"
    assert session["capabilities"]["manage_services"] is True
    assert "invalid auth proxy secret" in service_forbidden["error"]
    assert created["service"]["service_id"] == "proxy-service"


def test_static_js_and_css_are_revalidated_without_asset_fingerprints(tmp_path):
    (tmp_path / "index.html").write_text("<script src=\"/app.js\"></script>", encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log('ok');", encoding="utf-8")
    (tmp_path / "styles.css").write_text("body { color: #18202a; }", encoding="utf-8")
    app = make_test_app(tmp_path)

    with run_test_server(app) as base_url:
        with urlopen(Request(f"{base_url}/app.js"), timeout=5) as app_js:  # noqa: S310 - local test server.
            app_js_cache_control = app_js.headers["Cache-Control"]
        with urlopen(Request(f"{base_url}/styles.css"), timeout=5) as styles_css:  # noqa: S310 - local test server.
            styles_css_cache_control = styles_css.headers["Cache-Control"]

    assert app_js_cache_control == "no-cache"
    assert styles_css_cache_control == "no-cache"


def test_expire_accepted_risks_reopens_due_impacts_and_audits(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]
    app.update_impact_status(
        impact_id,
        {
            "status": "accepted_risk",
            "actor": "security-approver",
            "reason": "temporary exception",
            "expires_at": "2026-01-01T00:00:00Z",
        },
    )

    dry_run = app.expire_accepted_risks(now="2026-01-02T00:00:00Z", dry_run=True)
    result = app.expire_accepted_risks(now="2026-01-02T00:00:00Z", actor="risk-scheduler")

    assert dry_run["expired"] == 1
    assert result["expired"] == 1
    assert app.get_impact(impact_id)["impact"]["status"] == "open"
    assert app.get_impact(impact_id)["accepted_risk"] is None
    audit = app.search_audit_logs({"action": ["accepted_risk.expire"], "target_id": [impact_id]})
    assert audit["pagination"]["total"] == 1
    assert audit["audit_logs"][0]["actor"] == "risk-scheduler"
    with app.db.connect() as conn:
        row = conn.execute("SELECT revoked_at FROM accepted_risks WHERE impact_pk = ?", (impact_id,)).fetchone()
    assert row["revoked_at"] == "2026-01-02T00:00:00Z"


def test_expire_accepted_risks_ignores_future_expiry(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]
    app.update_impact_status(
        impact_id,
        {
            "status": "accepted_risk",
            "actor": "security-approver",
            "reason": "temporary exception",
            "expires_at": "2026-02-01T00:00:00Z",
        },
    )

    result = app.expire_accepted_risks(now="2026-01-02T00:00:00Z")

    assert result["expired"] == 0
    assert app.get_impact(impact_id)["impact"]["status"] == "accepted_risk"
    assert app.get_impact(impact_id)["accepted_risk"]["expires_at"] == "2026-02-01T00:00:00Z"


def test_closed_workflow_statuses_are_excluded_from_open_counts(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]

    assert app.overview()["open_impacts"] == 1

    app.update_impact_status(impact_id, {"status": "not_affected", "actor": "tester"})

    assert app.overview()["open_impacts"] == 0
    assert app.list_services()[0]["open_impacts"] == 0


def test_list_impacts_supports_server_side_filters(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    second_payload = osv_fixture()
    second_payload["id"] = "OSV-TEST-0002"
    second_payload["summary"] = "Fixture advisory for second-package"
    second_payload["affected"][0]["package"]["name"] = "second-package"
    second_payload["affected"][0]["database_specific"]["severity"] = "LOW"
    app.import_osv_payload(second_payload)
    app.push_snapshot(
        {
            "service_id": "billing-service",
            "service_name": "Billing Service",
            "environment": "stage",
            "owner_team": "billing-team",
            "dependencies": [{"ecosystem": "npm", "name": "second-package", "version": "1.0.1"}],
        }
    )
    high_impact = next(impact for impact in app.list_impacts({}) if impact["risk_level"] == "high")
    app.update_impact_status(high_impact["id"], {"status": "acknowledged", "actor": "tester"})

    assert {impact["service_id"] for impact in app.list_impacts({})} == {"alert-service", "billing-service"}
    assert [impact["service_id"] for impact in app.list_impacts({"status": ["acknowledged"]})] == ["alert-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"risk_level": ["low"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"service_id": ["billing-service"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"owner_team": ["billing-team"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"environment": ["stage"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"package_name": ["Second-Package"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"advisory_id": ["OSV-TEST-0002"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"known_exploited": ["false"], "service_id": ["billing-service"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"malicious_package": ["false"], "service_id": ["billing-service"]})] == ["billing-service"]
    assert [impact["service_id"] for impact in app.list_impacts({"q": ["billing"]})] == ["billing-service"]

    page = app.search_impacts({"limit": ["1"], "offset": ["1"], "sort": ["service"], "direction": ["asc"]})

    assert page["pagination"] == {
        "total": 2,
        "limit": 1,
        "offset": 1,
        "returned": 1,
        "next_offset": None,
        "prev_offset": 0,
        "sort": "service",
        "direction": "asc",
    }
    assert [impact["service_id"] for impact in page["impacts"]] == ["billing-service"]


def test_bulk_update_impact_status_updates_filtered_impacts_and_audits(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    second_payload = osv_fixture()
    second_payload["id"] = "OSV-TEST-0002"
    second_payload["summary"] = "Fixture advisory for second-package"
    second_payload["affected"][0]["package"]["name"] = "second-package"
    app.import_osv_payload(second_payload)
    app.push_snapshot(
        {
            "service_id": "billing-service",
            "service_name": "Billing Service",
            "environment": "stage",
            "owner_team": "billing-team",
            "dependencies": [{"ecosystem": "npm", "name": "second-package", "version": "1.0.1"}],
        }
    )

    result = app.bulk_update_impact_status(
        {
            "target_status": "in_progress",
            "filters": {"owner_team": "billing-team"},
            "actor": "triage-bot",
            "reason": "bulk owner triage",
        }
    )

    assert result["matched"] == 1
    assert result["updated"] == 1
    assert result["skipped"] == 0
    assert [impact["status"] for impact in app.list_impacts({"service_id": ["billing-service"]})] == ["in_progress"]
    assert [impact["status"] for impact in app.list_impacts({"service_id": ["alert-service"]})] == ["open"]
    audit = app.search_audit_logs({"action": ["impact.status.update"], "q": ["bulk owner triage"]})
    assert audit["pagination"]["total"] == 1
    assert audit["audit_logs"][0]["actor"] == "triage-bot"

    skipped = app.bulk_update_impact_status({"target_status": "in_progress", "filters": {"owner_team": "billing-team"}})

    assert skipped["matched"] == 1
    assert skipped["updated"] == 0
    assert skipped["skipped"] == 1


def test_bulk_update_impact_status_rejects_accepted_risk(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)

    with pytest.raises(ValueError, match="target_status must be one of"):
        app.bulk_update_impact_status({"target_status": "accepted_risk", "filters": {"service_id": "alert-service"}})


def test_sync_osv_ecosystem_dump_from_zip(tmp_path):
    app = make_test_app(tmp_path)
    zip_path = tmp_path / "osv-fixture.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("OSV-TEST-0001.json", json.dumps(osv_fixture()))
        second = osv_fixture()
        second["id"] = "OSV-TEST-0002"
        second["affected"][0]["package"]["name"] = "second-package"
        archive.writestr("OSV-TEST-0002.json", json.dumps(second))

    result = sync_osv_ecosystem_dump(app, "npm", zip_path=zip_path, limit=1)

    assert result.scanned == 1
    assert result.processed == 1
    assert result.scan_limit_reached is False
    assert result.imported_rows == 1
    assert result.failed == 0
    advisories = app.list_advisories({"source": ["OSV"]})
    assert any(advisory["advisory_id"] == "OSV-TEST-0001" for advisory in advisories)
    assert all(advisory["advisory_id"] != "OSV-TEST-0002" for advisory in advisories)
    assert app.overview()["advisory_sync"]["OSV"] == "ok"


def test_sync_openssf_malicious_records_from_osv_zip(tmp_path):
    app = make_test_app(tmp_path)
    zip_path = tmp_path / "openssf-malicious.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("OSV-TEST-0001.json", json.dumps(osv_fixture()))
        archive.writestr("MAL-2026-0001.json", json.dumps(malicious_osv_fixture()))

    result = sync_osv_ecosystem_dump(app, "npm", zip_path=zip_path, source="OpenSSF", malicious_only=True)

    assert result.source == "OpenSSF"
    assert result.scanned == 2
    assert result.processed == 1
    assert result.skipped == 1
    assert result.scan_limit_reached is False
    assert result.imported_rows == 1
    assert result.failed == 0
    advisories = app.list_advisories({"source": ["OpenSSF"]})
    imported = next(advisory for advisory in advisories if advisory["advisory_id"] == "MAL-2026-0001")
    assert imported["is_malicious_package"] is True
    assert app.overview()["advisory_sync"]["OpenSSF"] == "ok"


def test_osv_sync_scan_limit_stops_large_malicious_only_scan(tmp_path):
    app = make_test_app(tmp_path)
    zip_path = tmp_path / "openssf-scan-limit.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("AAA-OSV-TEST-0001.json", json.dumps(osv_fixture()))
        archive.writestr("MAL-2026-0001.json", json.dumps(malicious_osv_fixture()))

    result = sync_osv_ecosystem_dump(
        app,
        "npm",
        zip_path=zip_path,
        source="OpenSSF",
        malicious_only=True,
        scan_limit=1,
    )

    assert result.scanned == 1
    assert result.processed == 0
    assert result.skipped == 1
    assert result.imported_rows == 0
    assert result.scan_limit_reached is True
    overview = app.overview()
    assert overview["advisory_sync"]["OpenSSF"] == "partial"
    assert overview["advisory_sync_readiness"]["status"] == "degraded"


def test_openssf_malicious_advisory_matches_as_critical_impact(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(malicious_osv_fixture())

    app.push_snapshot(
        {
            "service_id": "malicious-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "bad-package", "version": "1.2.3"}],
        }
    )

    impacts = app.search_impacts({"service_id": ["malicious-service"]})["impacts"]
    assert len(impacts) == 1
    assert impacts[0]["advisory_id"] == "MAL-2026-0001"
    assert impacts[0]["risk_level"] == "critical"
    assert impacts[0]["is_malicious_package"] is True
    assert app.search_impacts({"malicious_package": ["true"]})["impacts"][0]["service_id"] == "malicious-service"
    assert app.search_impacts({"malicious_package": ["false"], "service_id": ["malicious-service"]})["impacts"] == []
    assert app.overview()["critical_impacts"] == 1


def test_parse_ghsa_advisory_extracts_package_vulnerability():
    advisories = parse_ghsa_advisory(ghsa_fixture()[0])

    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory.advisory_id == "GHSA-xxxx-yyyy-zzzz"
    assert advisory.source == "GHSA"
    assert advisory.severity == "high"
    assert advisory.ecosystem == "npm"
    assert advisory.package_name == "example-package"
    assert advisory.fixed_version == "2.0.0"
    assert advisory.affected_ranges[0]["events"] == [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    assert advisory.is_malicious_package is False


def test_sync_github_advisories_from_json_file_records_sync_state_and_matches(tmp_path):
    app = make_test_app(tmp_path)
    app.push_snapshot(
        {
            "service_id": "ghsa-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.5.0"}],
        }
    )
    json_path = tmp_path / "ghsa.json"
    json_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")

    result = sync_github_advisories(app, json_path=json_path, limit=1)

    assert result.source == "GHSA"
    assert result.processed == 1
    assert result.imported_rows == 1
    assert result.failed == 0
    assert result.rematched_impacts == 1
    advisories = app.list_advisories({"source": ["GHSA"]})
    assert advisories[0]["advisory_id"] == "GHSA-xxxx-yyyy-zzzz"
    impacts = app.search_impacts({"service_id": ["ghsa-service"]})["impacts"]
    assert impacts[0]["advisory_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert app.overview()["advisory_sync"]["GHSA"] == "ok"


def test_sync_github_advisories_marks_malware_as_malicious(tmp_path):
    app = make_test_app(tmp_path)
    json_path = tmp_path / "ghsa-malware.json"
    json_path.write_text(json.dumps([ghsa_fixture_item(advisory_type="malware")]), encoding="utf-8")

    result = sync_github_advisories(app, json_path=json_path, advisory_type="malware")

    assert result.imported_rows == 1
    advisory = app.list_advisories({"source": ["GHSA"]})[0]
    assert advisory["is_malicious_package"] is True
    assert result.query["type"] == "malware"


def test_ghsa_sync_cli_imports_local_json(tmp_path):
    json_path = tmp_path / "ghsa.json"
    json_path.write_text(json.dumps(ghsa_fixture()), encoding="utf-8")
    database_url = f"sqlite:///{tmp_path / 'ghsa-cli.sqlite3'}"

    result = subprocess.run(
        ["python3", "scripts/ghsa_sync.py", "--json-path", str(json_path), "--limit", "1"],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["source"] == "GHSA"
    assert payload["processed"] == 1
    assert payload["imported_rows"] == 1
    assert payload["query"]["per_page"] == 1


def test_parse_cisa_kev_vulnerability_marks_known_exploited():
    advisory = parse_cisa_kev_vulnerability(cisa_kev_fixture()["vulnerabilities"][0], cisa_kev_fixture())

    assert advisory.advisory_id == "CISA_KEV:CVE-2026-0001"
    assert advisory.source == "CISA_KEV"
    assert advisory.severity == "critical"
    assert advisory.ecosystem == "cve"
    assert advisory.package_name == "ExampleVendor/Example Product"
    assert advisory.is_known_exploited is True
    assert advisory.raw_payload["dueDate"] == "2026-07-01"


def test_sync_cisa_kev_catalog_from_json_file(tmp_path):
    app = make_test_app(tmp_path)
    catalog_path = tmp_path / "cisa-kev.json"
    catalog_path.write_text(json.dumps(cisa_kev_fixture()), encoding="utf-8")

    result = sync_cisa_kev_catalog(app, json_path=catalog_path, limit=1)

    assert result.processed == 1
    assert result.imported_rows == 1
    assert result.failed == 0
    advisories = app.list_advisories({"source": ["CISA_KEV"]})
    imported = next(advisory for advisory in advisories if advisory["advisory_id"] == "CISA_KEV:CVE-2026-0001")
    assert imported["is_known_exploited"] is True
    assert imported["severity"] == "critical"
    with app.db.connect() as conn:
        raw_payload = json.loads(conn.execute("SELECT raw_payload FROM advisories WHERE advisory_id = 'CISA_KEV:CVE-2026-0001'").fetchone()["raw_payload"])
    assert raw_payload["requiredAction"] == "Apply vendor mitigations."
    assert app.overview()["advisory_sync"]["CISA_KEV"] == "ok"


def test_parse_nvd_cve_vulnerability_extracts_cpe_advisory():
    advisories = parse_nvd_cve_vulnerability(nvd_cve_fixture()["vulnerabilities"][0])

    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory.advisory_id == "CVE-2026-0001"
    assert advisory.source == "NVD"
    assert advisory.severity == "critical"
    assert advisory.ecosystem == "cpe"
    assert advisory.package_name == "example/example-server"
    assert advisory.affected_versions == ["versionStartIncluding:1.0.0", "versionEndExcluding:2.0.0"]
    assert advisory.is_known_exploited is True


def test_nvd_modified_window_extracts_deduped_cve_ids(tmp_path):
    payload = {
        "vulnerabilities": [
            nvd_cve_fixture("CVE-2026-0001")["vulnerabilities"][0],
            nvd_cve_fixture("cve-2026-0001")["vulnerabilities"][0],
            nvd_cve_fixture("CVE-2026-0002")["vulnerabilities"][0],
            {"cve": {"id": ""}},
        ]
    }
    json_path = tmp_path / "nvd-modified.json"
    json_path.write_text(json.dumps(payload), encoding="utf-8")

    assert nvd_cve_ids_from_payload(payload) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert load_nvd_modified_cve_ids(
        last_mod_start="2026-01-01T00:00:00.000",
        last_mod_end="2026-01-02T00:00:00.000",
        json_path=json_path,
    ) == ["CVE-2026-0001", "CVE-2026-0002"]


def test_nvd_modified_window_fetches_all_pages(monkeypatch):
    requests = []
    pages = {
        0: {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": [nvd_cve_fixture("CVE-2026-0001")["vulnerabilities"][0]],
        },
        1: {
            "resultsPerPage": 1,
            "startIndex": 1,
            "totalResults": 2,
            "vulnerabilities": [nvd_cve_fixture("CVE-2026-0002")["vulnerabilities"][0]],
        },
    }

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(request, timeout):
        parsed = urlparse(request.full_url)
        query = parse_qs(parsed.query)
        start_index = int(query.get("startIndex", ["0"])[0])
        requests.append({"timeout": timeout, "query": query})
        return FakeResponse(pages[start_index])

    monkeypatch.setattr("backend.sca_monitor.advisory_sync.urlopen", fake_urlopen)

    cve_ids = load_nvd_modified_cve_ids(
        last_mod_start="2026-01-01T00:00:00.000",
        last_mod_end="2026-01-02T00:00:00.000",
        api_url="https://nvd.example.test/rest/json/cves/2.0",
        timeout_seconds=7,
    )

    assert cve_ids == ["CVE-2026-0001", "CVE-2026-0002"]
    assert [request["query"].get("startIndex", ["0"])[0] for request in requests] == ["0", "1"]
    assert all(request["timeout"] == 7 for request in requests)


def test_sync_nvd_cve_from_json_file_records_sync_state(tmp_path):
    app = make_test_app(tmp_path)
    json_path = tmp_path / "nvd-cve.json"
    json_path.write_text(json.dumps(nvd_cve_fixture()), encoding="utf-8")

    result = sync_nvd_cve(app, "CVE-2026-0001", json_path=json_path)

    assert result.source == "NVD"
    assert result.imported_rows == 1
    advisories = app.list_advisories({"source": ["NVD"]})
    assert advisories[0]["advisory_id"] == "CVE-2026-0001"
    assert advisories[0]["package_name"] == "example/example-server"
    assert app.overview()["advisory_sync"]["NVD"] == "ok"
    with app.db.connect() as conn:
        state = conn.execute("SELECT cursor, last_run_at, records_processed FROM advisory_sync_state WHERE source = 'NVD'").fetchone()
    assert state["cursor"] == "CVE-2026-0001"
    assert state["last_run_at"]
    assert state["records_processed"] == 1


def test_sync_nvd_cve_enriches_matching_osv_alias_and_rematches_impacts(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "nvd-enrichment-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    before = app.search_impacts({"service_id": ["nvd-enrichment-service"]})["impacts"][0]
    assert before["risk_level"] == "high"
    json_path = tmp_path / "nvd-cve.json"
    nvd_payload = nvd_cve_fixture("CVE-2026-0001", severity="CRITICAL")
    json_path.write_text(json.dumps(nvd_payload), encoding="utf-8")

    result = sync_nvd_cve(app, "CVE-2026-0001", json_path=json_path)

    assert result.imported_rows == 1
    assert result.rematched_impacts == 1
    detail = app.get_advisory("OSV-TEST-0001")["advisory"]
    assert detail["severity"] == "critical"
    assert detail["raw_payload"]["_nvd_enrichment"]["cve_id"] == "CVE-2026-0001"
    assert detail["raw_payload"]["_nvd_enrichment"]["severity"] == "critical"
    assert detail["raw_payload"]["_nvd_enrichment"]["cpe_matches"][0]["criteria"].startswith("cpe:2.3:a:example:example-server")
    assert detail["raw_payload"]["_nvd_enrichment"]["cwes"] == ["CWE-79"]
    assert detail["raw_payload"]["_nvd_enrichment"]["references"] == [
        {"source": "nvd@example.test", "url": "https://example.test/advisories/CVE-2026-0001", "tags": ["Vendor Advisory"]}
    ]
    after = app.search_impacts({"service_id": ["nvd-enrichment-service"]})["impacts"][0]
    assert after["advisory_id"] == "OSV-TEST-0001"
    assert after["risk_level"] == "critical"


def test_sync_nvd_cves_dedupes_limits_and_reads_json_dir(tmp_path):
    app = make_test_app(tmp_path)
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    first = nvd_cve_fixture()
    second = nvd_cve_fixture("CVE-2026-0002", product="example-client", severity="HIGH")
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(first), encoding="utf-8")
    (json_dir / "CVE-2026-0002.json").write_text(json.dumps(second), encoding="utf-8")

    result = sync_nvd_cves(
        app,
        ["cve-2026-0001", "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
        json_dir=json_dir,
        limit=2,
    )

    assert result.source == "NVD"
    assert result.processed == 2
    assert result.imported_rows == 2
    assert result.failed == 0
    assert [item["cve_id"] for item in result.results] == ["CVE-2026-0001", "CVE-2026-0002"]
    advisories = app.list_advisories({"source": ["NVD"]})
    assert {advisory["advisory_id"] for advisory in advisories} == {"CVE-2026-0001", "CVE-2026-0002"}
    assert {advisory["package_name"] for advisory in advisories} == {
        "example/example-client",
        "example/example-server",
    }
    assert app.overview()["advisory_sync"]["NVD"] == "ok"
    assert result.request_delay_seconds == 0
    with app.db.connect() as conn:
        state = conn.execute("SELECT cursor, records_processed FROM advisory_sync_state WHERE source = 'NVD'").fetchone()
    assert state["cursor"] == "CVE-2026-0002"
    assert state["records_processed"] == 2


def test_sync_nvd_cves_uses_success_cursor_for_modified_window(tmp_path):
    app = make_test_app(tmp_path)
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(nvd_cve_fixture()), encoding="utf-8")

    result = sync_nvd_cves(
        app,
        ["CVE-2026-0001"],
        json_dir=json_dir,
        success_cursor="2026-06-02T00:00:00.000",
    )

    assert result.processed == 1
    assert result.failed == 0
    with app.db.connect() as conn:
        state = conn.execute("SELECT cursor, last_advisory_id FROM advisory_sync_state WHERE source = 'NVD'").fetchone()
    assert state["cursor"] == "2026-06-02T00:00:00.000"
    assert state["last_advisory_id"] == "CVE-2026-0001"


def test_sync_nvd_cves_keeps_cursor_on_partial_failure(tmp_path, monkeypatch):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("NVD", "ok", "CVE-2026-0000", None, cursor="CVE-2026-0000", records_processed=1)

    def fake_sync_nvd_cve(app_arg, cve_id, **kwargs):
        if cve_id == "CVE-2026-0002":
            raise RuntimeError("rate limited")

        class FakeResult:
            source = "NVD"
            imported_rows = 1
            rematched_impacts = 0

            def __init__(self, cve_id, api_url):
                self.cve_id = cve_id
                self.api_url = api_url

        return FakeResult(cve_id, kwargs["api_url"])

    monkeypatch.setattr("backend.sca_monitor.advisory_sync.sync_nvd_cve", fake_sync_nvd_cve)

    result = sync_nvd_cves(app, ["CVE-2026-0001", "CVE-2026-0002"], delay_seconds=0)

    assert result.processed == 2
    assert result.imported_rows == 1
    assert result.failed == 1
    with app.db.connect() as conn:
        state = conn.execute(
            "SELECT status, cursor, last_advisory_id, records_processed FROM advisory_sync_state WHERE source = 'NVD'"
        ).fetchone()
    assert state["status"] == "partial"
    assert state["cursor"] == "CVE-2026-0000"
    assert state["last_advisory_id"] == "CVE-2026-0001"
    assert state["records_processed"] == 2


def test_sync_nvd_cves_delays_between_remote_batch_requests(tmp_path, monkeypatch):
    app = make_test_app(tmp_path)
    calls = []
    sleeps = []

    def fake_sync_nvd_cve(app_arg, cve_id, **kwargs):
        calls.append({"cve_id": cve_id, **kwargs})
        class FakeResult:
            source = "NVD"
            imported_rows = 1
            rematched_impacts = 0

            def __init__(self, cve_id, api_url):
                self.cve_id = cve_id
                self.api_url = api_url

        return FakeResult(cve_id, kwargs["api_url"])

    monkeypatch.setattr("backend.sca_monitor.advisory_sync.sync_nvd_cve", fake_sync_nvd_cve)

    result = sync_nvd_cves(
        app,
        ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0002", "CVE-2026-0003"],
        limit=3,
        delay_seconds=1.25,
        sleep_func=sleeps.append,
    )

    assert result.processed == 3
    assert result.imported_rows == 3
    assert result.request_delay_seconds == 1.25
    assert [call["cve_id"] for call in calls] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert [item["cve_id"] for item in result.results] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert sleeps == [1.25, 1.25]


def test_sync_nvd_cves_does_not_delay_for_local_json_dir(tmp_path, monkeypatch):
    app = make_test_app(tmp_path)
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(nvd_cve_fixture()), encoding="utf-8")
    (json_dir / "CVE-2026-0002.json").write_text(json.dumps(nvd_cve_fixture("CVE-2026-0002")), encoding="utf-8")
    sleeps = []

    result = sync_nvd_cves(
        app,
        ["CVE-2026-0001", "CVE-2026-0002"],
        json_dir=json_dir,
        delay_seconds=1.25,
        sleep_func=sleeps.append,
    )

    assert result.processed == 2
    assert result.imported_rows == 2
    assert result.request_delay_seconds == 1.25
    assert sleeps == []


def test_nvd_cve_sync_cli_imports_local_json(tmp_path):
    json_path = tmp_path / "nvd-cve.json"
    json_path.write_text(json.dumps(nvd_cve_fixture()), encoding="utf-8")
    database_url = f"sqlite:///{tmp_path / 'nvd-cli.sqlite3'}"

    result = subprocess.run(
        ["python3", "scripts/nvd_cve_sync.py", "CVE-2026-0001", "--json-path", str(json_path)],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["source"] == "NVD"
    assert payload["cve_id"] == "CVE-2026-0001"
    assert payload["imported_rows"] == 1


def test_nvd_cve_sync_cli_batch_exposes_delay_seconds(tmp_path):
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(nvd_cve_fixture()), encoding="utf-8")
    (json_dir / "CVE-2026-0002.json").write_text(json.dumps(nvd_cve_fixture("CVE-2026-0002")), encoding="utf-8")
    cve_list_path = tmp_path / "cves.txt"
    cve_list_path.write_text("CVE-2026-0001\nCVE-2026-0002\n", encoding="utf-8")
    database_url = f"sqlite:///{tmp_path / 'nvd-list-cli.sqlite3'}"

    result = subprocess.run(
        [
            "python3",
            "scripts/nvd_cve_sync.py",
            "--cve-list-path",
            str(cve_list_path),
            "--json-dir",
            str(json_dir),
            "--delay-seconds",
            "1.5",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["source"] == "NVD"
    assert payload["processed"] == 2
    assert payload["imported_rows"] == 2
    assert payload["request_delay_seconds"] == 1.5


def test_nvd_cve_sync_cli_imports_modified_window_candidates_from_json(tmp_path):
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    first = nvd_cve_fixture("CVE-2026-0001")
    second = nvd_cve_fixture("CVE-2026-0002", product="example-client", severity="HIGH")
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(first), encoding="utf-8")
    (json_dir / "CVE-2026-0002.json").write_text(json.dumps(second), encoding="utf-8")
    modified_path = tmp_path / "nvd-modified.json"
    modified_path.write_text(
        json.dumps({"vulnerabilities": [first["vulnerabilities"][0], first["vulnerabilities"][0], second["vulnerabilities"][0]]}),
        encoding="utf-8",
    )
    database_url = f"sqlite:///{tmp_path / 'nvd-modified-cli.sqlite3'}"

    result = subprocess.run(
        [
            "python3",
            "scripts/nvd_cve_sync.py",
            "--modified-json-path",
            str(modified_path),
            "--json-dir",
            str(json_dir),
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["source"] == "NVD"
    assert payload["processed"] == 2
    assert payload["imported_rows"] == 2
    assert [item["cve_id"] for item in payload["results"]] == ["CVE-2026-0001", "CVE-2026-0002"]


def test_nvd_cve_sync_cli_imports_paginated_modified_window(tmp_path):
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    first = nvd_cve_fixture("CVE-2026-0001")
    second = nvd_cve_fixture("CVE-2026-0002", product="example-client", severity="HIGH")
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(first), encoding="utf-8")
    (json_dir / "CVE-2026-0002.json").write_text(json.dumps(second), encoding="utf-8")
    seen_queries = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            query = parse_qs(urlparse(self.path).query)
            seen_queries.append(query)
            start_index = int(query.get("startIndex", ["0"])[0])
            vulnerabilities = [first["vulnerabilities"][0]] if start_index == 0 else [second["vulnerabilities"][0]]
            body = json.dumps(
                {
                    "resultsPerPage": 1,
                    "startIndex": start_index,
                    "totalResults": 2,
                    "vulnerabilities": vulnerabilities,
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    database_url = f"sqlite:///{tmp_path / 'nvd-paginated-modified-cli.sqlite3'}"

    try:
        result = subprocess.run(
            [
                "python3",
                "scripts/nvd_cve_sync.py",
                "--api-url",
                f"http://{host}:{port}/rest/json/cves/2.0",
                "--last-mod-start",
                "2026-06-01T00:00:00.000",
                "--last-mod-end",
                "2026-06-02T00:00:00.000",
                "--modified-results-per-page",
                "1",
                "--json-dir",
                str(json_dir),
            ],
            cwd=REPO_ROOT,
            env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        server.server_close()

    payload = json.loads(result.stdout)
    assert payload["processed"] == 2
    assert [item["cve_id"] for item in payload["results"]] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert [query["startIndex"][0] for query in seen_queries] == ["0", "1"]
    assert [query["resultsPerPage"][0] for query in seen_queries] == ["1", "1"]


def test_nvd_cve_sync_cli_stores_modified_window_end_cursor(tmp_path):
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    first = nvd_cve_fixture("CVE-2026-0001")
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(first), encoding="utf-8")
    modified_path = tmp_path / "nvd-modified.json"
    modified_path.write_text(json.dumps({"vulnerabilities": [first["vulnerabilities"][0]]}), encoding="utf-8")
    database_url = f"sqlite:///{tmp_path / 'nvd-modified-cursor-cli.sqlite3'}"

    result = subprocess.run(
        [
            "python3",
            "scripts/nvd_cve_sync.py",
            "--last-mod-start",
            "2026-06-01T00:00:00.000",
            "--last-mod-end",
            "2026-06-02T00:00:00.000",
            "--modified-json-path",
            str(modified_path),
            "--json-dir",
            str(json_dir),
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["processed"] == 1
    database = Database(database_url)
    with database.connect() as conn:
        state = conn.execute("SELECT cursor, last_advisory_id FROM advisory_sync_state WHERE source = 'NVD'").fetchone()
    assert state["cursor"] == "2026-06-02T00:00:00.000"
    assert state["last_advisory_id"] == "CVE-2026-0001"


def test_nvd_cve_sync_cli_records_ok_when_modified_window_has_no_candidates(tmp_path):
    modified_path = tmp_path / "nvd-modified-empty.json"
    modified_path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    database_url = f"sqlite:///{tmp_path / 'nvd-empty-modified-cli.sqlite3'}"

    result = subprocess.run(
        [
            "python3",
            "scripts/nvd_cve_sync.py",
            "--last-mod-start",
            "2026-06-01T00:00:00.000",
            "--last-mod-end",
            "2026-06-02T00:00:00.000",
            "--modified-json-path",
            str(modified_path),
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["source"] == "NVD"
    assert payload["processed"] == 0
    assert payload["imported_rows"] == 0
    database = Database(database_url)
    with database.connect() as conn:
        state = conn.execute("SELECT status, cursor, records_processed FROM advisory_sync_state WHERE source = 'NVD'").fetchone()
    assert state["status"] == "ok"
    assert state["cursor"] == "2026-06-02T00:00:00.000"
    assert state["records_processed"] == 0


def test_nvd_cve_sync_use_cursor_falls_back_from_invalid_timestamp(tmp_path):
    app = make_test_app(tmp_path)
    app.record_advisory_sync("NVD", "ok", "CVE-2026-0001", None, cursor="badTcursor", records_processed=1)

    start = nvd_cursor_or_fallback_start(app, 1)

    assert start != "badTcursor"
    assert start.endswith(".000")
    assert "T" in start


def test_nvd_cve_sync_cli_imports_list_file_from_json_dir(tmp_path):
    json_dir = tmp_path / "nvd"
    json_dir.mkdir()
    (json_dir / "CVE-2026-0001.json").write_text(json.dumps(nvd_cve_fixture()), encoding="utf-8")
    (json_dir / "CVE-2026-0002.json").write_text(
        json.dumps(nvd_cve_fixture("CVE-2026-0002", product="example-client", severity="HIGH")),
        encoding="utf-8",
    )
    cve_list_path = tmp_path / "cves.txt"
    cve_list_path.write_text(
        "\n".join(["# reported CVEs", "cve-2026-0001", "CVE-2026-0001", "CVE-2026-0002"]),
        encoding="utf-8",
    )
    database_url = f"sqlite:///{tmp_path / 'nvd-list-cli.sqlite3'}"

    result = subprocess.run(
        [
            "python3",
            "scripts/nvd_cve_sync.py",
            "--cve-list-path",
            str(cve_list_path),
            "--json-dir",
            str(json_dir),
            "--limit",
            "2",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": database_url, "SCA_MONITOR_DATA_DIR": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["source"] == "NVD"
    assert payload["processed"] == 2
    assert payload["imported_rows"] == 2
    assert payload["failed"] == 0
    assert [item["cve_id"] for item in payload["results"]] == ["CVE-2026-0001", "CVE-2026-0002"]


def test_cisa_kev_sync_enriches_matching_osv_alias_and_rematches_impacts(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "kev-service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    assert app.overview()["critical_impacts"] == 0
    assert app.search_impacts({"service_id": ["kev-service"]})["impacts"][0]["risk_level"] == "high"
    catalog_path = tmp_path / "cisa-kev.json"
    catalog_path.write_text(json.dumps(cisa_kev_fixture()), encoding="utf-8")

    result = sync_cisa_kev_catalog(app, json_path=catalog_path, limit=1)

    assert result.enriched_advisories == 1
    assert result.rematched_impacts == 1
    with app.db.connect() as conn:
        advisory = conn.execute("SELECT is_known_exploited, severity FROM advisories WHERE advisory_id = 'OSV-TEST-0001'").fetchone()
    assert advisory["is_known_exploited"] == 1
    assert advisory["severity"] == "critical"
    assert app.search_impacts({"service_id": ["kev-service"]})["impacts"][0]["risk_level"] == "critical"
    assert app.search_impacts({"known_exploited": ["true"]})["impacts"][0]["service_id"] == "kev-service"
    assert app.search_impacts({"known_exploited": ["false"], "service_id": ["kev-service"]})["impacts"] == []
    assert app.overview()["critical_impacts"] == 1


def test_advisory_sync_lock_releases_after_success(tmp_path):
    app = make_test_app(tmp_path)

    with app.advisory_sync_lock("OSV", "owner-a", ttl_seconds=60):
        with app.db.connect() as conn:
            row = conn.execute("SELECT lock_owner FROM advisory_sync_state WHERE source = 'OSV'").fetchone()
            assert row["lock_owner"] == "owner-a"

    with app.db.connect() as conn:
        row = conn.execute("SELECT lock_owner, lock_expires_at FROM advisory_sync_state WHERE source = 'OSV'").fetchone()
        assert row["lock_owner"] is None
        assert row["lock_expires_at"] is None


def test_osv_sync_refuses_held_lock(tmp_path):
    app = make_test_app(tmp_path)
    zip_path = write_osv_fixture_zip(tmp_path)

    with app.advisory_sync_lock("OSV", "owner-a", ttl_seconds=60):
        with pytest.raises(RuntimeError, match="sync lock is held"):
            sync_osv_ecosystem_dump(app, "npm", zip_path=zip_path, lock_owner="owner-b")

    with app.db.connect() as conn:
        row = conn.execute("SELECT lease_acquire_failures FROM advisory_sync_state WHERE source = 'OSV'").fetchone()
    assert row["lease_acquire_failures"] == 1
    assert 'sca_monitor_worker_lease_acquire_failures{worker_type="advisory_sync",source="OSV"} 1' in app.metrics()


def test_dispatch_pending_alerts_marks_sent(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    delivered = []

    result = dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        sender=lambda url, payload: delivered.append((url, payload)),
    )

    assert result.pending == 1
    assert result.claimed == 1
    assert result.sent == 1
    assert result.failed == 0
    assert delivered[0][0] == "https://alerts.example.test/webhook"
    assert delivered[0][1]["service_id"] == "alert-service"
    with app.db.connect() as conn:
        row = conn.execute("SELECT status, sent_at, channel_type FROM alert_events").fetchone()
        assert row["status"] == "sent"
        assert row["sent_at"] is not None
        assert row["channel_type"] == "webhook"


def test_dispatch_pending_alerts_sends_idempotency_headers(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    delivered = []

    result = dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        sender=lambda url, payload, headers: delivered.append((url, payload, headers)),
    )

    assert result.sent == 1
    event_id = delivered[0][1]["alert_event_id"]
    assert delivered[0][2]["Idempotency-Key"] == event_id
    assert delivered[0][2]["X-SCA-Alert-Event-Id"] == event_id
    assert delivered[0][2]["X-SCA-Alert-Suppression-Key"] == delivered[0][1]["alert_suppression_key"]


def test_dispatch_pending_alerts_uses_default_channel(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default", "is_default": True})
    delivered = []

    result = dispatch_pending_alerts(app, webhook_url=None, sender=lambda url, payload: delivered.append((url, payload)))

    assert result.sent == 1
    assert delivered[0][0] == "https://alerts.example.test/default"
    with app.db.connect() as conn:
        row = conn.execute("SELECT channel_target FROM alert_events").fetchone()
        assert row["channel_target"] == "https://alerts.example.test/default"


def test_dispatch_pending_alerts_routes_daily_digest_to_owner_team_channel(tmp_path):
    app = make_test_app(tmp_path)
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "platform-service",
            "service_name": "Platform Service",
            "environment": "prod",
            "owner_team": "platform",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )
    with app.db.connect() as conn:
        conn.execute("UPDATE impacts SET risk_level = 'medium', status = 'open'")
        conn.execute("DELETE FROM alert_events")
    app.enqueue_daily_digest_alert(
        now="2026-01-03T00:00:00+00:00",
        owner_team="platform",
        actor="digest-scheduler",
    )
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default", "is_default": True})
    app.create_alert_channel(
        {
            "name": "platform",
            "target_url": "https://alerts.internal/platform",
            "is_default": False,
            "owner_team": "platform",
        }
    )
    delivered = []

    result = dispatch_pending_alerts(app, webhook_url=None, sender=lambda url, payload: delivered.append((url, payload)))

    assert result.sent == 1
    assert delivered[0][0] == "https://alerts.internal/platform"
    assert delivered[0][1]["digest"]["owner_team"] == "platform"
    with app.db.connect() as conn:
        row = conn.execute("SELECT channel_target FROM alert_events WHERE reason = 'daily_digest'").fetchone()
        assert row["channel_target"] == "https://alerts.internal/platform"


def test_dispatch_pending_alerts_ignores_disabled_default_channel(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    channel = app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default", "is_default": True})["channel"]
    app.update_alert_channel(channel["id"], {"enabled": False})

    with pytest.raises(ValueError, match="webhook_url required"):
        dispatch_pending_alerts(app, webhook_url=None, sender=lambda url, payload: None)


def test_dispatch_pending_alerts_dry_run_does_not_update(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)

    result = dispatch_pending_alerts(app, webhook_url=None, dry_run=True)

    assert result.pending == 1
    assert result.claimed == 0
    assert result.sent == 0
    with app.db.connect() as conn:
        row = conn.execute("SELECT status FROM alert_events").fetchone()
        assert row["status"] == "pending"


def test_dispatch_pending_alerts_dry_run_does_not_read_default_channel(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)

    def fail_default_channel_lookup():
        raise AssertionError("dry-run should not read default alert channel")

    app.default_alert_webhook_url = fail_default_channel_lookup

    result = dispatch_pending_alerts(app, webhook_url=None, dry_run=True)

    assert result.pending == 1
    assert result.claimed == 0


def test_alert_dispatcher_preflight_requires_default_channel(tmp_path):
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
    }

    result = subprocess.run(
        ["python3", "scripts/alert_dispatcher_preflight.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "failed"
    assert payload["checks"]["database_ready"] is True
    assert payload["checks"]["default_alert_channel_configured"] is False
    assert payload["default_alert_channel"] == {"configured": False}


def test_alert_dispatcher_preflight_route_reports_failures_without_updating_rows(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default-secret", "is_default": True})

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/alerts/dispatcher/preflight?limit=10")

    assert payload["status"] == "failed"
    assert payload["checks"]["database_ready"] is True
    assert payload["checks"]["default_alert_channel_configured"] is True
    assert payload["checks"]["default_alert_channel_not_placeholder"] is False
    assert payload["dry_run"]["pending"] == 1
    assert payload["dry_run"]["claimed"] == 0
    assert payload["default_alert_channel"]["target_url_masked"] == "https://alerts.example.test/..."
    with app.db.connect() as conn:
        assert conn.execute("SELECT status FROM alert_events").fetchone()["status"] == "pending"


def test_alert_dispatcher_preflight_route_passes_with_default_channel(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.internal/default-secret", "is_default": True})

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/alerts/dispatcher/preflight?limit=10")

    assert payload["status"] == "ok"
    assert payload["checks"]["default_alert_channel_not_placeholder"] is True
    assert payload["dry_run"]["pending"] == 1


def test_alert_dispatcher_preflight_route_requires_admin_in_header_auth(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/alerts/dispatcher/preflight",
            headers={"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"},
            expect_status=403,
        )
        allowed = http_json(
            f"{base_url}/api/v1/alerts/dispatcher/preflight?allow_missing_default_channel=true",
            headers={"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"},
        )

    assert "admin role" in forbidden["error"]
    assert allowed["status"] == "ok"


def test_alert_dispatcher_activation_checklist_blocks_placeholder_without_updating_rows(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default-secret", "is_default": True})

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/alerts/dispatcher/activation-checklist?limit=10")

    assert payload["status"] == "blocked"
    assert payload["next_action"] == "resolve_blocking_failures"
    assert "default_alert_channel_not_placeholder" in payload["blocking_failures"]
    assert payload["preflight"]["dry_run"]["pending"] == 1
    item_status = {item["name"]: item["status"] for item in payload["items"]}
    assert item_status["database_ready"] == "passed"
    assert item_status["default_alert_channel_not_placeholder"] == "failed"
    with app.db.connect() as conn:
        assert conn.execute("SELECT status FROM alert_events").fetchone()["status"] == "pending"


def test_alert_dispatcher_activation_checklist_ready_with_real_default_channel(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.internal/default-secret", "is_default": True})

    with run_test_server(app) as base_url:
        payload = http_json(f"{base_url}/api/v1/alerts/dispatcher/activation-checklist?limit=10")

    assert payload["status"] == "ready"
    assert payload["next_action"] == "enable_live_dispatcher"
    assert payload["blocking_failures"] == []
    assert payload["preflight"]["checks"]["default_alert_channel_not_placeholder"] is True


def test_alert_dispatcher_activation_checklist_requires_admin_in_header_auth(tmp_path):
    app = make_test_app(tmp_path, auth_mode="header")

    with run_test_server(app) as base_url:
        forbidden = http_json(
            f"{base_url}/api/v1/alerts/dispatcher/activation-checklist",
            headers={"X-SCA-Principal": "owner@example.test", "X-SCA-Roles": "service-owner", "X-SCA-Owner-Teams": "platform"},
            expect_status=403,
        )
        allowed = http_json(
            f"{base_url}/api/v1/alerts/dispatcher/activation-checklist?limit=10",
            headers={"X-SCA-Principal": "admin@example.test", "X-SCA-Roles": "admin"},
            expect_status=200,
        )

    assert "admin role" in forbidden["error"]
    assert allowed["status"] == "blocked"
    assert "default_alert_channel_configured" in allowed["blocking_failures"]


def test_alert_dispatcher_activation_check_cli_reports_blocked(tmp_path):
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
    }

    result = subprocess.run(
        ["python3", "scripts/alert_dispatcher_activation_check.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert "default_alert_channel_configured" in payload["blocking_failures"]


def test_alert_dispatcher_go_live_gate_blocks_placeholder_channel(tmp_path):
    app = make_test_app(tmp_path)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default-secret", "is_default": True})
    unit_dir = tmp_path / "systemd"
    subprocess.run(
        [
            "bash",
            "scripts/install_systemd_units.sh",
            "--dry-run",
            "--unit-dir",
            str(unit_dir),
            "--repo-dir",
            str(REPO_ROOT),
            "--python",
            "/usr/bin/python3",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/alert_dispatcher_go_live_gate.py",
            "--json",
            "--unit-dir",
            str(unit_dir),
            "--skip-systemctl-state",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": app.settings.database_url},
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "blocked"
    assert payload["systemd"]["status"] == "ok"
    assert "activation_check_ready" in payload["blocking_failures"]
    assert "default_alert_channel_not_placeholder" in payload["activation_check"]["blocking_failures"]


def test_alert_dispatcher_go_live_gate_ready_with_real_channel_and_valid_units(tmp_path):
    app = make_test_app(tmp_path)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.internal/default-secret", "is_default": True})
    unit_dir = tmp_path / "systemd"
    subprocess.run(
        [
            "bash",
            "scripts/install_systemd_units.sh",
            "--dry-run",
            "--unit-dir",
            str(unit_dir),
            "--repo-dir",
            str(REPO_ROOT),
            "--python",
            "/usr/bin/python3",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/alert_dispatcher_go_live_gate.py",
            "--json",
            "--unit-dir",
            str(unit_dir),
            "--skip-systemctl-state",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCA_MONITOR_DATABASE_URL": app.settings.database_url},
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ready"
    assert payload["blocking_failures"] == []
    assert payload["activation_check"]["status"] == "ready"
    assert payload["systemd"]["status"] == "ok"
    assert "SCA_MONITOR_SYSTEMD_MODE=enable" in payload["go_live_command"]


def test_alert_dispatcher_preflight_passes_with_default_channel_and_does_not_update_rows(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.internal/default-secret", "is_default": True})
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
    }

    result = subprocess.run(
        ["python3", "scripts/alert_dispatcher_preflight.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["checks"] == {
        "database_ready": True,
        "default_alert_channel_configured": True,
        "default_alert_channel_not_placeholder": True,
        "dispatcher_dry_run_ok": True,
    }
    assert payload["default_alert_channel"]["target_url_masked"] == "https://alerts.internal/..."
    assert payload["dry_run"]["pending"] == 1
    assert payload["dry_run"]["claimed"] == 0
    assert payload["alert_events"]["pending"] == 1
    with app.db.connect() as conn:
        assert conn.execute("SELECT status FROM alert_events").fetchone()["status"] == "pending"


def test_alert_dispatcher_preflight_rejects_placeholder_default_channel(tmp_path):
    app = make_test_app(tmp_path)
    app.create_alert_channel({"name": "default", "target_url": "https://alerts.example.test/default-secret", "is_default": True})
    env = {
        **os.environ,
        "SCA_MONITOR_DATA_DIR": str(tmp_path),
        "SCA_MONITOR_DATABASE_URL": app.settings.database_url,
    }

    result = subprocess.run(
        ["python3", "scripts/alert_dispatcher_preflight.py", "--json"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["checks"]["default_alert_channel_configured"] is True
    assert payload["checks"]["default_alert_channel_not_placeholder"] is False
    assert payload["default_alert_channel"]["placeholder_target"] is True


def test_alert_webhook_smoke_posts_synthetic_payload(tmp_path):
    received = []

    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            received.append({"headers": dict(self.headers), "payload": json.loads(body)})
            self.send_response(204)
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        result = subprocess.run(
            [
                "python3",
                "scripts/alert_webhook_smoke.py",
                "--webhook-url",
                f"http://{host}:{port}/hook/secret",
                "--service-id",
                "smoke-service",
                "--environment",
                "stage",
                "--json",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    output = json.loads(result.stdout)
    assert output["status"] == "ok"
    assert output["webhook_url"] == f"http://{host}:{port}/..."
    assert received[0]["payload"]["smoke"] is True
    assert received[0]["payload"]["service_id"] == "smoke-service"
    assert received[0]["payload"]["environment"] == "stage"
    assert received[0]["headers"]["X-Sca-Smoke"] == "true"
    assert received[0]["headers"]["Idempotency-Key"] == received[0]["payload"]["smoke_id"]


def test_dispatch_pending_alerts_marks_failed(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)

    def fail_sender(url, payload):
        raise RuntimeError("delivery failed")

    result = dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        sender=fail_sender,
    )

    assert result.pending == 1
    assert result.claimed == 1
    assert result.sent == 0
    assert result.failed == 1
    with app.db.connect() as conn:
        row = conn.execute("SELECT status, payload, retry_count, next_attempt_at FROM alert_events").fetchone()
        assert row["status"] == "failed"
        assert "delivery failed" in row["payload"]
        assert row["retry_count"] == 1
        assert row["next_attempt_at"] is not None


def test_dispatch_pending_alerts_moves_to_dead_letter_after_max_retries(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)

    result = dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        max_retries=1,
        sender=lambda url, payload, headers: (_ for _ in ()).throw(RuntimeError("delivery failed")),
    )

    assert result.failed == 1
    with app.db.connect() as conn:
        row = conn.execute("SELECT status, payload, retry_count, next_attempt_at FROM alert_events").fetchone()
        assert row["status"] == "dead_letter"
        assert row["retry_count"] == 1
        assert row["next_attempt_at"] is None
        assert json.loads(row["payload"])["dispatch_terminal"] is True


def test_requeue_dead_letter_alert_event(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        max_retries=1,
        sender=lambda url, payload, headers: (_ for _ in ()).throw(RuntimeError("delivery failed")),
    )
    with app.db.connect() as conn:
        alert_id = conn.execute("SELECT id FROM alert_events").fetchone()["id"]

    result = app.requeue_alert_event(alert_id, {"actor": "security", "reason": "target fixed"})

    assert result["alert_event"]["status"] == "pending"
    assert result["alert_event"]["retry_count"] == 0
    assert result["alert_event"]["next_attempt_at"] is None
    assert result["alert_event"]["payload"]["requeued_by"] == "security"
    assert result["alert_event"]["payload"]["requeue_reason"] == "target fixed"
    audit = app.search_audit_logs({"target_type": ["alert_event"], "target_id": [alert_id]})
    assert audit["pagination"]["total"] == 1
    assert audit["audit_logs"][0]["action"] == "alert_event.requeue"
    assert audit["audit_logs"][0]["before"]["status"] == "dead_letter"
    assert audit["audit_logs"][0]["after"]["status"] == "pending"


def test_search_audit_logs_filters_by_actor_and_query(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]
    app.update_impact_status(impact_id, {"status": "acknowledged", "actor": "auditor", "reason": "triaged for audit"})

    by_actor = app.search_audit_logs({"actor": ["auditor"]})
    by_query = app.search_audit_logs({"q": ["triaged for audit"], "limit": ["5"]})

    assert by_actor["pagination"]["total"] == 1
    assert by_query["pagination"]["total"] == 1
    assert by_query["audit_logs"][0]["target_id"] == impact_id


def test_bulk_requeue_dead_letter_alert_events_filters_and_limits(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        max_retries=1,
        sender=lambda url, payload, headers: (_ for _ in ()).throw(RuntimeError("delivery failed")),
    )
    with app.db.connect() as conn:
        original = conn.execute("SELECT * FROM alert_events").fetchone()
        clone = dict(original)
        clone["id"] = "dead-letter-secondary"
        clone["reason"] = "secondary delivery failure"
        columns = list(clone.keys())
        conn.execute(
            f"INSERT INTO alert_events ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            tuple(clone[column] for column in columns),
        )

    result = app.bulk_requeue_alert_events(
        {
            "q": "secondary",
            "actor": "security",
            "reason": "target fixed",
            "limit": 10,
        }
    )

    assert result["matched"] == 1
    assert result["requeued"] == 1
    assert result["alert_events"][0]["id"] == "dead-letter-secondary"
    with app.db.connect() as conn:
        statuses = {row["id"]: row["status"] for row in conn.execute("SELECT id, status FROM alert_events").fetchall()}
    assert statuses["dead-letter-secondary"] == "pending"
    assert [status for event_id, status in statuses.items() if event_id != "dead-letter-secondary"] == ["dead_letter"]


def test_bulk_requeue_rejects_non_dead_letter_status(tmp_path):
    app = make_test_app(tmp_path)

    with pytest.raises(ValueError, match="bulk requeue only supports dead_letter"):
        app.bulk_requeue_alert_events({"status": "pending"})


def test_search_alert_events_lists_and_filters(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    app.record_advisory_sync("GHSA", "error", "GHSA-TEST", "rate limit")

    page = app.search_alert_events({"status": ["pending"], "limit": ["5"]})

    assert page["pagination"]["total"] == 2
    assert page["alert_events"][0]["status"] == "pending"
    assert "channel_target" not in page["alert_events"][0]

    system_page = app.search_alert_events({"system_only": ["true"], "limit": ["5"]})
    assert system_page["pagination"]["total"] == 1
    assert system_page["alert_events"][0]["reason"] == "system_advisory_sync_failed"
    assert system_page["alert_events"][0]["service_id"] is None
    assert system_page["alert_events"][0]["payload"]["source"] == "GHSA"
    assert system_page["alert_events"][0]["payload"]["error_message"] == "rate limit"

    assert app.search_alert_events({"q": ["alert-service"]})["pagination"]["total"] == 1
    assert app.search_alert_events({"status": ["sent"]})["pagination"]["total"] == 0


def test_search_alert_events_masks_channel_target(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/hooks/secret",
        sender=lambda url, payload, headers: None,
    )

    event = app.search_alert_events({"status": ["sent"]})["alert_events"][0]

    assert event["channel_target_masked"] == "https://alerts.example.test/..."
    assert "secret" not in json.dumps(event)


def test_requeue_rejects_non_dead_letter_alert_event(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        alert_id = conn.execute("SELECT id FROM alert_events").fetchone()["id"]

    with pytest.raises(ValueError, match="only dead_letter"):
        app.requeue_alert_event(alert_id, {"actor": "security"})


def test_failed_alert_waits_for_next_attempt(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)

    dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        retry_backoff_seconds=3600,
        sender=lambda url, payload: (_ for _ in ()).throw(RuntimeError("delivery failed")),
    )

    result = dispatch_pending_alerts(app, webhook_url=None, dry_run=True)

    assert result.pending == 0


def test_expired_dispatch_lock_can_be_reclaimed(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    with app.db.connect() as conn:
        conn.execute(
            """
            UPDATE alert_events
            SET status = 'dispatching',
                dispatch_lock_owner = 'stale-owner',
                dispatch_lock_expires_at = '2000-01-01T00:00:00+00:00'
            """
        )
    delivered = []

    result = dispatch_pending_alerts(
        app,
        webhook_url="https://alerts.example.test/webhook",
        lock_owner="new-owner",
        sender=lambda url, payload: delivered.append(payload),
    )

    assert result.pending == 1
    assert result.claimed == 1
    assert result.sent == 1
    assert len(delivered) == 1


def test_dispatch_alert_batches_repeats_with_sleep(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    slept = []
    delivered = []

    results = dispatch_alert_batches(
        app,
        webhook_url="https://alerts.example.test/webhook",
        iterations=2,
        interval_seconds=3,
        sender=lambda url, payload: delivered.append(payload),
        sleeper=lambda seconds: slept.append(seconds),
    )

    assert [result.sent for result in results] == [1, 0]
    assert [result.pending for result in results] == [1, 0]
    assert slept == [3]
    assert len(delivered) == 1


def make_test_app(tmp_path, auth_mode="disabled", **setting_overrides):
    settings = Settings(
        app_env="test",
        host="127.0.0.1",
        port=0,
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
        database_path=tmp_path / "sca-monitor.sqlite3",
        frontend_dir=tmp_path,
        smoke_token="test",
        auth_mode=auth_mode,
        **setting_overrides,
    )
    return ScaMonitorApp(settings)


@contextmanager
def run_test_server(app):
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def http_json(url, *, method="GET", body=None, headers=None, expect_status=200):
    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(url, data=payload, method=method)
    request.add_header("Accept", "application/json")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urlopen(request, timeout=5) as response:  # noqa: S310 - local test server.
            assert response.status == expect_status
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        assert exc.code == expect_status
        return json.loads(exc.read().decode("utf-8"))


def write_osv_fixture_zip(tmp_path):
    zip_path = tmp_path / "osv-fixture.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("OSV-TEST-0001.json", json.dumps(osv_fixture()))
    return zip_path


def create_alerting_impact(app):
    app.import_osv_payload(osv_fixture())
    app.push_snapshot(
        {
            "service_id": "alert-service",
            "service_name": "Alert Service",
            "environment": "prod",
            "dependencies": [{"ecosystem": "npm", "name": "example-package", "version": "1.0.1"}],
        }
    )


def osv_fixture():
    return {
        "id": "OSV-TEST-0001",
        "aliases": ["CVE-2026-0001"],
        "summary": "Fixture advisory for example-package",
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "example-package"},
                "versions": ["1.0.1", "1.0.0"],
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}]}],
                "database_specific": {"severity": "HIGH"},
            }
        ],
    }


def malicious_osv_fixture():
    payload = osv_fixture()
    payload["id"] = "MAL-2026-0001"
    payload["aliases"] = []
    payload["summary"] = "Malicious package report for bad-package"
    payload["details"] = "The package executes malicious install-time behavior."
    payload["affected"][0]["package"]["name"] = "bad-package"
    payload["affected"][0]["versions"] = ["1.2.3"]
    payload["affected"][0]["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "1.2.3"}, {"last_affected": "1.2.3"}]}]
    payload["affected"][0]["database_specific"] = {"severity": "CRITICAL"}
    return payload


def cisa_kev_fixture():
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.06.11",
        "dateReleased": "2026-06-11",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "ExampleVendor",
                "product": "Example Product",
                "vulnerabilityName": "Example Product Remote Code Execution Vulnerability",
                "dateAdded": "2026-06-10",
                "shortDescription": "Example Product contains a remote code execution vulnerability.",
                "requiredAction": "Apply vendor mitigations.",
                "dueDate": "2026-07-01",
                "knownRansomwareCampaignUse": "Known",
                "notes": "https://example.test/advisory",
                "cwes": ["CWE-78"],
            },
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "OtherVendor",
                "product": "Other Product",
                "vulnerabilityName": "Other Product Vulnerability",
                "dateAdded": "2026-06-11",
                "shortDescription": "Other Product contains a known exploited vulnerability.",
                "requiredAction": "Apply updates.",
                "dueDate": "2026-07-02",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
                "cwes": [],
            },
        ],
    }


def ghsa_fixture():
    return [ghsa_fixture_item()]


def ghsa_fixture_item(advisory_type: str = "reviewed"):
    return {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_id": "CVE-2026-0001",
        "url": "https://api.github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "summary": "Example package vulnerable to remote code execution",
        "description": "Example package contains a remote code execution vulnerability.",
        "type": advisory_type,
        "severity": "high",
        "source_code_location": "https://github.com/example/example-package",
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"},
            {"type": "CVE", "value": "CVE-2026-0001"},
        ],
        "references": ["https://github.com/example/example-package/security/advisories/GHSA-xxxx-yyyy-zzzz"],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "example-package"},
                "vulnerable_version_range": ">= 1.0.0, < 2.0.0",
                "first_patched_version": {"identifier": "2.0.0"},
                "vulnerable_functions": [],
            }
        ],
        "published_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "withdrawn_at": None,
    }


def nvd_cve_fixture(cve_id: str = "CVE-2026-0001", *, product: str = "example-server", severity: str = "CRITICAL"):
    description_product = product.replace("-", " ").title()
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": f"{description_product} contains a remote code execution vulnerability."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": severity,
                                }
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": f"cpe:2.3:a:example:{product}:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "1.0.0",
                                            "versionEndExcluding": "2.0.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                    "weaknesses": [
                        {
                            "source": "nvd@example.test",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-79"}],
                        }
                    ],
                    "references": [
                        {
                            "source": "nvd@example.test",
                            "url": "https://example.test/advisories/CVE-2026-0001",
                            "tags": ["Vendor Advisory"],
                        }
                    ],
                    "cisaExploitAdd": "2026-06-10",
                }
            }
        ],
    }
