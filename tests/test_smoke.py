import json
import zipfile

import pytest

from backend.sca_monitor.alert_dispatch import dispatch_alert_batches, dispatch_pending_alerts
from backend.sca_monitor.advisory_sync import sync_osv_ecosystem_dump
from backend.sca_monitor.endpoint_poll import endpoint_poll_lock, poll_configured_endpoints
from backend.sca_monitor.db import Database, canonical_package_name
from backend.sca_monitor.migrations import REQUIRED_MIGRATION_VERSION
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import Settings
from backend.sca_monitor.osv import parse_osv_advisories
from backend.sca_monitor.versioning import version_is_affected


def test_pypi_canonical_name():
    assert canonical_package_name("PyPI", "Django_REST.Framework") == "django-rest-framework"


def test_npm_canonical_name():
    assert canonical_package_name("npm", "Lodash") == "lodash"


def test_sqlite_migration_records_version(tmp_path):
    database = Database(tmp_path / "sca-monitor.sqlite3")

    database.migrate()

    assert database.current_migration_version() == REQUIRED_MIGRATION_VERSION
    readiness = database.readiness()
    assert readiness["database"] == "ok"
    assert readiness["database_backend"] == "sqlite"
    assert readiness["migration"]["compatible"] is True


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
    assert "secret-token" not in json.dumps(created)
    channels = app.list_alert_channels()
    assert channels[0]["is_default"] is True
    assert "secret-token" not in json.dumps(channels)
    assert app.default_alert_webhook_url() == "https://alerts.example.test/hooks/secret-token"


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

    metrics = app.metrics()

    assert 'sca_monitor_advisory_sync_lag_seconds{source="OSV"}' in metrics
    assert 'sca_monitor_endpoint_poll_success_rate{worker="metric-worker"} 1.000000' in metrics
    assert "sca_monitor_endpoint_poll_success_rate 1.000000" in metrics
    assert "sca_monitor_alert_delivery_success_rate 1.000000" in metrics
    assert "sca_monitor_alert_outbox_pending_count 0" in metrics
    assert "sca_monitor_stale_services 0" in metrics


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


def test_impact_status_rejects_unknown_status(tmp_path):
    app = make_test_app(tmp_path)
    create_alerting_impact(app)
    impact_id = app.list_impacts({})[0]["id"]

    with pytest.raises(ValueError, match="status must be one of"):
        app.update_impact_status(impact_id, {"status": "waiting_for_magic"})


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

    assert result.processed == 1
    assert result.imported_rows == 1
    assert result.failed == 0
    advisories = app.list_advisories({"source": ["OSV"]})
    assert any(advisory["advisory_id"] == "OSV-TEST-0001" for advisory in advisories)
    assert all(advisory["advisory_id"] != "OSV-TEST-0002" for advisory in advisories)
    assert app.overview()["advisory_sync"]["OSV"] == "ok"


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


def make_test_app(tmp_path):
    settings = Settings(
        app_env="test",
        host="127.0.0.1",
        port=0,
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'sca-monitor.sqlite3'}",
        database_path=tmp_path / "sca-monitor.sqlite3",
        frontend_dir=tmp_path,
        smoke_token="test",
    )
    return ScaMonitorApp(settings)


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
