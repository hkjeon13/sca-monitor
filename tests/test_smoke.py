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

    imported = app.import_osv_payload(osv_fixture())

    assert imported == 1
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
