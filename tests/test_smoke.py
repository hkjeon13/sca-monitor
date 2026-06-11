from backend.sca_monitor.db import Database, canonical_package_name
from backend.sca_monitor.migrations import REQUIRED_MIGRATION_VERSION


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
