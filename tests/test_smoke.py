from backend.sca_monitor.db import canonical_package_name


def test_pypi_canonical_name():
    assert canonical_package_name("PyPI", "Django_REST.Framework") == "django-rest-framework"


def test_npm_canonical_name():
    assert canonical_package_name("npm", "Lodash") == "lodash"

