from __future__ import annotations

import json
import socket
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator
from uuid import uuid4
from urllib.request import Request, urlopen

from .app import ScaMonitorApp
from .db import canonical_package_name
from .osv import AdvisoryImport

OSV_DUMP_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class OsvSyncResult:
    source: str
    ecosystem: str
    processed: int
    imported_rows: int
    failed: int
    dump_url: str


@dataclass(frozen=True)
class CisaKevSyncResult:
    source: str
    processed: int
    imported_rows: int
    failed: int
    catalog_url: str
    catalog_version: str | None
    date_released: str | None


def osv_dump_url(ecosystem: str) -> str:
    if not ecosystem:
        raise ValueError("ecosystem required")
    return f"{OSV_DUMP_BASE_URL}/{ecosystem}/all.zip"


def sync_osv_ecosystem_dump(
    app: ScaMonitorApp,
    ecosystem: str,
    *,
    limit: int | None = None,
    dump_url: str | None = None,
    zip_path: Path | None = None,
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 3600,
) -> OsvSyncResult:
    url = dump_url or osv_dump_url(ecosystem)
    processed = 0
    imported_rows = 0
    failed = 0
    owner = lock_owner or default_lock_owner(ecosystem)

    try:
        with app.advisory_sync_lock("OSV", owner, ttl_seconds=lock_ttl_seconds):
            for payload in iter_osv_dump_payloads(url=url, zip_path=zip_path):
                if limit is not None and processed >= limit:
                    break
                processed += 1
                try:
                    imported_rows += app.import_osv_payload(payload)["imported"]
                except Exception:
                    failed += 1
            status = "ok" if failed == 0 else "partial"
            app.record_advisory_sync("OSV", status, f"{ecosystem}:dump", None, imported_count=0)
    except Exception as exc:
        app.record_advisory_sync("OSV", "error", f"{ecosystem}:dump", str(exc), imported_count=0)
        raise

    return OsvSyncResult(
        source="OSV",
        ecosystem=ecosystem,
        processed=processed,
        imported_rows=imported_rows,
        failed=failed,
        dump_url=url,
    )


def sync_cisa_kev_catalog(
    app: ScaMonitorApp,
    *,
    limit: int | None = None,
    catalog_url: str = CISA_KEV_CATALOG_URL,
    json_path: Path | None = None,
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 3600,
) -> CisaKevSyncResult:
    catalog = load_cisa_kev_catalog(catalog_url=catalog_url, json_path=json_path)
    processed = 0
    imported_rows = 0
    failed = 0
    owner = lock_owner or default_lock_owner("cisa-kev")
    catalog_version = catalog.get("catalogVersion")
    date_released = catalog.get("dateReleased")

    try:
        with app.advisory_sync_lock("CISA_KEV", owner, ttl_seconds=lock_ttl_seconds):
            for item in catalog.get("vulnerabilities") or []:
                if limit is not None and processed >= limit:
                    break
                processed += 1
                try:
                    advisory = parse_cisa_kev_vulnerability(item, catalog)
                    with app.db.connect() as conn:
                        app.upsert_advisory(conn, advisory)
                    imported_rows += 1
                except Exception:
                    failed += 1
            status = "ok" if failed == 0 else "partial"
            app.record_advisory_sync(
                "CISA_KEV",
                status,
                f"catalog:{catalog_version or date_released or 'unknown'}",
                None,
                imported_count=imported_rows,
            )
    except Exception as exc:
        app.record_advisory_sync("CISA_KEV", "error", "catalog", str(exc), imported_count=0)
        raise

    return CisaKevSyncResult(
        source="CISA_KEV",
        processed=processed,
        imported_rows=imported_rows,
        failed=failed,
        catalog_url=catalog_url,
        catalog_version=str(catalog_version) if catalog_version else None,
        date_released=str(date_released) if date_released else None,
    )


def load_cisa_kev_catalog(*, catalog_url: str, json_path: Path | None = None) -> dict[str, Any]:
    if json_path is not None:
        return json.loads(json_path.read_text(encoding="utf-8"))
    request = Request(catalog_url, headers={"Accept": "application/json", "User-Agent": "sca-monitor/0.1"})
    with urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def parse_cisa_kev_vulnerability(item: dict[str, Any], catalog: dict[str, Any] | None = None) -> AdvisoryImport:
    cve_id = str(item.get("cveID") or "").strip()
    if not cve_id:
        raise ValueError("CISA KEV item cveID required")
    vendor = str(item.get("vendorProject") or "unknown-vendor").strip()
    product = str(item.get("product") or "unknown-product").strip()
    package_name = f"{vendor}/{product}"
    catalog_context = {
        "catalogVersion": (catalog or {}).get("catalogVersion"),
        "dateReleased": (catalog or {}).get("dateReleased"),
    }
    raw_payload = {**catalog_context, **item}
    summary = str(item.get("shortDescription") or item.get("vulnerabilityName") or cve_id)
    modified_at = item.get("dateAdded") or (catalog or {}).get("dateReleased")
    return AdvisoryImport(
        advisory_id=f"CISA_KEV:{cve_id}",
        source="CISA_KEV",
        summary=summary,
        severity="critical",
        ecosystem="cve",
        package_name=package_name,
        canonical_package_name=canonical_package_name("cve", package_name),
        affected_versions=[],
        affected_ranges=[],
        fixed_version=None,
        is_known_exploited=True,
        is_malicious_package=False,
        published_at=item.get("dateAdded"),
        modified_at=modified_at,
        raw_payload=raw_payload,
    )


def default_lock_owner(ecosystem: str) -> str:
    return f"advisory-sync:{ecosystem}:{socket.gethostname()}:{uuid4()}"


def iter_osv_dump_payloads(*, url: str, zip_path: Path | None = None) -> Iterator[dict]:
    if zip_path is not None:
        yield from iter_zip_payloads(zip_path)
        return

    with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
        download_file(url, Path(temp_file.name))
        yield from iter_zip_payloads(Path(temp_file.name))


def download_file(url: str, path: Path, opener: Callable | None = None) -> None:
    request = Request(url, headers={"Accept": "application/zip", "User-Agent": "sca-monitor/0.1"})
    open_url = opener or urlopen
    with open_url(request, timeout=60) as response:
        with path.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)


def iter_zip_payloads(path: Path) -> Iterator[dict]:
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith(".json"):
                continue
            with archive.open(name) as entry:
                yield json.loads(entry.read().decode("utf-8"))
