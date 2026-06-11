from __future__ import annotations

import json
import socket
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator
from uuid import uuid4
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .app import ScaMonitorApp
from .db import canonical_package_name
from .osv import AdvisoryImport

OSV_DUMP_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORIES_API_URL = "https://api.github.com/advisories"


@dataclass(frozen=True)
class OsvSyncResult:
    source: str
    ecosystem: str
    scanned: int
    processed: int
    skipped: int
    imported_rows: int
    failed: int
    dump_url: str
    scan_limit_reached: bool


@dataclass(frozen=True)
class CisaKevSyncResult:
    source: str
    processed: int
    imported_rows: int
    enriched_advisories: int
    rematched_impacts: int
    failed: int
    catalog_url: str
    catalog_version: str | None
    date_released: str | None


@dataclass(frozen=True)
class NvdCveSyncResult:
    source: str
    cve_id: str
    imported_rows: int
    rematched_impacts: int
    api_url: str


@dataclass(frozen=True)
class NvdCveBatchSyncResult:
    source: str
    processed: int
    imported_rows: int
    rematched_impacts: int
    failed: int
    results: list[dict[str, Any]]
    api_url: str
    request_delay_seconds: float


@dataclass(frozen=True)
class GhsaSyncResult:
    source: str
    processed: int
    imported_rows: int
    rematched_impacts: int
    failed: int
    api_url: str
    query: dict[str, Any]


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
    source: str = "OSV",
    malicious_only: bool = False,
    scan_limit: int | None = None,
) -> OsvSyncResult:
    url = dump_url or osv_dump_url(ecosystem)
    sync_source = normalize_sync_source(source)
    scanned = 0
    processed = 0
    skipped = 0
    imported_rows = 0
    failed = 0
    scan_limit_reached = False
    owner = lock_owner or default_lock_owner(f"{sync_source.lower()}-{ecosystem}")

    try:
        with app.advisory_sync_lock(sync_source, owner, ttl_seconds=lock_ttl_seconds):
            for payload in iter_osv_dump_payloads(url=url, zip_path=zip_path):
                if limit is not None and processed >= limit:
                    break
                if scan_limit is not None and scanned >= scan_limit:
                    scan_limit_reached = True
                    break
                scanned += 1
                advisory_id = str(payload.get("id") or "")
                if malicious_only and not advisory_id.startswith("MAL-"):
                    skipped += 1
                    continue
                processed += 1
                try:
                    imported_rows += app.import_osv_payload(payload, source_override=sync_source)["imported"]
                except Exception:
                    failed += 1
            status = "ok" if failed == 0 and not scan_limit_reached else "partial"
            error_message = "scan_limit reached before dump exhausted" if scan_limit_reached else None
            app.record_advisory_sync(sync_source, status, f"{ecosystem}:dump", error_message, imported_count=imported_rows)
    except Exception as exc:
        app.record_advisory_sync(sync_source, "error", f"{ecosystem}:dump", str(exc), imported_count=0)
        raise

    return OsvSyncResult(
        source=sync_source,
        ecosystem=ecosystem,
        scanned=scanned,
        processed=processed,
        skipped=skipped,
        imported_rows=imported_rows,
        failed=failed,
        dump_url=url,
        scan_limit_reached=scan_limit_reached,
    )


def normalize_sync_source(source: str) -> str:
    value = (source or "OSV").strip()
    aliases = {
        "osv": "OSV",
        "openssf": "OpenSSF",
        "openssf_malicious_packages": "OpenSSF",
        "malicious": "OpenSSF",
    }
    return aliases.get(value.lower(), value)


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
    enriched_advisories = 0
    rematched_impacts = 0
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
                        enrichment = app.enrich_known_exploited_advisories(conn, item.get("cveID"))
                        enriched_advisories += enrichment["enriched_advisories"]
                        rematched_impacts += enrichment["rematched_impacts"]
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
        enriched_advisories=enriched_advisories,
        rematched_impacts=rematched_impacts,
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


def load_github_advisories(
    *,
    api_url: str = GITHUB_ADVISORIES_API_URL,
    token: str | None = None,
    query: dict[str, Any] | None = None,
    timeout_seconds: int = 60,
) -> list[dict[str, Any]]:
    clean_query = {key: value for key, value in (query or {}).items() if value not in (None, "")}
    url = f"{api_url}?{urlencode(clean_query)}" if clean_query else api_url
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "sca-monitor/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, list):
        raise ValueError("GitHub advisory API response must be a list")
    return payload


def parse_ghsa_advisory(item: dict[str, Any]) -> list[AdvisoryImport]:
    ghsa_id = str(item.get("ghsa_id") or "").strip()
    if not ghsa_id:
        raise ValueError("GHSA item ghsa_id required")
    vulnerabilities = item.get("vulnerabilities") or []
    package_count = sum(
        1
        for vulnerability in vulnerabilities
        if (vulnerability.get("package") or {}).get("ecosystem") and (vulnerability.get("package") or {}).get("name")
    )
    imports: list[AdvisoryImport] = []
    for vulnerability in vulnerabilities:
        package = vulnerability.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "").strip()
        package_name = str(package.get("name") or "").strip()
        if not ecosystem or not package_name:
            continue
        advisory_id = ghsa_id if package_count == 1 else f"{ghsa_id}:{ecosystem}/{package_name}"
        fixed_version = ghsa_first_patched_version(vulnerability)
        imports.append(
            AdvisoryImport(
                advisory_id=advisory_id,
                source="GHSA",
                summary=str(item.get("summary") or item.get("description") or ghsa_id),
                severity=normalize_severity(item.get("severity")),
                ecosystem=ecosystem,
                package_name=package_name,
                canonical_package_name=canonical_package_name(ecosystem, package_name),
                affected_versions=[],
                affected_ranges=ghsa_affected_ranges(vulnerability),
                fixed_version=fixed_version,
                is_known_exploited=False,
                is_malicious_package=str(item.get("type") or "").lower() == "malware",
                published_at=item.get("published_at"),
                modified_at=item.get("updated_at"),
                raw_payload=item,
            )
        )
    if not imports:
        raise ValueError(f"GHSA advisory has no package vulnerability entries: {ghsa_id}")
    return imports


def sync_github_advisories(
    app: ScaMonitorApp,
    *,
    api_url: str = GITHUB_ADVISORIES_API_URL,
    token: str | None = None,
    json_path: Path | None = None,
    limit: int | None = None,
    advisory_type: str | None = None,
    ecosystem: str | None = None,
    severity: str | None = None,
    ghsa_id: str | None = None,
    cve_id: str | None = None,
    modified: str | None = None,
    published: str | None = None,
    updated: str | None = None,
    sort: str = "updated",
    direction: str = "desc",
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 3600,
) -> GhsaSyncResult:
    query = {
        "type": advisory_type,
        "ecosystem": ecosystem,
        "severity": severity,
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "modified": modified,
        "published": published,
        "updated": updated,
        "sort": sort,
        "direction": direction,
        "per_page": min(limit or 100, 100),
    }
    payload = json.loads(json_path.read_text(encoding="utf-8")) if json_path else load_github_advisories(api_url=api_url, token=token, query=query)
    if not isinstance(payload, list):
        raise ValueError("GitHub advisory payload must be a list")
    processed = 0
    imported_rows = 0
    rematched_impacts = 0
    failed = 0
    owner = lock_owner or default_lock_owner("ghsa")
    try:
        with app.advisory_sync_lock("GHSA", owner, ttl_seconds=lock_ttl_seconds):
            for item in payload:
                if limit is not None and processed >= limit:
                    break
                processed += 1
                try:
                    for advisory in parse_ghsa_advisory(item):
                        with app.db.connect() as conn:
                            changed = app.upsert_advisory(conn, advisory)
                            if changed:
                                rematched_impacts += app.rematch_latest_snapshots_for_advisory(conn, advisory)
                            imported_rows += 1
                except Exception:
                    failed += 1
            status = "ok" if failed == 0 else "partial"
            app.record_advisory_sync("GHSA", status, f"advisories:{processed}", None, imported_count=imported_rows)
    except Exception as exc:
        app.record_advisory_sync("GHSA", "error", "advisories", str(exc), imported_count=0)
        raise
    return GhsaSyncResult(
        source="GHSA",
        processed=processed,
        imported_rows=imported_rows,
        rematched_impacts=rematched_impacts,
        failed=failed,
        api_url=api_url,
        query={key: value for key, value in query.items() if value not in (None, "")},
    )


def load_nvd_cve_payload(
    *,
    cve_id: str,
    api_url: str = NVD_CVE_API_URL,
    api_key: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    if not cve_id:
        raise ValueError("cve_id required")
    url = f"{api_url}?{urlencode({'cveId': cve_id})}"
    headers = {"Accept": "application/json", "User-Agent": "sca-monitor/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def nvd_cve_ids_from_payload(payload: dict[str, Any]) -> list[str]:
    cve_ids: list[str] = []
    seen: set[str] = set()
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or item
        cve_id = str(cve.get("id") or "").strip().upper()
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            cve_ids.append(cve_id)
    return cve_ids


def load_nvd_modified_cve_ids(
    *,
    last_mod_start: str,
    last_mod_end: str,
    api_url: str = NVD_CVE_API_URL,
    api_key: str | None = None,
    timeout_seconds: int = 60,
    json_path: Path | None = None,
    results_per_page: int = 2000,
) -> list[str]:
    if not last_mod_start or not last_mod_end:
        raise ValueError("last_mod_start and last_mod_end are required")
    if json_path is not None:
        return nvd_cve_ids_from_payload(json.loads(json_path.read_text(encoding="utf-8")))
    if results_per_page <= 0:
        raise ValueError("results_per_page must be greater than 0")
    headers = {"Accept": "application/json", "User-Agent": "sca-monitor/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    cve_ids: list[str] = []
    seen: set[str] = set()
    start_index = 0
    while True:
        query = {
            "lastModStartDate": last_mod_start,
            "lastModEndDate": last_mod_end,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        request = Request(f"{api_url}?{urlencode(query)}", headers=headers)
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        for cve_id in nvd_cve_ids_from_payload(payload):
            if cve_id not in seen:
                seen.add(cve_id)
                cve_ids.append(cve_id)
        page_size = int(payload.get("resultsPerPage") or 0)
        total_results = int(payload.get("totalResults") or 0)
        start_index = int(payload.get("startIndex") or start_index) + page_size
        if page_size <= 0 or start_index >= total_results:
            return cve_ids


def parse_nvd_cve_vulnerability(item: dict[str, Any]) -> list[AdvisoryImport]:
    cve = item.get("cve") or item
    cve_id = str(cve.get("id") or "").strip()
    if not cve_id:
        raise ValueError("NVD CVE id required")
    cpe_matches = vulnerable_cpe_matches(cve.get("configurations") or [])
    if not cpe_matches:
        cpe_matches = [{"criteria": f"cve:{cve_id}"}]

    imports: list[AdvisoryImport] = []
    for cpe_match in cpe_matches:
        criteria = str(cpe_match.get("criteria") or "").strip()
        package_name = package_name_from_cpe(criteria) or cve_id
        advisory_id = cve_id if len(cpe_matches) == 1 else f"{cve_id}:{package_name}"
        imports.append(
            AdvisoryImport(
                advisory_id=advisory_id,
                source="NVD",
                summary=nvd_english_description(cve) or cve_id,
                severity=nvd_severity(cve),
                ecosystem="cpe",
                package_name=package_name,
                canonical_package_name=canonical_package_name("cpe", package_name),
                affected_versions=nvd_affected_versions(cpe_match),
                affected_ranges=[cpe_match],
                fixed_version=None,
                is_known_exploited=bool(cve.get("cisaExploitAdd")),
                is_malicious_package=False,
                published_at=cve.get("published"),
                modified_at=cve.get("lastModified"),
                raw_payload=cve,
            )
        )
    return imports


def normalize_severity(value: Any) -> str:
    severity = str(value or "").lower()
    if severity in {"critical", "high", "medium", "low"}:
        return severity
    if severity == "moderate":
        return "medium"
    return "medium"


def ghsa_first_patched_version(vulnerability: dict[str, Any]) -> str | None:
    value = vulnerability.get("first_patched_version")
    if isinstance(value, dict):
        identifier = value.get("identifier")
        return str(identifier) if identifier else None
    if value:
        return str(value)
    return None


def ghsa_affected_ranges(vulnerability: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerable_range = str(vulnerability.get("vulnerable_version_range") or "").strip()
    if not vulnerable_range:
        return []
    range_item: dict[str, Any] = {"type": "GHSA", "vulnerable_version_range": vulnerable_range}
    events = ghsa_range_events(vulnerable_range)
    if events:
        range_item["events"] = events
    return [range_item]


def ghsa_range_events(vulnerable_range: str) -> list[dict[str, str]]:
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    for clause in vulnerable_range.split(","):
        part = clause.strip()
        if not part:
            continue
        for operator in (">=", "<=", "<", "="):
            if part.startswith(operator):
                version = part[len(operator) :].strip()
                if not version:
                    break
                if operator == ">=":
                    introduced = version
                elif operator == "<":
                    fixed = version
                elif operator == "<=":
                    last_affected = version
                elif operator == "=":
                    introduced = version
                    last_affected = version
                break
    events: list[dict[str, str]] = [{"introduced": introduced or "0"}]
    if fixed:
        events.append({"fixed": fixed})
    elif last_affected:
        events.append({"last_affected": last_affected})
    return events


def sync_nvd_cve(
    app: ScaMonitorApp,
    cve_id: str,
    *,
    api_url: str = NVD_CVE_API_URL,
    api_key: str | None = None,
    json_path: Path | None = None,
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 3600,
    record_state: bool = True,
) -> NvdCveSyncResult:
    owner = lock_owner or default_lock_owner("nvd-cve")
    payload = json.loads(json_path.read_text(encoding="utf-8")) if json_path else load_nvd_cve_payload(cve_id=cve_id, api_url=api_url, api_key=api_key)
    vulnerabilities = payload.get("vulnerabilities") or []
    imported_rows = 0
    rematched_impacts = 0
    with app.advisory_sync_lock("NVD", owner, ttl_seconds=lock_ttl_seconds):
        for item in vulnerabilities:
            for advisory in parse_nvd_cve_vulnerability(item):
                with app.db.connect() as conn:
                    changed = app.upsert_advisory(conn, advisory)
                    if changed:
                        rematched_impacts += app.rematch_latest_snapshots_for_advisory(conn, advisory)
                    imported_rows += 1
        status = "ok" if imported_rows else "partial"
        error_message = None if imported_rows else f"NVD CVE not found: {cve_id}"
        if record_state:
            app.record_advisory_sync(
                "NVD",
                status,
                cve_id,
                error_message,
                imported_count=imported_rows,
                cursor=cve_id,
                records_processed=1,
            )
    return NvdCveSyncResult(source="NVD", cve_id=cve_id, imported_rows=imported_rows, rematched_impacts=rematched_impacts, api_url=api_url)


def sync_nvd_cves(
    app: ScaMonitorApp,
    cve_ids: list[str],
    *,
    api_url: str = NVD_CVE_API_URL,
    api_key: str | None = None,
    json_dir: Path | None = None,
    limit: int | None = None,
    lock_ttl_seconds: int = 3600,
    delay_seconds: float = 0.0,
    sleep_func: Callable[[float], None] = time.sleep,
    success_cursor: str | None = None,
) -> NvdCveBatchSyncResult:
    if delay_seconds < 0:
        raise ValueError("delay_seconds must be greater than or equal to 0")
    processed = 0
    imported_rows = 0
    rematched_impacts = 0
    failed = 0
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    unique_cve_ids: list[str] = []
    for raw_cve_id in cve_ids:
        cve_id = raw_cve_id.strip().upper()
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        unique_cve_ids.append(cve_id)
    if limit is not None:
        unique_cve_ids = unique_cve_ids[:limit]

    last_successful_cve_id: str | None = None
    for index, cve_id in enumerate(unique_cve_ids):
        if limit is not None and processed >= limit:
            break
        processed += 1
        json_path = json_dir / f"{cve_id}.json" if json_dir else None
        uses_remote_api = not (json_path and json_path.exists())
        try:
            result = sync_nvd_cve(
                app,
                cve_id,
                api_url=api_url,
                api_key=api_key,
                json_path=json_path if json_path and json_path.exists() else None,
                lock_owner=default_lock_owner(f"nvd-cve-{cve_id.lower()}"),
                lock_ttl_seconds=lock_ttl_seconds,
                record_state=False,
            )
            imported_rows += result.imported_rows
            rematched_impacts += result.rematched_impacts
            results.append(result.__dict__)
            if result.imported_rows:
                last_successful_cve_id = cve_id
        except Exception as exc:  # noqa: BLE001 - batch sync should report per-CVE failures.
            failed += 1
            results.append({"source": "NVD", "cve_id": cve_id, "status": "failed", "error": exc.__class__.__name__, "detail": str(exc)})
        if uses_remote_api and delay_seconds > 0 and index < len(unique_cve_ids) - 1:
            sleep_func(delay_seconds)
    if processed:
        app.record_advisory_sync(
            "NVD",
            "ok" if failed == 0 else "partial",
            last_successful_cve_id,
            None if failed == 0 else f"{failed} NVD CVE sync failures",
            imported_count=imported_rows,
            cursor=success_cursor or last_successful_cve_id,
            records_processed=processed,
        )
    return NvdCveBatchSyncResult(
        source="NVD",
        processed=processed,
        imported_rows=imported_rows,
        rematched_impacts=rematched_impacts,
        failed=failed,
        results=results,
        api_url=api_url,
        request_delay_seconds=delay_seconds,
    )


def vulnerable_cpe_matches(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for config in configurations:
        for node in config.get("nodes") or []:
            for cpe_match in node.get("cpeMatch") or []:
                if cpe_match.get("vulnerable") is True and cpe_match.get("criteria"):
                    matches.append(cpe_match)
    return matches


def package_name_from_cpe(criteria: str) -> str | None:
    parts = criteria.split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor = parts[3].replace("\\", "")
        product = parts[4].replace("\\", "")
        if vendor and product:
            return f"{vendor}/{product}"
    return None


def nvd_english_description(cve: dict[str, Any]) -> str | None:
    for item in cve.get("descriptions") or []:
        if str(item.get("lang") or "").lower() == "en" and item.get("value"):
            return str(item["value"])
    return None


def nvd_severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics") or {}
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(metric_name) or []:
            severity = str(item.get("cvssData", {}).get("baseSeverity") or item.get("baseSeverity") or "").lower()
            if severity in {"critical", "high", "medium", "low"}:
                return severity
    return "medium"


def nvd_affected_versions(cpe_match: dict[str, Any]) -> list[str]:
    versions = []
    for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
        if cpe_match.get(key):
            versions.append(f"{key}:{cpe_match[key]}")
    return versions


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
