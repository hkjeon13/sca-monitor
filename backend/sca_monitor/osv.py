from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .db import canonical_package_name

OSV_API_BASE_URL = "https://api.osv.dev/v1/vulns"


@dataclass(frozen=True)
class AdvisoryImport:
    advisory_id: str
    source: str
    summary: str
    severity: str
    ecosystem: str
    package_name: str
    canonical_package_name: str
    affected_versions: list[str]
    affected_ranges: list[dict[str, Any]]
    fixed_version: str | None
    is_known_exploited: bool
    is_malicious_package: bool
    published_at: str | None
    modified_at: str | None
    raw_payload: dict[str, Any]


def fetch_osv_advisory(advisory_id: str, timeout_seconds: float = 10.0) -> dict[str, Any]:
    if not advisory_id:
        raise ValueError("advisory_id required")
    url = f"{OSV_API_BASE_URL}/{advisory_id}"
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "sca-monitor/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise ValueError(f"OSV advisory not found: {advisory_id}") from exc
        raise RuntimeError(f"OSV API returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"OSV API request failed: {exc.reason}") from exc


def parse_osv_advisories(payload: dict[str, Any], source_override: str | None = None) -> list[AdvisoryImport]:
    advisory_id = str(payload.get("id") or "")
    if not advisory_id:
        raise ValueError("OSV payload id required")

    imports: list[AdvisoryImport] = []
    source = source_override or ("OpenSSF" if advisory_id.startswith("MAL-") else "OSV")
    affected_items = payload.get("affected") or []
    package_count = sum(1 for affected in affected_items if (affected.get("package") or {}).get("ecosystem") and (affected.get("package") or {}).get("name"))
    for affected in affected_items:
        package = affected.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "").strip()
        package_name = str(package.get("name") or "").strip()
        if not ecosystem or not package_name:
            continue
        row_advisory_id = advisory_id
        if package_count > 1:
            row_advisory_id = f"{advisory_id}:{ecosystem}/{package_name}"
        imports.append(
            AdvisoryImport(
                advisory_id=row_advisory_id,
                source=source,
                summary=str(payload.get("summary") or payload.get("details") or advisory_id),
                severity=osv_severity(payload, affected),
                ecosystem=ecosystem,
                package_name=package_name,
                canonical_package_name=canonical_package_name(ecosystem, package_name),
                affected_versions=sorted({str(version) for version in affected.get("versions") or []}),
                affected_ranges=affected.get("ranges") or [],
                fixed_version=first_fixed_version(affected),
                is_known_exploited=False,
                is_malicious_package=advisory_id.startswith("MAL-"),
                published_at=payload.get("published"),
                modified_at=payload.get("modified"),
                raw_payload=payload,
            )
        )
    if not imports:
        raise ValueError(f"OSV advisory has no package affected entries: {advisory_id}")
    return imports


def first_fixed_version(affected: dict[str, Any]) -> str | None:
    for range_item in affected.get("ranges") or []:
        for event in range_item.get("events") or []:
            fixed = event.get("fixed")
            if fixed:
                return str(fixed)
    return None


def osv_severity(payload: dict[str, Any], affected: dict[str, Any]) -> str:
    affected_specific = affected.get("database_specific") or {}
    payload_specific = payload.get("database_specific") or {}
    value = str(affected_specific.get("severity") or payload_specific.get("severity") or "").lower()
    if value in {"critical", "high", "medium", "low"}:
        return value
    if value == "moderate":
        return "medium"

    for item in payload.get("severity") or []:
        score = str(item.get("score") or "")
        if score.startswith("CVSS:"):
            return cvss_vector_to_level(score)
    return "medium"


def cvss_vector_to_level(vector: str) -> str:
    if "/AV:N/" in vector and "/PR:N/" in vector and "/UI:N/" in vector:
        return "critical"
    if "/AV:N/" in vector:
        return "high"
    return "medium"
