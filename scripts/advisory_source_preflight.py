#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.sca_monitor.advisory_sync import CISA_KEV_CATALOG_URL, GITHUB_ADVISORIES_API_URL, NVD_CVE_API_URL, OSV_DUMP_BASE_URL
from backend.sca_monitor.osv import OSV_API_BASE_URL


DEFAULT_SOURCES = [
    {
        "id": "OSV_API",
        "name": "OSV API",
        "url": f"{OSV_API_BASE_URL}/OSV-2020-111",
        "required": True,
        "required_by": ["FR-009", "SRC-001", "REQ-NET-006"],
    },
    {
        "id": "OSV_DUMP",
        "name": "OSV ecosystem dump",
        "url": f"{OSV_DUMP_BASE_URL}/npm/all.zip",
        "required": True,
        "required_by": ["FR-009", "SRC-001", "REQ-NET-006"],
    },
    {
        "id": "CISA_KEV",
        "name": "CISA KEV catalog",
        "url": CISA_KEV_CATALOG_URL,
        "required": True,
        "required_by": ["FR-010", "SRC-002", "REQ-NET-006"],
    },
    {
        "id": "GHSA",
        "name": "GitHub Security Advisory",
        "url": GITHUB_ADVISORIES_API_URL,
        "required": False,
        "required_by": ["FR-011", "SRC-003", "REQ-NET-006"],
    },
    {
        "id": "NVD",
        "name": "NVD CVE API",
        "url": NVD_CVE_API_URL,
        "required": False,
        "required_by": ["FR-011", "SRC-004", "REQ-NET-006"],
    },
    {
        "id": "OpenSSF",
        "name": "OpenSSF malicious packages",
        "url": "https://github.com/ossf/malicious-packages",
        "required": True,
        "required_by": ["FR-009", "SRC-005", "REQ-NET-006"],
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preflight advisory source outbound access without printing URL secrets.")
    parser.add_argument("--source-spec", type=Path, help="JSON file containing source objects with id, url, required_by, required.")
    parser.add_argument("--check", action="store_true", help="Perform HTTP GET checks. Without this flag, only configuration is listed.")
    parser.add_argument("--list-only", action="store_true", help="List configured sources without network access.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-source network timeout in seconds.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def sanitize_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def source_metadata(source: dict[str, Any]) -> dict[str, Any]:
    parts = urlsplit(str(source["url"]))
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return {
        "id": source["id"],
        "name": source.get("name", source["id"]),
        "scheme": parts.scheme,
        "host": parts.hostname,
        "port": port,
        "url": sanitize_url(str(source["url"])),
        "required": bool(source.get("required", True)),
        "required_by": list(source.get("required_by") or []),
    }


def load_sources(path: Path | None) -> list[dict[str, Any]]:
    if not path:
        return [dict(source) for source in DEFAULT_SOURCES]
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("source spec must be a JSON array")
    return [dict(source) for source in payload]


def check_source(source: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    metadata = source_metadata(source)
    started = time.monotonic()
    request = Request(
        str(source["url"]),
        headers={
            "User-Agent": "sca-monitor-advisory-source-preflight/1.0",
            "Accept": "application/json,*/*;q=0.8",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            status_code = int(response.status)
            ok = 200 <= status_code < 400
            detail = f"HTTP {status_code}"
    except HTTPError as exc:
        status_code = int(exc.code)
        ok = 200 <= status_code < 400
        detail = f"HTTP {status_code}"
    except (TimeoutError, socket.timeout):
        status_code = None
        ok = False
        detail = "timeout"
    except (URLError, ssl.SSLError, OSError) as exc:
        status_code = None
        ok = False
        detail = exc.__class__.__name__
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if ok:
        status = "ok"
    else:
        status = "blocker" if metadata["required"] else "warning"
    return {
        **metadata,
        "status": status,
        "http_status": status_code,
        "elapsed_ms": elapsed_ms,
        "detail": detail,
    }


def preflight(sources: list[dict[str, Any]], *, check: bool, timeout: float) -> dict[str, Any]:
    source_list = [source_metadata(source) for source in sources]
    if not check:
        return {"status": "configured", "checked": False, "sources": source_list, "checks": []}
    checks = [check_source(source, timeout=timeout) for source in sources]
    blockers = [item for item in checks if item["status"] == "blocker"]
    warnings = [item for item in checks if item["status"] == "warning"]
    return {
        "status": "blocked" if blockers else "degraded" if warnings else "ok",
        "checked": True,
        "sources": source_list,
        "checks": checks,
        "summary": {"ok": len([item for item in checks if item["status"] == "ok"]), "blockers": len(blockers), "warnings": len(warnings)},
    }


def main() -> int:
    args = parse_args()
    sources = load_sources(args.source_spec)
    result = preflight(sources, check=args.check and not args.list_only, timeout=args.timeout)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"advisory source preflight: {result['status']}")
        for source in result["sources"]:
            print(f"- {source['id']}: {source['host']}:{source['port']} ({', '.join(source['required_by'])})")
        for check in result["checks"]:
            print(f"- {check['status']}: {check['id']}: {check['detail']}")
    return 2 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
