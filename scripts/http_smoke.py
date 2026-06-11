#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


DEFAULT_PATHS = ("/health", "/ready", "/api/v1/overview", "/")
JSON_PATHS = {"/health", "/ready", "/api/v1/overview"}


@dataclass
class CheckResult:
    path: str
    url: str
    ok: bool
    status: int | None
    elapsed_ms: int
    json_ok: bool | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "url": self.url,
            "ok": self.ok,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "json_ok": self.json_ok,
            "error": self.error,
        }


def smoke_url(base_url: str, path: str, timeout: float) -> CheckResult:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    started = time.monotonic()
    status: int | None = None
    error: str | None = None
    json_ok: bool | None = None
    ok = False
    try:
        request = Request(
            url,
            headers={
                "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
                "User-Agent": "sca-monitor-http-smoke/1.0",
            },
        )
        with urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read(1024 * 1024)
        ok = 200 <= status < 300
        if path in JSON_PATHS:
            try:
                json.loads(body.decode("utf-8"))
                json_ok = True
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                json_ok = False
                ok = False
                error = f"invalid JSON response: {exc}"
    except HTTPError as exc:
        status = int(exc.code)
        error = f"HTTP {exc.code}: {exc.reason}"
    except URLError as exc:
        error = f"URL error: {exc.reason}"
    except TimeoutError:
        error = "request timed out"
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return CheckResult(path=path, url=url, ok=ok, status=status, elapsed_ms=elapsed_ms, json_ok=json_ok, error=error)


def run_smoke(base_url: str, paths: list[str], timeout: float) -> dict[str, Any]:
    checks = [smoke_url(base_url, path, timeout) for path in paths]
    ok = all(check.ok for check in checks)
    return {
        "status": "ok" if ok else "failed",
        "base_url": base_url,
        "checks": [check.as_dict() for check in checks],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run read-only HTTP smoke checks against SCA Monitor.")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SCA_MONITOR_PUBLIC_URL") or os.environ.get("SCA_MONITOR_BASE_URL") or "http://127.0.0.1:18780",
        help="Base URL to check. Defaults to SCA_MONITOR_PUBLIC_URL, SCA_MONITOR_BASE_URL, then localhost.",
    )
    parser.add_argument("--path", action="append", dest="paths", help="Path to check. May be repeated.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = args.paths or list(DEFAULT_PATHS)
    result = run_smoke(args.base_url, paths, args.timeout)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"http smoke {result['status']}: {result['base_url']}")
        for check in result["checks"]:
            suffix = "" if check["ok"] else f" error={check['error']}"
            print(f"- {check['path']} status={check['status']} elapsed_ms={check['elapsed_ms']}{suffix}")
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
