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
POSTGRES_SPLIT_METRICS = ("sca_monitor_postgres_split_required", "sca_monitor_postgres_split_ready")


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


def metric_names(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line.split(None, 1)[0].split("{", 1)[0])
    return names


def metric_values(text: str) -> dict[str, float]:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        name = parts[0].split("{", 1)[0]
        try:
            values[name] = float(parts[1])
        except ValueError:
            continue
    return values


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError("expected one of true/false/1/0/yes/no/on/off")


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


def fetch_text(base_url: str, path: str, timeout: float) -> tuple[int, str]:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = Request(url, headers={"Accept": "text/plain,*/*;q=0.8", "User-Agent": "sca-monitor-http-smoke/1.0"})
    with urlopen(request, timeout=timeout) as response:
        return int(response.status), response.read(1024 * 1024).decode("utf-8", "replace")


def fetch_json(base_url: str, path: str, timeout: float) -> tuple[int, dict[str, Any]]:
    status, text = fetch_text(base_url, path, timeout)
    return status, json.loads(text)


def check_postgres_split_metrics(base_url: str, timeout: float) -> dict[str, Any]:
    try:
        status, text = fetch_text(base_url, "/metrics", timeout)
        names = metric_names(text)
        missing = [name for name in POSTGRES_SPLIT_METRICS if name not in names]
        return {
            "required_metric_present": "sca_monitor_postgres_split_required" in names,
            "ready_metric_present": "sca_monitor_postgres_split_ready" in names,
            "ok": status == 200 and not missing,
            "status": status,
            "missing": missing,
        }
    except (HTTPError, URLError, TimeoutError) as exc:
        return {
            "required_metric_present": False,
            "ready_metric_present": False,
            "ok": False,
            "status": getattr(exc, "code", None),
            "missing": list(POSTGRES_SPLIT_METRICS),
            "error": str(exc),
        }


def check_postgres_split_consistency(base_url: str, timeout: float, expected_split_required: bool) -> dict[str, Any]:
    try:
        ready_status, ready = fetch_json(base_url, "/ready", timeout)
        metrics_status, metrics_text = fetch_text(base_url, "/metrics", timeout)
        metrics = metric_values(metrics_text)
        ready_require_split = bool((ready.get("cutover_required") or {}).get("require_split"))
        metric_split_required = int(metrics.get("sca_monitor_postgres_split_required", -1))
        ok = ready_status == 200 and metrics_status == 200 and ready_require_split == expected_split_required and metric_split_required == int(expected_split_required)
        return {
            "expected_split_required": expected_split_required,
            "ready_require_split": ready_require_split,
            "metric_split_required": metric_split_required,
            "ok": ok,
        }
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "expected_split_required": expected_split_required,
            "ready_require_split": None,
            "metric_split_required": None,
            "ok": False,
            "error": str(exc),
        }


def run_smoke(
    base_url: str,
    paths: list[str],
    timeout: float,
    *,
    require_postgres_split_metrics: bool = False,
    expect_postgres_split_required: bool | None = None,
) -> dict[str, Any]:
    if (require_postgres_split_metrics or expect_postgres_split_required is not None) and "/metrics" not in paths:
        paths = [*paths, "/metrics"]
    checks = [smoke_url(base_url, path, timeout) for path in paths]
    ok = all(check.ok for check in checks)
    result = {
        "status": "ok" if ok else "failed",
        "base_url": base_url,
        "checks": [check.as_dict() for check in checks],
    }
    if require_postgres_split_metrics:
        split_metrics = check_postgres_split_metrics(base_url, timeout)
        result["postgres_split_metrics"] = {
            "required_metric_present": split_metrics["required_metric_present"],
            "ready_metric_present": split_metrics["ready_metric_present"],
        }
        if not split_metrics["ok"]:
            result["postgres_split_metrics"]["missing"] = split_metrics.get("missing", [])
            if split_metrics.get("error"):
                result["postgres_split_metrics"]["error"] = split_metrics["error"]
            result["status"] = "failed"
    if expect_postgres_split_required is not None:
        consistency = check_postgres_split_consistency(base_url, timeout, expect_postgres_split_required)
        result["postgres_split_consistency"] = {
            "expected_split_required": consistency["expected_split_required"],
            "ready_require_split": consistency["ready_require_split"],
            "metric_split_required": consistency["metric_split_required"],
            "ok": consistency["ok"],
        }
        if not consistency["ok"]:
            if consistency.get("error"):
                result["postgres_split_consistency"]["error"] = consistency["error"]
            result["status"] = "failed"
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run read-only HTTP smoke checks against SCA Monitor.")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SCA_MONITOR_PUBLIC_URL") or os.environ.get("SCA_MONITOR_BASE_URL") or "http://127.0.0.1:18780",
        help="Base URL to check. Defaults to SCA_MONITOR_PUBLIC_URL, SCA_MONITOR_BASE_URL, then localhost.",
    )
    parser.add_argument("--path", action="append", dest="paths", help="Path to check. May be repeated.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds.")
    parser.add_argument("--require-postgres-split-metrics", action="store_true", help="Fail unless /metrics exposes PostgreSQL split cutover gauges.")
    parser.add_argument("--expect-postgres-split-required", type=parse_bool, help="Fail unless /ready and /metrics report the expected split cutover requirement.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = args.paths or list(DEFAULT_PATHS)
    result = run_smoke(
        args.base_url,
        paths,
        args.timeout,
        require_postgres_split_metrics=args.require_postgres_split_metrics,
        expect_postgres_split_required=args.expect_postgres_split_required,
    )
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
