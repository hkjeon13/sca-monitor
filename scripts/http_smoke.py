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


DEFAULT_PATHS = ("/health", "/ready", "/api/v1/overview", "/api/v1/operations/cutover-readiness-report", "/")
JSON_PATHS = {"/health", "/ready", "/api/v1/overview", "/api/v1/operations/cutover-readiness-report"}
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


def parse_expected_source_statuses(values: list[str]) -> dict[str, str]:
    expected: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"invalid --expect-advisory-source-status value: {value}; expected SOURCE=STATUS")
        source, status = value.split("=", 1)
        source = source.strip()
        status = status.strip()
        if not source or not status:
            raise SystemExit(f"invalid --expect-advisory-source-status value: {value}; expected SOURCE=STATUS")
        expected[source] = status
    return expected


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


def check_database_backend(base_url: str, timeout: float, expected_backend: str) -> dict[str, Any]:
    try:
        status, ready = fetch_json(base_url, "/ready", timeout)
        actual_backend = ready.get("database_backend")
        return {
            "expected": expected_backend,
            "actual": actual_backend,
            "ok": status == 200 and actual_backend == expected_backend,
        }
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "expected": expected_backend,
            "actual": None,
            "ok": False,
            "error": str(exc),
        }


def check_database_env_file_configured(base_url: str, timeout: float, expected_configured: bool) -> dict[str, Any]:
    try:
        status, ready = fetch_json(base_url, "/ready", timeout)
        database_env_file = ready.get("database_env_file") or {}
        actual_configured = bool(database_env_file.get("configured"))
        return {
            "expected_configured": expected_configured,
            "actual_configured": actual_configured,
            "source": database_env_file.get("source"),
            "ok": status == 200 and actual_configured == expected_configured,
        }
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "expected_configured": expected_configured,
            "actual_configured": None,
            "source": None,
            "ok": False,
            "error": str(exc),
        }


def check_advisory_sync_readiness(base_url: str, timeout: float, expected_ready: bool) -> dict[str, Any]:
    try:
        status, overview = fetch_json(base_url, "/api/v1/overview", timeout)
        readiness = overview.get("advisory_sync_readiness") or {}
        freshness = readiness.get("freshness") or {}
        overview_status = readiness.get("status")
        is_ready = overview_status == "ready"
        return {
            "expected_ready": expected_ready,
            "overview_status": overview_status,
            "freshness_status": freshness.get("status"),
            "initialized_count": readiness.get("initialized_count"),
            "required_count": readiness.get("required_count"),
            "ok": status == 200 and is_ready == expected_ready,
        }
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "expected_ready": expected_ready,
            "overview_status": None,
            "freshness_status": None,
            "initialized_count": None,
            "required_count": None,
            "ok": False,
            "error": str(exc),
        }


def check_advisory_source_statuses(base_url: str, timeout: float, expected_statuses: dict[str, str]) -> dict[str, Any]:
    try:
        status, overview = fetch_json(base_url, "/api/v1/overview", timeout)
        advisory_sync = overview.get("advisory_sync") or {}
        actual = {source: advisory_sync.get(source) for source in expected_statuses}
        return {
            "expected": expected_statuses,
            "actual": actual,
            "ok": status == 200 and actual == expected_statuses,
        }
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "expected": expected_statuses,
            "actual": {source: None for source in expected_statuses},
            "ok": False,
            "error": str(exc),
        }


def check_cutover_report_status(
    base_url: str,
    timeout: float,
    expected_status: str | None,
    *,
    expected_report_expected_status: str | None = None,
    expected_production_preflight_status: str | None = None,
    require_expectation_met: bool = False,
) -> dict[str, Any]:
    try:
        status, payload = fetch_json(base_url, "/api/v1/operations/cutover-readiness-report", timeout)
        artifact = payload.get("artifact") or {}
        report = payload.get("report") or {}
        artifact_status = artifact.get("status")
        report_status = report.get("status")
        report_expected_status = report.get("expected_status")
        report_expectation_met = report.get("expectation_met")
        production_preflight = report.get("production_preflight") or {}
        production_preflight_status = production_preflight.get("status")
        report_status_ok = expected_status is None or report_status == expected_status
        expected_status_ok = expected_report_expected_status is None or report_expected_status == expected_report_expected_status
        production_preflight_ok = (
            expected_production_preflight_status is None
            or production_preflight_status == expected_production_preflight_status
        )
        expectation_met_ok = not require_expectation_met or report_expectation_met is True
        return {
            "expected_status": expected_status,
            "artifact_status": artifact_status,
            "report_status": report_status,
            "report_expected_status": report_expected_status,
            "report_expectation_met": report_expectation_met,
            "expected_production_preflight_status": expected_production_preflight_status,
            "production_preflight_status": production_preflight_status,
            "required_expectation_met": require_expectation_met,
            "ok": status == 200
            and artifact_status == "available"
            and report_status_ok
            and expected_status_ok
            and production_preflight_ok
            and expectation_met_ok,
        }
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "expected_status": expected_status,
            "artifact_status": None,
            "report_status": None,
            "report_expected_status": None,
            "report_expectation_met": None,
            "expected_production_preflight_status": expected_production_preflight_status,
            "production_preflight_status": None,
            "required_expectation_met": require_expectation_met,
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
    expect_database_backend: str | None = None,
    expect_database_env_file_configured: bool | None = None,
    expect_advisory_sync_ready: bool | None = None,
    expect_advisory_source_statuses: dict[str, str] | None = None,
    expect_cutover_report_status: str | None = None,
    expect_cutover_report_expected_status: str | None = None,
    expect_cutover_report_production_preflight_status: str | None = None,
    require_cutover_report_expectation_met: bool = False,
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
    if expect_database_backend is not None:
        database_backend = check_database_backend(base_url, timeout, expect_database_backend)
        result["database_backend"] = {
            "expected": database_backend["expected"],
            "actual": database_backend["actual"],
            "ok": database_backend["ok"],
        }
        if not database_backend["ok"]:
            if database_backend.get("error"):
                result["database_backend"]["error"] = database_backend["error"]
            result["status"] = "failed"
    if expect_database_env_file_configured is not None:
        database_env_file = check_database_env_file_configured(base_url, timeout, expect_database_env_file_configured)
        result["database_env_file"] = {
            "expected_configured": database_env_file["expected_configured"],
            "actual_configured": database_env_file["actual_configured"],
            "source": database_env_file["source"],
            "ok": database_env_file["ok"],
        }
        if not database_env_file["ok"]:
            if database_env_file.get("error"):
                result["database_env_file"]["error"] = database_env_file["error"]
            result["status"] = "failed"
    if expect_advisory_sync_ready is not None:
        readiness = check_advisory_sync_readiness(base_url, timeout, expect_advisory_sync_ready)
        result["advisory_sync_readiness"] = {
            "expected_ready": readiness["expected_ready"],
            "overview_status": readiness["overview_status"],
            "freshness_status": readiness["freshness_status"],
            "initialized_count": readiness["initialized_count"],
            "required_count": readiness["required_count"],
            "ok": readiness["ok"],
        }
        if not readiness["ok"]:
            if readiness.get("error"):
                result["advisory_sync_readiness"]["error"] = readiness["error"]
            result["status"] = "failed"
    if expect_advisory_source_statuses:
        source_statuses = check_advisory_source_statuses(base_url, timeout, expect_advisory_source_statuses)
        result["advisory_source_statuses"] = {
            "expected": source_statuses["expected"],
            "actual": source_statuses["actual"],
            "ok": source_statuses["ok"],
        }
        if not source_statuses["ok"]:
            if source_statuses.get("error"):
                result["advisory_source_statuses"]["error"] = source_statuses["error"]
            result["status"] = "failed"
    if (
        expect_cutover_report_status is not None
        or expect_cutover_report_expected_status is not None
        or expect_cutover_report_production_preflight_status is not None
        or require_cutover_report_expectation_met
    ):
        cutover_report = check_cutover_report_status(
            base_url,
            timeout,
            expect_cutover_report_status,
            expected_report_expected_status=expect_cutover_report_expected_status,
            expected_production_preflight_status=expect_cutover_report_production_preflight_status,
            require_expectation_met=require_cutover_report_expectation_met,
        )
        result["cutover_readiness_report"] = {
            "expected_status": cutover_report["expected_status"],
            "artifact_status": cutover_report["artifact_status"],
            "report_status": cutover_report["report_status"],
            "report_expected_status": cutover_report["report_expected_status"],
            "report_expectation_met": cutover_report["report_expectation_met"],
            "expected_production_preflight_status": cutover_report["expected_production_preflight_status"],
            "production_preflight_status": cutover_report["production_preflight_status"],
            "required_expectation_met": cutover_report["required_expectation_met"],
            "ok": cutover_report["ok"],
        }
        if not cutover_report["ok"]:
            if cutover_report.get("error"):
                result["cutover_readiness_report"]["error"] = cutover_report["error"]
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
    parser.add_argument("--expect-database-backend", choices=("sqlite", "postgres"), help="Fail unless /ready reports the expected database_backend.")
    parser.add_argument("--expect-database-env-file-configured", type=parse_bool, help="Fail unless /ready reports the expected database_env_file.configured value.")
    parser.add_argument("--expect-advisory-sync-ready", type=parse_bool, help="Fail unless /api/v1/overview reports the expected advisory sync readiness.")
    parser.add_argument(
        "--expect-advisory-source-status",
        action="append",
        default=[],
        metavar="SOURCE=STATUS",
        help="Fail unless /api/v1/overview advisory_sync has SOURCE with STATUS. May be repeated.",
    )
    parser.add_argument("--expect-cutover-report-status", choices=("ok", "action_required", "blocked"), help="Fail unless cutover readiness report artifact has the expected report status.")
    parser.add_argument("--expect-cutover-report-expected-status", choices=("ok", "action_required", "blocked"), help="Fail unless cutover readiness report expected_status matches this value.")
    parser.add_argument(
        "--expect-cutover-report-production-preflight-status",
        choices=("ok", "failed", "skipped"),
        help="Fail unless cutover readiness report production_preflight.status matches this value.",
    )
    parser.add_argument("--require-cutover-report-expectation-met", action="store_true", help="Fail unless cutover readiness report expectation_met is true.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = args.paths or list(DEFAULT_PATHS)
    expected_source_statuses = parse_expected_source_statuses(args.expect_advisory_source_status)
    result = run_smoke(
        args.base_url,
        paths,
        args.timeout,
        require_postgres_split_metrics=args.require_postgres_split_metrics,
        expect_postgres_split_required=args.expect_postgres_split_required,
        expect_database_backend=args.expect_database_backend,
        expect_database_env_file_configured=args.expect_database_env_file_configured,
        expect_advisory_sync_ready=args.expect_advisory_sync_ready,
        expect_advisory_source_statuses=expected_source_statuses,
        expect_cutover_report_status=args.expect_cutover_report_status,
        expect_cutover_report_expected_status=args.expect_cutover_report_expected_status,
        expect_cutover_report_production_preflight_status=args.expect_cutover_report_production_preflight_status,
        require_cutover_report_expectation_met=args.require_cutover_report_expectation_met,
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
