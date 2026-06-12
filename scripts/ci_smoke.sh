#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SCA_MONITOR_SMOKE_BASE_URL:-${SCA_MONITOR_PUBLIC_URL:-}}"
RUN_HTTP_SMOKE="${SCA_MONITOR_CI_HTTP_SMOKE:-auto}"
EXPECT_POSTGRES_SPLIT_REQUIRED="${SCA_MONITOR_EXPECT_POSTGRES_SPLIT_REQUIRED:-}"
EXPECT_ADVISORY_SYNC_READY="${SCA_MONITOR_EXPECT_ADVISORY_SYNC_READY:-}"
EXPECT_DATABASE_BACKEND="${SCA_MONITOR_EXPECT_DATABASE_BACKEND:-}"
EXPECT_DATABASE_ENV_FILE_CONFIGURED="${SCA_MONITOR_EXPECT_DATABASE_ENV_FILE_CONFIGURED:-}"
EXPECT_CUTOVER_REPORT_STATUS="${SCA_MONITOR_EXPECT_CUTOVER_REPORT_STATUS:-}"
EXPECT_CUTOVER_REPORT_EXPECTED_STATUS="${SCA_MONITOR_EXPECT_CUTOVER_REPORT_EXPECTED_STATUS:-}"
EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS="${SCA_MONITOR_EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS:-}"
REQUIRE_CUTOVER_REPORT_EXPECTATION_MET="${SCA_MONITOR_REQUIRE_CUTOVER_REPORT_EXPECTATION_MET:-false}"
DEPLOYMENT_ENV_FILE="${SCA_MONITOR_DEPLOYMENT_ENV_FILE:-deploy/sca-monitor.env.example}"
REQUIRE_RUNTIME_INPUTS="${SCA_MONITOR_REQUIRE_RUNTIME_INPUTS:-false}"

if [ "$RUN_HTTP_SMOKE" = "required" ] && [ -z "$BASE_URL" ]; then
  echo "http smoke required but SCA_MONITOR_SMOKE_BASE_URL or SCA_MONITOR_PUBLIC_URL is not configured" >&2
  exit 2
fi

python3 -m pytest tests
python3 -m py_compile backend/sca_monitor/app.py backend/sca_monitor/db.py backend/sca_monitor/postgres_cutover.py scripts/configure_runtime_inputs.py scripts/postgres_integration_smoke.py scripts/validate_database_env_file.py scripts/prepare_database_env_file.py scripts/database_env_dry_run_gate.py scripts/backup_database.py scripts/verify_backup_restore.py scripts/cutover_readiness_report.py scripts/advisory_source_preflight.py
deployment_readiness_args=(--env-file "$DEPLOYMENT_ENV_FILE" --json)
case "$REQUIRE_RUNTIME_INPUTS" in
  true|1|yes|on)
    deployment_readiness_args+=(--require-runtime-inputs)
    ;;
  false|0|no|off|"")
    ;;
  *)
    echo "invalid SCA_MONITOR_REQUIRE_RUNTIME_INPUTS: $REQUIRE_RUNTIME_INPUTS" >&2
    exit 2
    ;;
esac
python3 scripts/deployment_input_readiness.py "${deployment_readiness_args[@]}"
python3 scripts/database_env_dry_run_gate.py --json
python3 scripts/advisory_source_preflight.py --list-only --json
node --check frontend/app.js
bash -n scripts/deploy_remote.sh scripts/deploy_db_gate.sh scripts/deploy_systemd_gate.sh scripts/postgres_docker_smoke_gate.sh
python3 scripts/migrate.py
bash scripts/deploy_db_gate.sh
bash scripts/deploy_systemd_gate.sh >/dev/null
bash scripts/postgres_docker_smoke_gate.sh

case "$RUN_HTTP_SMOKE" in
  disabled|skip|false|0)
    echo "http smoke skipped: disabled"
    ;;
  required)
    if [ -z "$BASE_URL" ]; then
      echo "http smoke required but SCA_MONITOR_SMOKE_BASE_URL or SCA_MONITOR_PUBLIC_URL is not configured" >&2
      exit 2
    fi
    http_smoke_args=(--base-url "$BASE_URL")
    if [ -n "$EXPECT_POSTGRES_SPLIT_REQUIRED" ]; then
      http_smoke_args+=(--expect-postgres-split-required "$EXPECT_POSTGRES_SPLIT_REQUIRED")
    fi
    if [ -n "$EXPECT_ADVISORY_SYNC_READY" ]; then
      http_smoke_args+=(--expect-advisory-sync-ready "$EXPECT_ADVISORY_SYNC_READY")
    fi
    if [ -n "$EXPECT_DATABASE_BACKEND" ]; then
      http_smoke_args+=(--expect-database-backend "$EXPECT_DATABASE_BACKEND")
    fi
    if [ -n "$EXPECT_DATABASE_ENV_FILE_CONFIGURED" ]; then
      http_smoke_args+=(--expect-database-env-file-configured "$EXPECT_DATABASE_ENV_FILE_CONFIGURED")
    fi
    if [ -n "$EXPECT_CUTOVER_REPORT_STATUS" ]; then
      http_smoke_args+=(--expect-cutover-report-status "$EXPECT_CUTOVER_REPORT_STATUS")
    fi
    if [ -n "$EXPECT_CUTOVER_REPORT_EXPECTED_STATUS" ]; then
      http_smoke_args+=(--expect-cutover-report-expected-status "$EXPECT_CUTOVER_REPORT_EXPECTED_STATUS")
    fi
    if [ -n "$EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS" ]; then
      http_smoke_args+=(--expect-cutover-report-production-preflight-status "$EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS")
    fi
    case "$REQUIRE_CUTOVER_REPORT_EXPECTATION_MET" in
      true|1|yes|on)
        http_smoke_args+=(--require-cutover-report-expectation-met)
        ;;
      false|0|no|off|"")
        ;;
      *)
        echo "invalid SCA_MONITOR_REQUIRE_CUTOVER_REPORT_EXPECTATION_MET: $REQUIRE_CUTOVER_REPORT_EXPECTATION_MET" >&2
        exit 2
        ;;
    esac
    python3 scripts/http_smoke.py "${http_smoke_args[@]}" --json
    ;;
  auto|"")
    if [ -n "$BASE_URL" ]; then
      http_smoke_args=(--base-url "$BASE_URL")
      if [ -n "$EXPECT_POSTGRES_SPLIT_REQUIRED" ]; then
        http_smoke_args+=(--expect-postgres-split-required "$EXPECT_POSTGRES_SPLIT_REQUIRED")
      fi
      if [ -n "$EXPECT_ADVISORY_SYNC_READY" ]; then
        http_smoke_args+=(--expect-advisory-sync-ready "$EXPECT_ADVISORY_SYNC_READY")
      fi
      if [ -n "$EXPECT_DATABASE_BACKEND" ]; then
        http_smoke_args+=(--expect-database-backend "$EXPECT_DATABASE_BACKEND")
      fi
      if [ -n "$EXPECT_DATABASE_ENV_FILE_CONFIGURED" ]; then
        http_smoke_args+=(--expect-database-env-file-configured "$EXPECT_DATABASE_ENV_FILE_CONFIGURED")
      fi
      if [ -n "$EXPECT_CUTOVER_REPORT_STATUS" ]; then
        http_smoke_args+=(--expect-cutover-report-status "$EXPECT_CUTOVER_REPORT_STATUS")
      fi
      if [ -n "$EXPECT_CUTOVER_REPORT_EXPECTED_STATUS" ]; then
        http_smoke_args+=(--expect-cutover-report-expected-status "$EXPECT_CUTOVER_REPORT_EXPECTED_STATUS")
      fi
      if [ -n "$EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS" ]; then
        http_smoke_args+=(--expect-cutover-report-production-preflight-status "$EXPECT_CUTOVER_REPORT_PRODUCTION_PREFLIGHT_STATUS")
      fi
      case "$REQUIRE_CUTOVER_REPORT_EXPECTATION_MET" in
        true|1|yes|on)
          http_smoke_args+=(--require-cutover-report-expectation-met)
          ;;
        false|0|no|off|"")
          ;;
        *)
          echo "invalid SCA_MONITOR_REQUIRE_CUTOVER_REPORT_EXPECTATION_MET: $REQUIRE_CUTOVER_REPORT_EXPECTATION_MET" >&2
          exit 2
          ;;
      esac
      python3 scripts/http_smoke.py "${http_smoke_args[@]}" --json
    else
      echo "http smoke skipped: base URL not configured"
    fi
    ;;
  *)
    echo "invalid SCA_MONITOR_CI_HTTP_SMOKE: $RUN_HTTP_SMOKE" >&2
    exit 2
    ;;
esac
