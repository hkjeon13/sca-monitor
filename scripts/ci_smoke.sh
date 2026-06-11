#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SCA_MONITOR_SMOKE_BASE_URL:-${SCA_MONITOR_PUBLIC_URL:-}}"
RUN_HTTP_SMOKE="${SCA_MONITOR_CI_HTTP_SMOKE:-auto}"
EXPECT_POSTGRES_SPLIT_REQUIRED="${SCA_MONITOR_EXPECT_POSTGRES_SPLIT_REQUIRED:-}"
DEPLOYMENT_ENV_FILE="${SCA_MONITOR_DEPLOYMENT_ENV_FILE:-deploy/sca-monitor.env.example}"
REQUIRE_RUNTIME_INPUTS="${SCA_MONITOR_REQUIRE_RUNTIME_INPUTS:-false}"

if [ "$RUN_HTTP_SMOKE" = "required" ] && [ -z "$BASE_URL" ]; then
  echo "http smoke required but SCA_MONITOR_SMOKE_BASE_URL or SCA_MONITOR_PUBLIC_URL is not configured" >&2
  exit 2
fi

python3 -m pytest tests
python3 -m py_compile backend/sca_monitor/app.py backend/sca_monitor/db.py backend/sca_monitor/postgres_cutover.py scripts/configure_runtime_inputs.py scripts/postgres_integration_smoke.py scripts/validate_database_env_file.py scripts/database_env_dry_run_gate.py
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
    python3 scripts/http_smoke.py "${http_smoke_args[@]}" --json
    ;;
  auto|"")
    if [ -n "$BASE_URL" ]; then
      http_smoke_args=(--base-url "$BASE_URL")
      if [ -n "$EXPECT_POSTGRES_SPLIT_REQUIRED" ]; then
        http_smoke_args+=(--expect-postgres-split-required "$EXPECT_POSTGRES_SPLIT_REQUIRED")
      fi
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
