#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-ai-assistant}"
REMOTE_DIR="${REMOTE_DIR:-/data/psyche/Projects/sca-monitor}"
PORT="${SCA_MONITOR_PORT:-18780}"
SYSTEMD_MODE_OVERRIDE="${SCA_MONITOR_SYSTEMD_MODE:-}"
SYSTEMD_SCOPE_OVERRIDE="${SCA_MONITOR_SYSTEMD_SCOPE:-}"
SYSTEMD_PREFIX_OVERRIDE="${SCA_MONITOR_SYSTEMD_PREFIX:-}"
SYSTEMD_PYTHON_OVERRIDE="${SCA_MONITOR_SYSTEMD_PYTHON:-}"
REQUIRE_RUNTIME_INPUTS="${SCA_MONITOR_REQUIRE_RUNTIME_INPUTS:-false}"
PUBLIC_URL_OVERRIDE="${SCA_MONITOR_PUBLIC_URL:-}"
GENERATE_SMOKE_TOKEN="${SCA_MONITOR_GENERATE_SMOKE_TOKEN:-false}"
DATABASE_ENV_FILE="${SCA_MONITOR_DATABASE_ENV_FILE:-}"
DATABASE_ENV_DRY_RUN="${SCA_MONITOR_DATABASE_ENV_DRY_RUN:-disabled}"
ADVISORY_SOURCE_PREFLIGHT="${SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT:-list}"
ADVISORY_SOURCE_PREFLIGHT_TIMEOUT="${SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT_TIMEOUT:-8}"
BOOTSTRAP_READINESS="${SCA_MONITOR_BOOTSTRAP_READINESS:-disabled}"
POST_DEPLOY_HTTP_SMOKE="${SCA_MONITOR_POST_DEPLOY_HTTP_SMOKE:-auto}"
EXPECT_POSTGRES_SPLIT_REQUIRED="${SCA_MONITOR_EXPECT_POSTGRES_SPLIT_REQUIRED:-}"
EXPECT_ADVISORY_SYNC_READY="${SCA_MONITOR_EXPECT_ADVISORY_SYNC_READY:-}"
EXPECT_DATABASE_BACKEND="${SCA_MONITOR_EXPECT_DATABASE_BACKEND:-}"

ssh "$REMOTE" "set -euo pipefail
  cd '$REMOTE_DIR'
  git fetch origin
  git pull --ff-only origin main
  mkdir -p .data logs
  if [ ! -f .env ]; then cp deploy/sca-monitor.env.example .env; fi
  sed -i 's/^SCA_MONITOR_PORT=.*/SCA_MONITOR_PORT=$PORT/' .env
  PUBLIC_URL_OVERRIDE='$PUBLIC_URL_OVERRIDE'
  GENERATE_SMOKE_TOKEN='$GENERATE_SMOKE_TOKEN'
  DATABASE_ENV_FILE='$DATABASE_ENV_FILE'
  DATABASE_ENV_DRY_RUN='$DATABASE_ENV_DRY_RUN'
  runtime_input_args=''
  case \"\$DATABASE_ENV_DRY_RUN\" in
    disabled|skip|false|0|'')
      echo 'database env dry-run gate skipped'
      ;;
    synthetic)
      python3 scripts/database_env_dry_run_gate.py --json
      ;;
    provided|required)
      if [ -z \"\$DATABASE_ENV_FILE\" ]; then
        echo \"SCA_MONITOR_DATABASE_ENV_DRY_RUN=\$DATABASE_ENV_DRY_RUN requires SCA_MONITOR_DATABASE_ENV_FILE\" >&2
        exit 2
      fi
      python3 scripts/database_env_dry_run_gate.py --database-env-file \"\$DATABASE_ENV_FILE\" --json
      ;;
    *)
      echo \"invalid SCA_MONITOR_DATABASE_ENV_DRY_RUN: \$DATABASE_ENV_DRY_RUN\" >&2
      exit 2
      ;;
  esac
  if [ -n \"\$PUBLIC_URL_OVERRIDE\" ]; then
    runtime_input_args=\"\$runtime_input_args --public-url \$PUBLIC_URL_OVERRIDE\"
  fi
  if [ -n \"\$DATABASE_ENV_FILE\" ]; then
    python3 scripts/validate_database_env_file.py --database-env-file \"\$DATABASE_ENV_FILE\" --json
    runtime_input_args=\"\$runtime_input_args --database-env-file \$DATABASE_ENV_FILE\"
  fi
  case \"\$GENERATE_SMOKE_TOKEN\" in
    true|1|yes|on)
      runtime_input_args=\"\$runtime_input_args --generate-smoke-token\"
      ;;
    false|0|no|off|'')
      ;;
    *)
      echo \"invalid SCA_MONITOR_GENERATE_SMOKE_TOKEN: \$GENERATE_SMOKE_TOKEN\" >&2
      exit 2
      ;;
  esac
  if [ -n \"\$runtime_input_args\" ]; then
    # shellcheck disable=SC2086
    python3 scripts/configure_runtime_inputs.py --env-file .env \$runtime_input_args --json
  fi
  set -a
  . ./.env
  set +a
  SYSTEMD_MODE_OVERRIDE='$SYSTEMD_MODE_OVERRIDE'
  SYSTEMD_SCOPE_OVERRIDE='$SYSTEMD_SCOPE_OVERRIDE'
  SYSTEMD_PREFIX_OVERRIDE='$SYSTEMD_PREFIX_OVERRIDE'
  SYSTEMD_PYTHON_OVERRIDE='$SYSTEMD_PYTHON_OVERRIDE'
  REQUIRE_RUNTIME_INPUTS='$REQUIRE_RUNTIME_INPUTS'
  ADVISORY_SOURCE_PREFLIGHT='$ADVISORY_SOURCE_PREFLIGHT'
  ADVISORY_SOURCE_PREFLIGHT_TIMEOUT='$ADVISORY_SOURCE_PREFLIGHT_TIMEOUT'
  BOOTSTRAP_READINESS='$BOOTSTRAP_READINESS'
  POST_DEPLOY_HTTP_SMOKE='$POST_DEPLOY_HTTP_SMOKE'
  EXPECT_POSTGRES_SPLIT_REQUIRED='$EXPECT_POSTGRES_SPLIT_REQUIRED'
  EXPECT_ADVISORY_SYNC_READY='$EXPECT_ADVISORY_SYNC_READY'
  EXPECT_DATABASE_BACKEND='$EXPECT_DATABASE_BACKEND'
  if [ -n \"\$SYSTEMD_MODE_OVERRIDE\" ]; then
    SCA_MONITOR_SYSTEMD_MODE=\"\$SYSTEMD_MODE_OVERRIDE\"
  fi
  if [ -n \"\$SYSTEMD_SCOPE_OVERRIDE\" ]; then
    SCA_MONITOR_SYSTEMD_SCOPE=\"\$SYSTEMD_SCOPE_OVERRIDE\"
  fi
  if [ -n \"\$SYSTEMD_PREFIX_OVERRIDE\" ]; then
    SCA_MONITOR_SYSTEMD_PREFIX=\"\$SYSTEMD_PREFIX_OVERRIDE\"
  fi
  if [ -n \"\$SYSTEMD_PYTHON_OVERRIDE\" ]; then
    SCA_MONITOR_SYSTEMD_PYTHON=\"\$SYSTEMD_PYTHON_OVERRIDE\"
  fi
  SYSTEMD_MODE=\"\${SCA_MONITOR_SYSTEMD_MODE:-validate}\"
  export SCA_MONITOR_SYSTEMD_MODE=\"\$SYSTEMD_MODE\"
  export SCA_MONITOR_SYSTEMD_SCOPE=\"\${SCA_MONITOR_SYSTEMD_SCOPE:-user}\"
  export SCA_MONITOR_SYSTEMD_PREFIX=\"\${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}\"
  export SCA_MONITOR_SYSTEMD_PYTHON=\"\${SCA_MONITOR_SYSTEMD_PYTHON:-python3}\"
  deployment_readiness_args=''
  case \"\$REQUIRE_RUNTIME_INPUTS\" in
    true|1|yes|on)
      deployment_readiness_args='--require-runtime-inputs'
      ;;
    false|0|no|off|'')
      ;;
    *)
      echo \"invalid SCA_MONITOR_REQUIRE_RUNTIME_INPUTS: \$REQUIRE_RUNTIME_INPUTS\" >&2
      exit 2
      ;;
  esac
  python3 scripts/deployment_input_readiness.py --env-file .env --json \$deployment_readiness_args
  case \"\$ADVISORY_SOURCE_PREFLIGHT\" in
    disabled|skip|false|0|'')
      echo 'advisory source preflight skipped'
      ;;
    list|list-only|auto)
      python3 scripts/advisory_source_preflight.py --list-only --json
      ;;
    check|required)
      python3 scripts/advisory_source_preflight.py --check --timeout \"\$ADVISORY_SOURCE_PREFLIGHT_TIMEOUT\" --json
      ;;
    *)
      echo \"invalid SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT: \$ADVISORY_SOURCE_PREFLIGHT\" >&2
      exit 2
      ;;
  esac
  systemd_worker_units_for_migration() {
    case \"\$SYSTEMD_MODE\" in
      enable-poller)
        printf '%s' \"\${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}-endpoint-poller.service\"
        ;;
      enable-dispatcher-dry-run)
        printf '%s' \"\${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}-endpoint-poller.service \${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}-alert-dispatcher-dry-run.service\"
        ;;
      enable)
        printf '%s' \"\${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}-endpoint-poller.service \${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}-alert-dispatcher.service \${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}-alert-dispatcher-dry-run.service\"
        ;;
      *)
        printf ''
        ;;
    esac
  }
  systemd_scope_args() {
    if [ \"\${SCA_MONITOR_SYSTEMD_SCOPE:-user}\" = 'system' ]; then
      printf ''
    else
      printf -- '--user'
    fi
  }
  workers_stopped_for_migration=0
  migration_worker_units=\"\$(systemd_worker_units_for_migration)\"
  stop_systemd_workers_for_migration() {
    if [ -z \"\$migration_worker_units\" ] || ! command -v systemctl >/dev/null 2>&1; then
      return
    fi
    scope_args=\"\$(systemd_scope_args)\"
    echo \"stopping systemd workers for migration: \$migration_worker_units\"
    # shellcheck disable=SC2086
    systemctl \$scope_args stop \$migration_worker_units 2>/dev/null || true
    workers_stopped_for_migration=1
  }
  restart_systemd_workers_after_migration() {
    if [ \"\$workers_stopped_for_migration\" != '1' ] || [ -z \"\$migration_worker_units\" ] || ! command -v systemctl >/dev/null 2>&1; then
      return
    fi
    scope_args=\"\$(systemd_scope_args)\"
    echo \"starting systemd workers after migration: \$migration_worker_units\"
    # shellcheck disable=SC2086
    systemctl \$scope_args start \$migration_worker_units 2>/dev/null || true
    workers_stopped_for_migration=0
  }
  stop_systemd_workers_for_migration
  trap restart_systemd_workers_after_migration EXIT
  python3 scripts/migrate.py
  bash scripts/deploy_db_gate.sh
  case \"\$BOOTSTRAP_READINESS\" in
    disabled|skip|false|0|'')
      echo 'bootstrap readiness gate skipped'
      ;;
    advisory|advisory-only|skip-alert-activation)
      python3 scripts/bootstrap_readiness_check.py --json --skip-alert-activation
      ;;
    required|full)
      python3 scripts/bootstrap_readiness_check.py --json
      ;;
    *)
      echo \"invalid SCA_MONITOR_BOOTSTRAP_READINESS: \$BOOTSTRAP_READINESS\" >&2
      exit 2
      ;;
  esac
  restart_systemd_workers_after_migration
  trap - EXIT
  start_legacy_api() {
    nohup python3 -m backend.sca_monitor > logs/sca-monitor.log 2>&1 &
    echo \$! > .data/sca-monitor.pid
  }
  if [ -f .data/sca-monitor.pid ]; then
    old_pid=\$(cat .data/sca-monitor.pid)
    if [ -n \"\$old_pid\" ] && kill -0 \"\$old_pid\" 2>/dev/null; then
      kill \"\$old_pid\" || true
      sleep 1
    fi
  fi
  if ! SCA_MONITOR_SYSTEMD_MODE=\"\$SYSTEMD_MODE\" \
    SCA_MONITOR_SYSTEMD_SCOPE=\"\${SCA_MONITOR_SYSTEMD_SCOPE:-user}\" \
    SCA_MONITOR_SYSTEMD_PREFIX=\"\${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}\" \
    SCA_MONITOR_SYSTEMD_PYTHON=\"\${SCA_MONITOR_SYSTEMD_PYTHON:-python3}\" \
    SCA_MONITOR_SYSTEMD_REPO_DIR='$REMOTE_DIR' \
    bash scripts/deploy_systemd_gate.sh; then
    if [ \"\$SYSTEMD_MODE\" = 'enable' ] || [ \"\$SYSTEMD_MODE\" = 'enable-api' ] || [ \"\$SYSTEMD_MODE\" = 'enable-poller' ] || [ \"\$SYSTEMD_MODE\" = 'enable-dispatcher-dry-run' ]; then
      if curl -fsS http://127.0.0.1:$PORT/health >/dev/null 2>&1 &&
         curl -fsS http://127.0.0.1:$PORT/ready >/dev/null 2>&1; then
        echo \"systemd deploy gate failed but API health check passed; keeping systemd runtime\" >&2
      else
        echo \"systemd deploy gate failed; restarting legacy API runtime\" >&2
        start_legacy_api
        exit 1
      fi
    else
      echo \"systemd deploy gate failed; restarting legacy API runtime\" >&2
      start_legacy_api
      exit 1
    fi
  fi
  if [ \"\$SYSTEMD_MODE\" = 'enable' ] || [ \"\$SYSTEMD_MODE\" = 'enable-api' ] || [ \"\$SYSTEMD_MODE\" = 'enable-poller' ] || [ \"\$SYSTEMD_MODE\" = 'enable-dispatcher-dry-run' ]; then
    rm -f .data/sca-monitor.pid
  else
    start_legacy_api
  fi
  api_ready=0
  for attempt in \$(seq 1 20); do
    if curl -fsS http://127.0.0.1:$PORT/health >/dev/null 2>&1 &&
       curl -fsS http://127.0.0.1:$PORT/ready >/dev/null 2>&1; then
      api_ready=1
      break
    fi
    sleep 1
  done
  if [ \"\$api_ready\" = '1' ]; then
    case \"\$POST_DEPLOY_HTTP_SMOKE\" in
      disabled|skip|false|0|'')
        echo 'post-deploy HTTP smoke skipped'
        ;;
      auto|required)
        http_smoke_args=(--base-url http://127.0.0.1:$PORT)
        if [ -n \"\$EXPECT_POSTGRES_SPLIT_REQUIRED\" ]; then
          http_smoke_args+=(--expect-postgres-split-required \"\$EXPECT_POSTGRES_SPLIT_REQUIRED\")
        fi
        if [ -n \"\$EXPECT_ADVISORY_SYNC_READY\" ]; then
          http_smoke_args+=(--expect-advisory-sync-ready \"\$EXPECT_ADVISORY_SYNC_READY\")
        fi
        if [ -n \"\$EXPECT_DATABASE_BACKEND\" ]; then
          http_smoke_args+=(--expect-database-backend \"\$EXPECT_DATABASE_BACKEND\")
        fi
        python3 scripts/http_smoke.py \"\${http_smoke_args[@]}\" --json
        ;;
      *)
        echo \"invalid SCA_MONITOR_POST_DEPLOY_HTTP_SMOKE: \$POST_DEPLOY_HTTP_SMOKE\" >&2
        exit 2
        ;;
    esac
    exit 0
  fi
  tail -80 logs/sca-monitor.log || true
  if [ \"\$SYSTEMD_MODE\" = 'enable' ] || [ \"\$SYSTEMD_MODE\" = 'enable-api' ] || [ \"\$SYSTEMD_MODE\" = 'enable-poller' ] || [ \"\$SYSTEMD_MODE\" = 'enable-dispatcher-dry-run' ]; then
    systemctl --user status sca-monitor-api.service --no-pager || true
  fi
  exit 1
"

echo "remote deployed: http://$REMOTE:$PORT"
