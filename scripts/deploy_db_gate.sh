#!/usr/bin/env bash
set -euo pipefail

MODE="${SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE:-auto}"
REQUIRE_SPLIT="${SCA_MONITOR_POSTGRES_REQUIRE_SPLIT:-false}"
DATABASE_URL="${SCA_MONITOR_DATABASE_URL:-${API_DATABASE_URL:-}}"
MIGRATION_URL="${MIGRATION_DATABASE_URL:-$DATABASE_URL}"
WORKER_URL="${WORKER_DATABASE_URL:-}"

case "$MODE" in
  disabled|skip|false|0|required|auto|"")
    ;;
  *)
    echo "invalid SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE: $MODE" >&2
    exit 2
    ;;
esac

case "$REQUIRE_SPLIT" in
  true|1|yes|on|false|0|no|off|"")
    ;;
  *)
    echo "invalid SCA_MONITOR_POSTGRES_REQUIRE_SPLIT: $REQUIRE_SPLIT" >&2
    exit 2
    ;;
esac

readiness_args=()
if [ "$MODE" = "required" ]; then
  readiness_args+=(--require-postgres)
fi
case "$REQUIRE_SPLIT" in
  true|1|yes|on)
    readiness_args+=(--require-split)
    ;;
esac

if [ "${#readiness_args[@]}" -gt 0 ]; then
  python3 scripts/postgres_cutover_readiness.py "${readiness_args[@]}"
else
  python3 scripts/postgres_cutover_readiness.py
fi

python3 scripts/db_smoke.py --component api
if [ -n "${WORKER_DATABASE_URL:-}" ] && [ -z "${SCA_MONITOR_DATABASE_URL:-}" ]; then
  python3 scripts/db_smoke.py --component worker --read-only
fi

run_postgres_smoke() {
  local database_url="$1"
  local label="$2"
  local extra_args="${3:-}"
  if [ -z "$database_url" ]; then
    if [ "$MODE" = "required" ]; then
      echo "postgres integration smoke required for $label but database URL is not configured" >&2
      exit 2
    fi
    echo "postgres integration smoke skipped for $label: database URL not configured"
    return 0
  fi
  case "$database_url" in
    postgres://*|postgresql://*)
      echo "postgres integration smoke: $label"
      # shellcheck disable=SC2086
      python3 scripts/postgres_integration_smoke.py --database-url "$database_url" $extra_args
      ;;
    *)
      if [ "$MODE" = "required" ]; then
        echo "postgres integration smoke required for $label but URL is not PostgreSQL" >&2
        exit 2
      fi
      ;;
  esac
}

case "$MODE" in
  disabled|skip|false|0)
    exit 0
    ;;
  required)
    run_postgres_smoke "$MIGRATION_URL" migration
    if [ -n "${API_DATABASE_URL:-}" ] && [ -z "${SCA_MONITOR_DATABASE_URL:-}" ]; then
      run_postgres_smoke "${API_DATABASE_URL:-}" api "--skip-migrate"
    fi
    if [ -n "$WORKER_URL" ] && [ -z "${SCA_MONITOR_DATABASE_URL:-}" ]; then
      run_postgres_smoke "$WORKER_URL" worker "--skip-migrate --read-only"
    fi
    ;;
  auto|"")
    run_postgres_smoke "$MIGRATION_URL" migration
    if [ -n "${API_DATABASE_URL:-}" ] && [ -z "${SCA_MONITOR_DATABASE_URL:-}" ]; then
      run_postgres_smoke "${API_DATABASE_URL:-}" api "--skip-migrate"
    fi
    if [ -n "$WORKER_URL" ] && [ -z "${SCA_MONITOR_DATABASE_URL:-}" ]; then
      run_postgres_smoke "$WORKER_URL" worker "--skip-migrate --read-only"
    fi
    ;;
esac
