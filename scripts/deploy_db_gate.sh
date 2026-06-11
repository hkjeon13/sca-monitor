#!/usr/bin/env bash
set -euo pipefail

MODE="${SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE:-auto}"
DATABASE_URL="${SCA_MONITOR_DATABASE_URL:-${API_DATABASE_URL:-}}"

python3 scripts/db_smoke.py

case "$MODE" in
  disabled|skip|false|0)
    exit 0
    ;;
  required)
    python3 scripts/postgres_integration_smoke.py --database-url "$DATABASE_URL"
    ;;
  auto|"")
    case "$DATABASE_URL" in
      postgres://*|postgresql://*)
        python3 scripts/postgres_integration_smoke.py --database-url "$DATABASE_URL"
        ;;
    esac
    ;;
  *)
    echo "invalid SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE: $MODE" >&2
    exit 2
    ;;
esac
