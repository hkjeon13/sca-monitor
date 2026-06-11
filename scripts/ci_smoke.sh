#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SCA_MONITOR_SMOKE_BASE_URL:-${SCA_MONITOR_PUBLIC_URL:-}}"
RUN_HTTP_SMOKE="${SCA_MONITOR_CI_HTTP_SMOKE:-auto}"

if [ "$RUN_HTTP_SMOKE" = "required" ] && [ -z "$BASE_URL" ]; then
  echo "http smoke required but SCA_MONITOR_SMOKE_BASE_URL or SCA_MONITOR_PUBLIC_URL is not configured" >&2
  exit 2
fi

python3 -m pytest tests
python3 -m py_compile backend/sca_monitor/app.py backend/sca_monitor/db.py backend/sca_monitor/postgres_cutover.py scripts/postgres_integration_smoke.py
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
    python3 scripts/http_smoke.py --base-url "$BASE_URL" --json
    ;;
  auto|"")
    if [ -n "$BASE_URL" ]; then
      python3 scripts/http_smoke.py --base-url "$BASE_URL" --json
    else
      echo "http smoke skipped: base URL not configured"
    fi
    ;;
  *)
    echo "invalid SCA_MONITOR_CI_HTTP_SMOKE: $RUN_HTTP_SMOKE" >&2
    exit 2
    ;;
esac
