#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-ai-assistant}"
REMOTE_DIR="${REMOTE_DIR:-/data/psyche/Projects/sca-monitor}"
PORT="${SCA_MONITOR_PORT:-18780}"

ssh "$REMOTE" "set -euo pipefail
  cd '$REMOTE_DIR'
  git fetch origin
  git pull --ff-only origin main
  mkdir -p .data logs
  if [ ! -f .env ]; then cp deploy/sca-monitor.env.example .env; fi
  sed -i 's/^SCA_MONITOR_PORT=.*/SCA_MONITOR_PORT=$PORT/' .env
  set -a
  . ./.env
  set +a
  python3 scripts/migrate.py
  python3 scripts/db_smoke.py
  if [ -f .data/sca-monitor.pid ]; then
    old_pid=\$(cat .data/sca-monitor.pid)
    if [ -n \"\$old_pid\" ] && kill -0 \"\$old_pid\" 2>/dev/null; then
      kill \"\$old_pid\" || true
      sleep 1
    fi
  fi
  nohup python3 -m backend.sca_monitor > logs/sca-monitor.log 2>&1 &
  echo \$! > .data/sca-monitor.pid
  for attempt in \$(seq 1 20); do
    if curl -fsS http://127.0.0.1:$PORT/health >/dev/null 2>&1 &&
       curl -fsS http://127.0.0.1:$PORT/ready >/dev/null 2>&1; then
      exit 0
    fi
    sleep 1
  done
  tail -80 logs/sca-monitor.log || true
  exit 1
"

echo "remote deployed: http://$REMOTE:$PORT"
