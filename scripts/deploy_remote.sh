#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-ai-assistant}"
REMOTE_DIR="${REMOTE_DIR:-/data/psyche/Projects/sca-monitor}"
PORT="${SCA_MONITOR_PORT:-18780}"
SYSTEMD_MODE_OVERRIDE="${SCA_MONITOR_SYSTEMD_MODE:-}"
SYSTEMD_SCOPE_OVERRIDE="${SCA_MONITOR_SYSTEMD_SCOPE:-}"
SYSTEMD_PREFIX_OVERRIDE="${SCA_MONITOR_SYSTEMD_PREFIX:-}"
SYSTEMD_PYTHON_OVERRIDE="${SCA_MONITOR_SYSTEMD_PYTHON:-}"

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
  SYSTEMD_MODE_OVERRIDE='$SYSTEMD_MODE_OVERRIDE'
  SYSTEMD_SCOPE_OVERRIDE='$SYSTEMD_SCOPE_OVERRIDE'
  SYSTEMD_PREFIX_OVERRIDE='$SYSTEMD_PREFIX_OVERRIDE'
  SYSTEMD_PYTHON_OVERRIDE='$SYSTEMD_PYTHON_OVERRIDE'
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
  python3 scripts/migrate.py
  bash scripts/deploy_db_gate.sh
  if [ -f .data/sca-monitor.pid ]; then
    old_pid=\$(cat .data/sca-monitor.pid)
    if [ -n \"\$old_pid\" ] && kill -0 \"\$old_pid\" 2>/dev/null; then
      kill \"\$old_pid\" || true
      sleep 1
    fi
  fi
  SCA_MONITOR_SYSTEMD_MODE=\"\$SYSTEMD_MODE\" \
    SCA_MONITOR_SYSTEMD_SCOPE=\"\${SCA_MONITOR_SYSTEMD_SCOPE:-user}\" \
    SCA_MONITOR_SYSTEMD_PREFIX=\"\${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}\" \
    SCA_MONITOR_SYSTEMD_PYTHON=\"\${SCA_MONITOR_SYSTEMD_PYTHON:-python3}\" \
    SCA_MONITOR_SYSTEMD_REPO_DIR='$REMOTE_DIR' \
    bash scripts/deploy_systemd_gate.sh
  if [ \"\$SYSTEMD_MODE\" = 'enable' ] || [ \"\$SYSTEMD_MODE\" = 'enable-api' ]; then
    rm -f .data/sca-monitor.pid
  else
    nohup python3 -m backend.sca_monitor > logs/sca-monitor.log 2>&1 &
    echo \$! > .data/sca-monitor.pid
  fi
  for attempt in \$(seq 1 20); do
    if curl -fsS http://127.0.0.1:$PORT/health >/dev/null 2>&1 &&
       curl -fsS http://127.0.0.1:$PORT/ready >/dev/null 2>&1; then
      exit 0
    fi
    sleep 1
  done
  tail -80 logs/sca-monitor.log || true
  if [ \"\$SYSTEMD_MODE\" = 'enable' ] || [ \"\$SYSTEMD_MODE\" = 'enable-api' ]; then
    systemctl --user status sca-monitor-api.service --no-pager || true
  fi
  exit 1
"

echo "remote deployed: http://$REMOTE:$PORT"
