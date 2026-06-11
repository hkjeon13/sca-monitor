#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PREFIX="${PREFIX:-sca-monitor}"
UNIT_SCOPE="user"
UNIT_DIR=""
ENABLE=0
ENABLE_API_ONLY=0
ENABLE_POLLER_ONLY=0
ENABLE_DISPATCHER_DRY_RUN=0
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: scripts/install_systemd_units.sh [options]

Options:
  --repo-dir PATH       Repository checkout path. Defaults to this repository.
  --python PATH         Python executable. Defaults to python3 or PYTHON_BIN.
  --prefix NAME         Unit name prefix. Defaults to sca-monitor.
  --user                Install user units under ~/.config/systemd/user. Default.
  --system              Install system units under /etc/systemd/system.
  --unit-dir PATH       Override target unit directory.
  --enable              Run daemon-reload and enable/restart units.
  --enable-api-only     Run daemon-reload and enable/restart only the API service.
  --enable-poller-only  Run daemon-reload and enable/restart API and endpoint poller services.
  --enable-dispatcher-dry-run
                        Run daemon-reload and enable/restart API, endpoint poller, and dry-run dispatcher services.
  --dry-run             Write unit files but do not call systemctl.
  -h, --help            Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-dir)
      REPO_DIR="$2"
      shift 2
      ;;
    --python)
      PYTHON_BIN="$2"
      shift 2
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --user)
      UNIT_SCOPE="user"
      shift
      ;;
    --system)
      UNIT_SCOPE="system"
      shift
      ;;
    --unit-dir)
      UNIT_DIR="$2"
      shift 2
      ;;
    --enable)
      ENABLE=1
      shift
      ;;
    --enable-api-only)
      ENABLE_API_ONLY=1
      shift
      ;;
    --enable-poller-only)
      ENABLE_POLLER_ONLY=1
      shift
      ;;
    --enable-dispatcher-dry-run)
      ENABLE_DISPATCHER_DRY_RUN=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

REPO_DIR="$(cd "$REPO_DIR" && pwd)"
if [[ -z "$UNIT_DIR" ]]; then
  if [[ "$UNIT_SCOPE" == "system" ]]; then
    UNIT_DIR="/etc/systemd/system"
  else
    UNIT_DIR="${HOME}/.config/systemd/user"
  fi
fi

mkdir -p "$UNIT_DIR"

write_unit() {
  local name="$1"
  local path="$UNIT_DIR/$name"
  cat > "$path"
  echo "wrote $path"
}

unit_header() {
  cat <<EOF
WorkingDirectory=$REPO_DIR
EnvironmentFile=-$REPO_DIR/.env
EOF
}

write_unit "${PREFIX}-api.service" <<EOF
[Unit]
Description=SCA Monitor API server
After=network-online.target

[Service]
Type=simple
$(unit_header)
ExecStart=$PYTHON_BIN -m backend.sca_monitor
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

write_unit "${PREFIX}-endpoint-poller.service" <<EOF
[Unit]
Description=SCA Monitor endpoint polling worker
After=network-online.target

[Service]
Type=simple
$(unit_header)
ExecStart=$PYTHON_BIN scripts/poll_endpoints.py --limit 50 --iterations 0 --interval-seconds 300 --worker-name default --lock-owner systemd-endpoint-poller --lock-ttl-seconds 240
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

write_unit "${PREFIX}-alert-dispatcher.service" <<EOF
[Unit]
Description=SCA Monitor alert dispatcher worker
After=network-online.target

[Service]
Type=simple
$(unit_header)
ExecStart=$PYTHON_BIN scripts/dispatch_alerts.py --limit 50 --iterations 0 --interval-seconds 30 --retry-backoff-seconds 300 --max-retries 5 --lock-owner systemd-alert-dispatcher
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

write_unit "${PREFIX}-alert-dispatcher-dry-run.service" <<EOF
[Unit]
Description=SCA Monitor alert dispatcher dry-run worker
After=network-online.target

[Service]
Type=simple
$(unit_header)
ExecStart=$PYTHON_BIN scripts/dispatch_alerts.py --limit 50 --iterations 0 --interval-seconds 30 --retry-backoff-seconds 300 --max-retries 5 --lock-owner systemd-alert-dispatcher-dry-run --dry-run
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

write_unit "${PREFIX}-accepted-risk-expiry.service" <<EOF
[Unit]
Description=SCA Monitor accepted risk expiry job

[Service]
Type=oneshot
$(unit_header)
ExecStart=$PYTHON_BIN scripts/expire_accepted_risks.py --limit 100 --actor risk-scheduler
EOF

write_unit "${PREFIX}-accepted-risk-expiry.timer" <<EOF
[Unit]
Description=Run SCA Monitor accepted risk expiry every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Unit=${PREFIX}-accepted-risk-expiry.service

[Install]
WantedBy=timers.target
EOF

write_unit "${PREFIX}-cisa-kev-sync.service" <<EOF
[Unit]
Description=SCA Monitor CISA KEV sync job
After=network-online.target

[Service]
Type=oneshot
$(unit_header)
ExecStart=$PYTHON_BIN scripts/cisa_kev_sync.py --lock-owner systemd-cisa-kev-sync --lock-ttl-seconds 3600
EOF

write_unit "${PREFIX}-cisa-kev-sync.timer" <<EOF
[Unit]
Description=Run SCA Monitor CISA KEV sync hourly

[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
Unit=${PREFIX}-cisa-kev-sync.service

[Install]
WantedBy=timers.target
EOF

write_unit "${PREFIX}-osv-npm-sync.service" <<EOF
[Unit]
Description=SCA Monitor OSV npm sync job
After=network-online.target

[Service]
Type=oneshot
$(unit_header)
ExecStart=$PYTHON_BIN scripts/osv_sync.py --ecosystem npm --lock-owner systemd-osv-npm-sync --lock-ttl-seconds 3600
EOF

write_unit "${PREFIX}-osv-npm-sync.timer" <<EOF
[Unit]
Description=Run SCA Monitor OSV npm sync hourly

[Timer]
OnBootSec=15min
OnUnitActiveSec=1h
Unit=${PREFIX}-osv-npm-sync.service

[Install]
WantedBy=timers.target
EOF

write_unit "${PREFIX}-openssf-malicious-sync.service" <<EOF
[Unit]
Description=SCA Monitor OpenSSF malicious package sync job
After=network-online.target

[Service]
Type=oneshot
$(unit_header)
ExecStart=$PYTHON_BIN scripts/osv_sync.py --ecosystem npm --source OpenSSF --malicious-only --lock-owner systemd-openssf-malicious-sync --lock-ttl-seconds 3600
EOF

write_unit "${PREFIX}-openssf-malicious-sync.timer" <<EOF
[Unit]
Description=Run SCA Monitor OpenSSF malicious package sync hourly

[Timer]
OnBootSec=20min
OnUnitActiveSec=1h
Unit=${PREFIX}-openssf-malicious-sync.service

[Install]
WantedBy=timers.target
EOF

if [[ "$DRY_RUN" == "1" ]]; then
  echo "dry-run: systemctl was not called"
  exit 0
fi

if [[ "$ENABLE_API_ONLY" == "1" ]]; then
  if [[ "$UNIT_SCOPE" == "system" ]]; then
    SYSTEMCTL=(systemctl)
  else
    SYSTEMCTL=(systemctl --user)
  fi
  "${SYSTEMCTL[@]}" daemon-reload
  "${SYSTEMCTL[@]}" enable --now "${PREFIX}-api.service"
  "${SYSTEMCTL[@]}" restart "${PREFIX}-api.service"
elif [[ "$ENABLE_POLLER_ONLY" == "1" ]]; then
  if [[ "$UNIT_SCOPE" == "system" ]]; then
    SYSTEMCTL=(systemctl)
  else
    SYSTEMCTL=(systemctl --user)
  fi
  "${SYSTEMCTL[@]}" daemon-reload
  "${SYSTEMCTL[@]}" enable --now \
    "${PREFIX}-api.service" \
    "${PREFIX}-endpoint-poller.service"
  "${SYSTEMCTL[@]}" restart \
    "${PREFIX}-api.service" \
    "${PREFIX}-endpoint-poller.service"
elif [[ "$ENABLE_DISPATCHER_DRY_RUN" == "1" ]]; then
  if [[ "$UNIT_SCOPE" == "system" ]]; then
    SYSTEMCTL=(systemctl)
  else
    SYSTEMCTL=(systemctl --user)
  fi
  "${SYSTEMCTL[@]}" daemon-reload
  "${SYSTEMCTL[@]}" disable --now "${PREFIX}-alert-dispatcher.service" 2>/dev/null || true
  "${SYSTEMCTL[@]}" enable --now \
    "${PREFIX}-api.service" \
    "${PREFIX}-endpoint-poller.service" \
    "${PREFIX}-alert-dispatcher-dry-run.service"
  "${SYSTEMCTL[@]}" restart \
    "${PREFIX}-api.service" \
    "${PREFIX}-endpoint-poller.service" \
    "${PREFIX}-alert-dispatcher-dry-run.service"
elif [[ "$ENABLE" == "1" ]]; then
  if [[ "$UNIT_SCOPE" == "system" ]]; then
    SYSTEMCTL=(systemctl)
  else
    SYSTEMCTL=(systemctl --user)
  fi
  "${SYSTEMCTL[@]}" daemon-reload
  "${SYSTEMCTL[@]}" disable --now "${PREFIX}-alert-dispatcher-dry-run.service" 2>/dev/null || true
  "${SYSTEMCTL[@]}" enable --now \
    "${PREFIX}-api.service" \
    "${PREFIX}-endpoint-poller.service" \
    "${PREFIX}-alert-dispatcher.service" \
    "${PREFIX}-accepted-risk-expiry.timer" \
    "${PREFIX}-cisa-kev-sync.timer" \
    "${PREFIX}-osv-npm-sync.timer" \
    "${PREFIX}-openssf-malicious-sync.timer"
  "${SYSTEMCTL[@]}" restart \
    "${PREFIX}-api.service" \
    "${PREFIX}-endpoint-poller.service" \
    "${PREFIX}-alert-dispatcher.service" \
    "${PREFIX}-accepted-risk-expiry.timer" \
    "${PREFIX}-cisa-kev-sync.timer" \
    "${PREFIX}-osv-npm-sync.timer" \
    "${PREFIX}-openssf-malicious-sync.timer"
else
  echo "unit files installed. Run with --enable to enable and start units."
fi
