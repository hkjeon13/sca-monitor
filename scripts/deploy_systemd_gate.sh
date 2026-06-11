#!/usr/bin/env bash
set -euo pipefail

MODE="${SCA_MONITOR_SYSTEMD_MODE:-validate}"
SCOPE="${SCA_MONITOR_SYSTEMD_SCOPE:-user}"
PREFIX="${SCA_MONITOR_SYSTEMD_PREFIX:-sca-monitor}"
PYTHON_BIN="${SCA_MONITOR_SYSTEMD_PYTHON:-python3}"
REPO_DIR="${SCA_MONITOR_SYSTEMD_REPO_DIR:-$PWD}"

case "$SCOPE" in
  user)
    SCOPE_FLAG="--user"
    ;;
  system)
    SCOPE_FLAG="--system"
    ;;
  *)
    echo "invalid SCA_MONITOR_SYSTEMD_SCOPE: $SCOPE" >&2
    exit 2
    ;;
esac

validate_units() {
  local staging_dir
  staging_dir="$(mktemp -d)"
  trap 'rm -rf "$staging_dir"' RETURN
  bash scripts/install_systemd_units.sh \
    "$SCOPE_FLAG" \
    --dry-run \
    --unit-dir "$staging_dir" \
    --repo-dir "$REPO_DIR" \
    --python "$PYTHON_BIN" \
    --prefix "$PREFIX" >/dev/null
  python3 scripts/systemd_scheduler_status.py \
    "$SCOPE_FLAG" \
    --unit-dir "$staging_dir" \
    --prefix "$PREFIX" \
    --json
}

install_units() {
  local enable_flag=()
  if [[ "$1" == "enable" ]]; then
    enable_flag=(--enable)
  fi
  bash scripts/install_systemd_units.sh \
    "$SCOPE_FLAG" \
    --repo-dir "$REPO_DIR" \
    --python "$PYTHON_BIN" \
    --prefix "$PREFIX" \
    "${enable_flag[@]}"
  python3 scripts/systemd_scheduler_status.py "$SCOPE_FLAG" --prefix "$PREFIX" --json
}

case "$MODE" in
  off)
    echo "systemd scheduler gate skipped: mode=off"
    ;;
  validate)
    validate_units
    ;;
  install)
    validate_units >/dev/null
    install_units install
    ;;
  enable)
    validate_units >/dev/null
    install_units enable
    ;;
  *)
    echo "invalid SCA_MONITOR_SYSTEMD_MODE: $MODE" >&2
    echo "expected one of: off, validate, install, enable" >&2
    exit 2
    ;;
esac
