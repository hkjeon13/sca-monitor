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

preflight_enable() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd enable preflight failed: systemctl not found" >&2
    exit 2
  fi
  local systemctl_cmd=(systemctl)
  if [[ "$SCOPE" == "user" ]]; then
    systemctl_cmd+=(--user)
  fi
  if ! "${systemctl_cmd[@]}" list-unit-files >/dev/null 2>&1; then
    echo "systemd enable preflight failed: ${systemctl_cmd[*]} list-unit-files is not available" >&2
    exit 2
  fi
}

install_units() {
  if [[ "$1" == "enable-api" ]]; then
    bash scripts/install_systemd_units.sh \
      "$SCOPE_FLAG" \
      --repo-dir "$REPO_DIR" \
      --python "$PYTHON_BIN" \
      --prefix "$PREFIX" \
      --enable-api-only
  elif [[ "$1" == "enable-poller" ]]; then
    bash scripts/install_systemd_units.sh \
      "$SCOPE_FLAG" \
      --repo-dir "$REPO_DIR" \
      --python "$PYTHON_BIN" \
      --prefix "$PREFIX" \
      --enable-poller-only
  elif [[ "$1" == "enable-dispatcher-dry-run" ]]; then
    bash scripts/install_systemd_units.sh \
      "$SCOPE_FLAG" \
      --repo-dir "$REPO_DIR" \
      --python "$PYTHON_BIN" \
      --prefix "$PREFIX" \
      --enable-dispatcher-dry-run
  elif [[ "$1" == "enable" ]]; then
    bash scripts/install_systemd_units.sh \
      "$SCOPE_FLAG" \
      --repo-dir "$REPO_DIR" \
      --python "$PYTHON_BIN" \
      --prefix "$PREFIX" \
      --enable
  else
    bash scripts/install_systemd_units.sh \
      "$SCOPE_FLAG" \
      --repo-dir "$REPO_DIR" \
      --python "$PYTHON_BIN" \
      --prefix "$PREFIX"
  fi
  if [[ "$1" == "enable" || "$1" == "enable-api" || "$1" == "enable-poller" || "$1" == "enable-dispatcher-dry-run" ]]; then
    python3 scripts/systemd_scheduler_status.py "$SCOPE_FLAG" --prefix "$PREFIX" --systemctl --json
  else
    python3 scripts/systemd_scheduler_status.py "$SCOPE_FLAG" --prefix "$PREFIX" --json
  fi
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
    preflight_enable
    validate_units >/dev/null
    install_units enable
    ;;
  enable-api)
    preflight_enable
    validate_units >/dev/null
    install_units enable-api
    ;;
  enable-poller)
    preflight_enable
    validate_units >/dev/null
    install_units enable-poller
    ;;
  enable-dispatcher-dry-run)
    preflight_enable
    validate_units >/dev/null
    install_units enable-dispatcher-dry-run
    ;;
  *)
    echo "invalid SCA_MONITOR_SYSTEMD_MODE: $MODE" >&2
    echo "expected one of: off, validate, install, enable-api, enable-poller, enable-dispatcher-dry-run, enable" >&2
    exit 2
    ;;
esac
