#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export APP_ENV="${APP_ENV:-dev}"
export SCA_MONITOR_HOST="${SCA_MONITOR_HOST:-127.0.0.1}"
export SCA_MONITOR_PORT="${SCA_MONITOR_PORT:-18780}"
export SCA_MONITOR_DATA_DIR="${SCA_MONITOR_DATA_DIR:-$ROOT_DIR/.data}"
export SCA_MONITOR_FRONTEND_DIR="${SCA_MONITOR_FRONTEND_DIR:-$ROOT_DIR/frontend}"

python3 -m backend.sca_monitor

