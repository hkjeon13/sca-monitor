#!/usr/bin/env bash
set -euo pipefail

MODE="${SCA_MONITOR_POSTGRES_DOCKER_SMOKE:-auto}"
IMAGE="${SCA_MONITOR_POSTGRES_DOCKER_IMAGE:-postgres:16}"
WITH_API_WORKFLOW="${SCA_MONITOR_POSTGRES_DOCKER_API_WORKFLOW:-true}"
TIMEOUT_SECONDS="${SCA_MONITOR_POSTGRES_DOCKER_TIMEOUT_SECONDS:-45}"

case "$MODE" in
  disabled|skip|false|0)
    echo "postgres docker smoke skipped: disabled"
    exit 0
    ;;
  required|auto|"")
    ;;
  *)
    echo "invalid SCA_MONITOR_POSTGRES_DOCKER_SMOKE: $MODE" >&2
    exit 2
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  if [ "$MODE" = "required" ]; then
    echo "postgres docker smoke required but docker executable was not found" >&2
    exit 2
  fi
  echo "postgres docker smoke skipped: docker executable not found"
  exit 0
fi

extra_args=()
case "$WITH_API_WORKFLOW" in
  true|1|yes|on|"")
    extra_args+=(--with-api-workflow)
    ;;
  false|0|no|off)
    ;;
  *)
    echo "invalid SCA_MONITOR_POSTGRES_DOCKER_API_WORKFLOW: $WITH_API_WORKFLOW" >&2
    exit 2
    ;;
esac

python3 scripts/postgres_integration_smoke.py \
  --use-docker \
  --image "$IMAGE" \
  --timeout-seconds "$TIMEOUT_SECONDS" \
  "${extra_args[@]}" \
  --json
