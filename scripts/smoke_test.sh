#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:18780}"

curl -fsS "$BASE_URL/health" >/dev/null
curl -fsS "$BASE_URL/ready" >/dev/null
curl -fsS "$BASE_URL/api/v1/overview" >/dev/null
curl -fsS "$BASE_URL/" >/dev/null

payload='{
  "schema_version": "1.0",
  "service_id": "sca-monitor-smoke",
  "service_name": "SCA Monitor Smoke",
  "environment": "prod",
  "generated_at": "2026-06-11T00:00:00Z",
  "dependencies": [
    {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "scope": "production"}
  ]
}'

curl -fsS -H 'Content-Type: application/json' -d "$payload" "$BASE_URL/api/v1/snapshots" >/dev/null
curl -fsS "$BASE_URL/api/v1/impacts" | grep -q "lodash"

echo "smoke ok: $BASE_URL"

