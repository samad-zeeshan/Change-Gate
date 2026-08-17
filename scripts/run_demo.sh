#!/usr/bin/env bash
set -euo pipefail

REQ_IDS=("${@:-cr-001 cr-002 cr-003 cr-004 cr-005}")

echo "[demo] waiting for MCP server at ${WARDEN_MCP_URL} ..."
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "http://mcp-server:9000/.well-known/oauth-protected-resource/mcp"; then
    break
  fi
  sleep 2
done

echo "[demo] fetching access token from Keycloak ..."
TOKEN=$(curl -fsS -X POST "${KEYCLOAK_TOKEN_URL}" \
  -d "grant_type=client_credentials" \
  -d "client_id=${WARDEN_CLIENT_ID}" \
  -d "client_secret=${WARDEN_CLIENT_SECRET}" \
  -d "scope=change:read change:approve change:approve:prod" \
  -d "resource=${WARDEN_RESOURCE_URL}" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

export WARDEN_ACCESS_TOKEN="${TOKEN}"

for rid in ${REQ_IDS[@]}; do
  echo ""
  echo "[demo] ===== ${rid} ====="
  python -m warden.agent.main "${rid}" --mcp-url "${WARDEN_MCP_URL}" || true
done

echo ""
echo "[demo] done. Open Jaeger at http://localhost:16686 (service: warden-agent / warden-mcp)."
