#!/usr/bin/env bash
set -euo pipefail

REQ_IDS=("${@:-cr-001 cr-002 cr-003 cr-004 cr-005}")

echo "[demo] waiting for MCP server at ${CHANGE_GATE_MCP_URL} ..."
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "http://mcp-server:9000/.well-known/oauth-protected-resource/mcp"; then
    break
  fi
  sleep 2
done

echo "[demo] fetching access token from Keycloak ..."
TOKEN=$(curl -fsS -X POST "${KEYCLOAK_TOKEN_URL}" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CHANGE_GATE_CLIENT_ID}" \
  -d "client_secret=${CHANGE_GATE_CLIENT_SECRET}" \
  -d "scope=change:read change:approve change:approve:prod" \
  -d "resource=${CHANGE_GATE_RESOURCE_URL}" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

export CHANGE_GATE_ACCESS_TOKEN="${TOKEN}"

for rid in ${REQ_IDS[@]}; do
  echo ""
  echo "[demo] ===== ${rid} ====="
  python -m change_gate.agent.main "${rid}" --mcp-url "${CHANGE_GATE_MCP_URL}" || true
done

echo ""
echo "[demo] done. Open Jaeger at http://localhost:16686 (service: change-gate-agent / change-gate-mcp)."
