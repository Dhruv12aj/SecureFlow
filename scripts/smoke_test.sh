#!/usr/bin/env bash
# Quick functional check after a deployment: can we authenticate, create,
# read and resolve an incident? Needs ANALYST_API_KEY in the environment.
#   scripts/smoke_test.sh http://secureflow-staging:8000
set -euo pipefail

BASE="$1"
AUTH=(-H "X-API-Key: ${ANALYST_API_KEY}" -H "Content-Type: application/json")

echo "==> smoke test against $BASE"

id=$(curl -fsS "${AUTH[@]}" -X POST "$BASE/incidents" \
    -d '{"title":"Pipeline smoke test","severity":"LOW","source":"Jenkins","description":"created by the deploy stage"}' \
    | jq -r '.id')
echo "    created incident #$id"

curl -fsS "${AUTH[@]}" "$BASE/incidents/$id" | jq -e '.title == "Pipeline smoke test"' >/dev/null
echo "    read it back"

curl -fsS "${AUTH[@]}" -X PUT "$BASE/incidents/$id" -d '{"status":"RESOLVED"}' \
    | jq -e '.status == "RESOLVED"' >/dev/null
echo "    resolved it"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/incidents")
[ "$code" = "401" ] || { echo "!!  expected 401 without a key, got $code"; exit 1; }
echo "    unauthenticated request rejected"

curl -fsS "$BASE/metrics" | grep -q secureflow_app_info
echo "    metrics endpoint ok"
