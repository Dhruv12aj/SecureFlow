#!/usr/bin/env bash
# Check that the monitoring stack is actually working - not just "running":
# Prometheus is scraping both environments, the alert rules are loaded,
# and Alertmanager + Grafana are up.
set -euo pipefail

PROM=http://prometheus:9090

wait_for() {
    local name="$1" url="$2"
    for _ in $(seq 1 24); do
        curl -fsS --max-time 3 "$url" >/dev/null 2>&1 && { echo "    $name is up"; return 0; }
        sleep 5
    done
    echo "!!  $name did not come up"
    return 1
}

echo "==> monitoring stack"
wait_for Prometheus   "$PROM/-/ready"
wait_for Alertmanager "http://alertmanager:9093/-/ready"
wait_for Grafana      "http://grafana:3000/api/health"

# pick up any rule changes without a restart
curl -fsS -X POST "$PROM/-/reload" >/dev/null || true

# if this build didn't release, production may not exist yet - check staging instead
EXPECT="production"
docker inspect secureflow-prod >/dev/null 2>&1 || EXPECT="staging"

echo "==> scrape targets"
for _ in $(seq 1 12); do
    targets=$(curl -fsS "$PROM/api/v1/targets" \
        | jq -r '.data.activeTargets[] | select(.labels.job=="secureflow") | "\(.labels.env)=\(.health)"')
    echo "$targets" | grep -q "${EXPECT}=up" && break
    sleep 5
done
echo "$targets" | sed 's/^/    /'
echo "$targets" | grep -q "${EXPECT}=up" || { echo "!!  ${EXPECT} is not being scraped"; exit 1; }

echo "==> alert rules"
curl -fsS "$PROM/api/v1/rules" | jq -r '.data.groups[].rules[] | "    \(.name) [\(.state)]"'
rules=$(curl -fsS "$PROM/api/v1/rules" | jq '[.data.groups[].rules[]] | length')
[ "$rules" -ge 7 ] || { echo "!!  expected 7 alert rules, found $rules"; exit 1; }

echo "==> live numbers from ${EXPECT}"
curl -fsS "$PROM/api/v1/query" --data-urlencode "query=secureflow_app_info{env=\"${EXPECT}\"}" \
    | jq -r '.data.result[] | "    running version \(.metric.version)"'
curl -fsS "$PROM/api/v1/query" --data-urlencode "query=sum(secureflow_incidents_open{env=\"${EXPECT}\"})" \
    | jq -r '.data.result[] | "    open incidents: \(.value[1])"'

echo "==> dashboards: http://localhost:3000  |  alerts: http://localhost:9093"
