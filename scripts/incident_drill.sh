#!/usr/bin/env bash
# Incident drills - prove that monitoring catches real problems and emails
# the team, then show everything recovering.
#
#   scripts/incident_drill.sh attack-wave     # flood production with attacks
#   scripts/incident_drill.sh staging-outage  # take staging down for ~2 min
set -euo pipefail

DRILL="${1:-attack-wave}"
AM=http://alertmanager:9093

wait_for_alert() {
    local alert="$1" timeout="$2"
    echo "==> waiting up to ${timeout}s for $alert to fire"
    for i in $(seq 1 $((timeout / 5))); do
        firing=$(curl -fsS "$AM/api/v2/alerts?active=true&filter=alertname%3D%22${alert}%22" | jq 'length')
        if [ "$firing" -gt 0 ]; then
            echo "    $alert is FIRING after ~$((i * 5))s - email sent to the on-call address"
            curl -fsS "$AM/api/v2/alerts?filter=alertname%3D%22${alert}%22" \
                | jq -r '.[] | "    \(.labels.env): \(.annotations.summary)"'
            return 0
        fi
        sleep 5
    done
    echo "!!  $alert never fired"
    return 1
}

case "$DRILL" in
    attack-wave)
        echo "==> drill: attack wave against production"
        python3 scripts/attack_sim.py --target http://secureflow-prod:8000 --rounds 3 --delay 0.1
        wait_for_alert AttackWave 180
        ;;

    staging-outage)
        echo "==> drill: staging outage"
        docker stop secureflow-staging
        wait_for_alert SecureFlowDown 150 || { docker start secureflow-staging; exit 1; }
        echo "==> recovering staging"
        docker start secureflow-staging
        bash scripts/healthcheck.sh http://secureflow-staging:8000/health
        echo "    staging is back - a RESOLVED email will follow within a couple of minutes"
        ;;

    *)
        echo "unknown drill: $DRILL (use attack-wave or staging-outage)"
        exit 1
        ;;
esac
