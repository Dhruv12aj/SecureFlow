#!/usr/bin/env bash
# Make sure the SonarQube project and our custom quality gate exist.
# Safe to run on every build - it only adds what is missing.
set -euo pipefail

SONAR="${SONAR_HOST_URL:-http://sonarqube:9000}"
GATE="SecureFlow Gate"
PROJECT="secureflow"

post() {
    curl -fsS -u "${SONAR_TOKEN}:" -X POST "$SONAR/api/$1" "${@:2}"
}

# wait for SonarQube to be up (it's slow to start)
for _ in $(seq 1 30); do
    [ "$(curl -fsS "$SONAR/api/system/status" | jq -r .status)" = "UP" ] && break
    echo "    waiting for SonarQube..."
    sleep 5
done

post projects/create --data-urlencode "project=$PROJECT" --data-urlencode "name=SecureFlow" >/dev/null 2>&1 \
    && echo "    created project $PROJECT" || true

if ! curl -fsS -u "${SONAR_TOKEN}:" -G "$SONAR/api/qualitygates/show" --data-urlencode "name=$GATE" >/dev/null 2>&1; then
    echo "    creating quality gate '$GATE'"
    post qualitygates/create --data-urlencode "name=$GATE" >/dev/null
fi

existing=$(curl -fsS -u "${SONAR_TOKEN}:" -G "$SONAR/api/qualitygates/show" --data-urlencode "name=$GATE" \
    | jq -r '.conditions[]?.metric')

# Newer SonarQube versions (MQR mode) renamed the rating metrics, so for the
# ratings we try the new name first and fall back to the classic one.
#   metrics (new|classic)                                        op  threshold
while read -r metrics op value; do
    if echo "$existing" | grep -qxE "$metrics"; then
        continue
    fi
    added=""
    for metric in ${metrics//|/ }; do
        if post qualitygates/create_condition --data-urlencode "gateName=$GATE" \
               -d "metric=$metric" -d "op=$op" -d "error=$value" >/dev/null 2>&1; then
            echo "      + $metric $op $value"
            added=yes
            break
        fi
    done
    [ -n "$added" ] || echo "      ! could not add a condition for $metrics"
done <<'EOF'
coverage LT 80
duplicated_lines_density GT 3
software_quality_reliability_rating|reliability_rating GT 1
software_quality_security_rating|security_rating GT 1
software_quality_maintainability_rating|sqale_rating GT 1
EOF

post qualitygates/select --data-urlencode "gateName=$GATE" --data-urlencode "projectKey=$PROJECT" >/dev/null
echo "    '$GATE' is assigned to $PROJECT:"
curl -fsS -u "${SONAR_TOKEN}:" -G "$SONAR/api/qualitygates/show" --data-urlencode "name=$GATE" \
    | jq -r '.conditions[] | "      \(.metric) \(.op) \(.error)"'
