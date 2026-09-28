#!/usr/bin/env bash
# Wait until /health says "healthy" and reports the version we expect.
#   scripts/healthcheck.sh http://secureflow-staging:8000/health 1.0.42
set -uo pipefail

URL="$1"
EXPECTED_VERSION="${2:-}"
ATTEMPTS="${ATTEMPTS:-12}"

for i in $(seq 1 "$ATTEMPTS"); do
    body=$(curl -fsS --max-time 3 "$URL" 2>/dev/null)
    status=$(echo "$body" | jq -r '.status' 2>/dev/null)
    version=$(echo "$body" | jq -r '.version' 2>/dev/null)

    if [ "$status" = "healthy" ] && { [ -z "$EXPECTED_VERSION" ] || [ "$version" = "$EXPECTED_VERSION" ]; }; then
        echo "    healthy (version $version) after $i attempt(s)"
        exit 0
    fi
    echo "    attempt $i/$ATTEMPTS: not ready yet (status=${status:-none}, version=${version:-none})"
    sleep 5
done

exit 1
