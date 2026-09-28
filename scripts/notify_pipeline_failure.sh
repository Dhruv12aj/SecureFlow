#!/usr/bin/env bash
# Push a "pipeline failed" alert straight into Alertmanager so failed
# builds reach the same inbox as production alerts. Never fails the build.
#   scripts/notify_pipeline_failure.sh "<build url>"
URL="${1:-}"

payload=$(jq -n --arg url "$URL" --arg build "${BUILD_NUMBER:-?}" '[{
    labels: {alertname: "PipelineFailed", severity: "critical", env: "ci", job: "jenkins"},
    annotations: {
        summary: "SecureFlow build #\($build) failed",
        description: "See \($url)console"
    },
    endsAt: (now + 900 | todate)
}]')

curl -fsS --max-time 5 -X POST -H "Content-Type: application/json" \
    -d "$payload" http://alertmanager:9093/api/v2/alerts >/dev/null \
    && echo "sent PipelineFailed alert" \
    || echo "alertmanager not reachable - skipped failure alert"
exit 0
