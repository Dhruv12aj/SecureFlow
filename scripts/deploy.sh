#!/usr/bin/env bash
# Deploy an image tag to staging or prod, health-check it, and roll back
# to the previous version automatically if it doesn't come up healthy.
#
#   scripts/deploy.sh staging 1.0.42
#   scripts/deploy.sh prod v1.0.42
set -euo pipefail

ENVIRONMENT="$1"
NEW_TAG="$2"
CONTAINER="secureflow-${ENVIRONMENT}"
COMPOSE_FILE="deploy/docker-compose.${ENVIRONMENT}.yml"
HEALTH_URL="http://${CONTAINER}:8000/health"

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

# what's running right now? (empty on the very first deploy)
PREVIOUS_TAG=""
if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    PREVIOUS_IMAGE=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER")
    PREVIOUS_TAG="${PREVIOUS_IMAGE##*:}"
fi
echo "==> ${ENVIRONMENT}: ${PREVIOUS_TAG:-nothing} -> ${NEW_TAG}"

# rollback demo: start the new version with a database path it can't write to
if [ "${BREAK_DEPLOY:-false}" = "true" ]; then
    echo "!!  BREAK_DEPLOY is set - this deployment is expected to fail"
    export DATABASE_PATH_OVERRIDE=/proc/not-writable/secureflow.db
fi

export IMAGE_TAG="$NEW_TAG"
compose pull --quiet
compose up -d --remove-orphans

if bash scripts/healthcheck.sh "$HEALTH_URL" "${NEW_TAG#v}"; then
    echo "==> ${ENVIRONMENT} is healthy on ${NEW_TAG}"
    exit 0
fi

echo "!!  ${NEW_TAG} failed its health check on ${ENVIRONMENT}"
docker logs --tail 30 "$CONTAINER" || true

if [ -z "$PREVIOUS_TAG" ]; then
    echo "!!  no previous version to roll back to"
    exit 1
fi

echo "==> rolling back ${ENVIRONMENT} to ${PREVIOUS_TAG}"
unset DATABASE_PATH_OVERRIDE
export IMAGE_TAG="$PREVIOUS_TAG"
compose up -d --remove-orphans
bash scripts/healthcheck.sh "$HEALTH_URL" "${PREVIOUS_TAG#v}"
echo "==> rollback complete - ${ENVIRONMENT} is back on ${PREVIOUS_TAG}"
# still fail the build so nobody thinks the new version went out
exit 1
