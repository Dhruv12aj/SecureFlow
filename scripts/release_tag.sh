#!/usr/bin/env bash
# Tag the released commit in git and write release notes.
# Needs GH_USER and GH_TOKEN (from the github-creds Jenkins credential).
#   scripts/release_tag.sh v1.0.42
set -euo pipefail

TAG="$1"
NOTES="reports/release-notes-${TAG}.md"
mkdir -p reports

# github.com/owner/repo.git - so we can push with the token
REMOTE=$(git config --get remote.origin.url)
REPO_HOST_PATH="${REMOTE#https://}"

git fetch --tags --quiet "https://${GH_USER}:${GH_TOKEN}@${REPO_HOST_PATH}" || true
PREVIOUS=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

{
    echo "# SecureFlow ${TAG}"
    echo
    echo "Released $(date -u '+%Y-%m-%d %H:%M UTC') by Jenkins build #${BUILD_NUMBER:-?}"
    echo "Image: localhost:5000/secureflow:${TAG}"
    echo
    echo "## Changes${PREVIOUS:+ since $PREVIOUS}"
    if [ -n "$PREVIOUS" ]; then
        git log --pretty='- %s (%h)' "${PREVIOUS}..HEAD"
    else
        git log --pretty='- %s (%h)' -n 20
    fi
} > "$NOTES"
cat "$NOTES"

if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "==> tag $TAG already exists, skipping"
    exit 0
fi

git -c user.name="Jenkins" -c user.email="jenkins@secureflow.local" \
    tag -a "$TAG" -m "SecureFlow $TAG (Jenkins build #${BUILD_NUMBER:-?})"
git push --quiet "https://${GH_USER}:${GH_TOKEN}@${REPO_HOST_PATH}" "refs/tags/${TAG}"
echo "==> pushed git tag $TAG"
