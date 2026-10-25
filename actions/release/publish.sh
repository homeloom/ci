#!/usr/bin/env bash
# Create the release for VERSION at SHA when SHA is the commit that changed
# the version, its tag does not exist yet, and it is greater than every
# existing version tag.
set -euo pipefail

tag="v${VERSION}"
# CI runs on main finish in any order, so a later commit may pass first.
# Only the commit that changed the version is released, so that the release
# holds exactly the changes of its notes.
if [[ "$CHANGED" != "true" ]]; then
  echo "::notice::This commit does not change the version (${VERSION}); nothing to release."
  exit 0
fi
if gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" --silent 2>/dev/null; then
  echo "::notice::Tag ${tag} already exists; nothing to release."
  exit 0
fi
gh api --paginate "repos/${GITHUB_REPOSITORY}/git/matching-refs/tags/v" --jq '.[].ref' \
  | python3 -P -m ci_checks.release newer --version "$VERSION"

notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
python3 -P -m ci_checks.release notes --version "$VERSION" --changelog "$CHANGELOG" > "$notes"

# Set "Latest" explicitly: GitHub marks every new release as the latest by
# default. The version is the highest, but a pre-release is never the latest.
flags=(--target "$SHA" --title "$tag" --notes-file "$notes")
if [[ "$PRERELEASE" == "true" ]]; then
  flags+=(--prerelease --latest=false)
else
  flags+=(--latest)
fi
if ! gh release create "$tag" "${flags[@]}"; then
  # Another run may have published the same version in the meantime.
  if gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" --silent 2>/dev/null; then
    echo "::notice::Tag ${tag} was created by another run; nothing to release."
    exit 0
  fi
  exit 1
fi
echo "::notice::Published ${tag}."
