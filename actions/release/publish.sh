#!/usr/bin/env bash
# Create the release for VERSION at SHA unless its tag already exists.
set -euo pipefail

tag="v${VERSION}"
if gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" --silent 2>/dev/null; then
  echo "::notice::Tag ${tag} already exists; nothing to release."
  exit 0
fi

notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
python3 -P -m ci_checks.release notes --version "$VERSION" --changelog "$CHANGELOG" > "$notes"

flags=(--target "$SHA" --title "$tag" --notes-file "$notes")
if [[ "$PRERELEASE" == "true" ]]; then
  flags+=(--prerelease)
fi
gh release create "$tag" "${flags[@]}"
echo "::notice::Published ${tag}."
