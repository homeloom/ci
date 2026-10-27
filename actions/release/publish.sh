#!/usr/bin/env bash
# Create the release for VERSION at SHA when SHA is the commit that changed
# the version, its tag does not exist yet, and it is greater than every
# existing version tag. With PLAN=true, only write release=true or false to
# GITHUB_OUTPUT. With ASSET set, attach that file before the release shows.
set -euo pipefail

tag="v${VERSION}"

# Tell a planning run whether this commit is released.
decide() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "release=$1" >> "$GITHUB_OUTPUT"
  fi
}
skip() {
  echo "::notice::$1"
  decide false
  exit 0
}
tag_exists() {
  gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" --silent 2>/dev/null
}
# An existing tag is only fine when it is this commit's release: a tag on
# another commit, or a tag that no release uses, would leave the version
# unreleased without a word.
check_existing() {
  local target
  target="$(gh api "repos/${GITHUB_REPOSITORY}/commits/${tag}" --jq .sha)"
  if [[ "$target" != "$SHA" ]]; then
    echo "::error::Tag ${tag} points to ${target}, not to ${SHA}, the commit that changed the version. Delete the tag or bump the version again."
    exit 1
  fi
  if ! gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" --silent 2>/dev/null; then
    echo "::error::Tag ${tag} has no GitHub release. Delete the tag so that the next run releases it, or create the release by hand."
    exit 1
  fi
  skip "$1"
}
# A failed create is not an error when another run published the same
# version in the meantime.
created_elsewhere() {
  if tag_exists; then
    check_existing "Tag ${tag} was created by another run; nothing to release."
  fi
  exit 1
}

# CI runs on main finish in any order, so a later commit may pass first.
# Only the commit that changed the version is released, so that the release
# holds exactly the changes of its notes.
if [[ "$CHANGED" != "true" ]]; then
  skip "This commit does not change the version (${VERSION}); nothing to release."
fi
if tag_exists; then
  check_existing "Tag ${tag} already exists; nothing to release."
fi
gh api --paginate "repos/${GITHUB_REPOSITORY}/git/matching-refs/tags/v" --jq '.[].ref' \
  | python3 -P -m ci_checks.release newer --version "$VERSION"

notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
python3 -P -m ci_checks.release notes --version "$VERSION" --changelog "$CHANGELOG" > "$notes"

if [[ "${PLAN:-false}" == "true" ]]; then
  echo "::notice::${tag} will be released."
  decide true
  exit 0
fi

# Set "Latest" explicitly: GitHub marks every new release as the latest by
# default. The version is the highest, but a pre-release is never the latest.
prerelease=false
latest=true
if [[ "$PRERELEASE" == "true" ]]; then
  prerelease=true
  latest=false
fi

if [[ -z "${ASSET:-}" ]]; then
  flags=(--target "$SHA" --title "$tag" --notes-file "$notes")
  if [[ "$prerelease" == "true" ]]; then
    flags+=(--prerelease --latest=false)
  else
    flags+=(--latest)
  fi
  gh release create "$tag" "${flags[@]}" || created_elsewhere
  echo "::notice::Published ${tag}."
  exit 0
fi

if [[ ! -f "$ASSET" ]]; then
  echo "::error::The asset ${ASSET} does not exist."
  exit 1
fi
# A draft gets its tag only when it is published, so an installer never
# sees the release without its asset. Every later call names the draft by
# its id: a lookup by tag could find a release that another run published.
draft="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/releases" \
  -f tag_name="$tag" -f target_commitish="$SHA" -f name="$tag" -F body=@"$notes" \
  -F draft=true -F prerelease="$prerelease" --jq '"\(.id) \(.upload_url)"')" || created_elsewhere
id="${draft%% *}"
upload_url="${draft#* }"
upload_url="${upload_url%%\{*}"
if ! gh api --method POST "${upload_url}?name=${ASSET##*/}" \
  -H "Content-Type: application/zip" --input "$ASSET" --silent \
  || ! gh api --method PATCH "repos/${GITHUB_REPOSITORY}/releases/${id}" \
    -F draft=false -f make_latest="$latest" --silent; then
  # Leave no draft behind, so that the next run starts clean.
  gh api --method DELETE "repos/${GITHUB_REPOSITORY}/releases/${id}" --silent \
    || echo "::warning::Could not delete the draft release ${id}."
  created_elsewhere
fi
echo "::notice::Published ${tag} with ${ASSET##*/}."
