#!/usr/bin/env bash
# Install pinned tools into a directory added to PATH.
# Every archive is checked against the SHA-256 digest recorded below before
# it is unpacked. To update a tool, change its version and digest together,
# taking the digest from the checksums published with the upstream release.
set -euo pipefail

if [[ "${RUNNER_OS:-}" != "Linux" || "${RUNNER_ARCH:-}" != "X64" ]]; then
  echo "::error::setup-tools supports Linux x64 runners only."
  exit 1
fi

bin_dir="${RUNNER_TEMP}/ci-tools/bin"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$bin_dir"

for tool in ${TOOLS}; do
  case "$tool" in
    actionlint)
      version="1.7.12"
      sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
      url="https://github.com/rhysd/actionlint/releases/download/v${version}/actionlint_${version}_linux_amd64.tar.gz"
      member="actionlint"
      ;;
    gitleaks)
      version="8.30.1"
      sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
      url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
      member="gitleaks"
      ;;
    ruff)
      version="0.17.2"
      sha256="7b2e6a6e132ecf7b5fe726163b186d5d209befe93bb25f83767b2d97fbdf14e5"
      url="https://github.com/astral-sh/ruff/releases/download/${version}/ruff-x86_64-unknown-linux-gnu.tar.gz"
      member="ruff-x86_64-unknown-linux-gnu/ruff"
      ;;
    uv)
      version="0.13.5"
      sha256="f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f"
      url="https://github.com/astral-sh/uv/releases/download/${version}/uv-x86_64-unknown-linux-gnu.tar.gz"
      member="uv-x86_64-unknown-linux-gnu/uv"
      ;;
    *)
      echo "::error::Unknown tool: ${tool}"
      exit 1
      ;;
  esac
  archive="${work_dir}/${tool}.tar.gz"
  curl --fail --silent --show-error --location --retry 3 --output "$archive" "$url"
  echo "${sha256}  ${archive}" | sha256sum --check --quiet
  tar -xzf "$archive" -C "$work_dir" "$member"
  install -m 0755 "${work_dir}/${member}" "${bin_dir}/${tool}"
  echo "Installed ${tool} ${version}."
done

echo "$bin_dir" >> "$GITHUB_PATH"
