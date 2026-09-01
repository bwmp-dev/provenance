#!/usr/bin/env bash
set -euo pipefail

readonly version="2.96.0"
readonly tag_commit="b300f2ec7ec9dc9addc39b2ad88c54097ded7ca0"
readonly archive_sha256="83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60"
readonly archive_size="14652560"
readonly archive_name="gh_${version}_linux_amd64.tar.gz"
readonly release_url="https://github.com/cli/cli/releases/download/v${version}/${archive_name}"
readonly expected_version_line="gh version ${version} (2026-07-02)"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The pinned GitHub CLI requires Linux amd64." >&2
  exit 1
fi
if [[ -z "${RUNNER_TEMP:-}" || -z "${GITHUB_PATH:-}" ]]; then
  echo "RUNNER_TEMP and GITHUB_PATH are required." >&2
  exit 1
fi

readonly expected_tag="${tag_commit}"$'\t'"refs/tags/v${version}"
actual_tag="$(git ls-remote https://github.com/cli/cli.git "refs/tags/v${version}")"
if [[ "$actual_tag" != "$expected_tag" ]]; then
  echo "GitHub CLI release tag identity differs." >&2
  exit 1
fi

readonly archive="$RUNNER_TEMP/$archive_name"
readonly install_root="$RUNNER_TEMP/gh_${version}_linux_amd64"
if [[ -e "$archive" || -e "$install_root" ]]; then
  echo "Pinned GitHub CLI destination already exists." >&2
  exit 1
fi

curl \
  --fail \
  --location \
  --proto '=https' \
  --show-error \
  --silent \
  --tlsv1.2 \
  --output "$archive" \
  "$release_url"

actual_size="$(wc -c <"$archive" | tr -d '[:space:]')"
if [[ "$actual_size" != "$archive_size" ]]; then
  echo "GitHub CLI archive size differs: expected $archive_size, got $actual_size." >&2
  exit 1
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum --check --strict

mkdir "$install_root"
tar \
  --extract \
  --file "$archive" \
  --gzip \
  --directory "$install_root" \
  --no-same-owner \
  --no-same-permissions \
  --strip-components 1

readonly binary="$install_root/bin/gh"
if [[ ! -f "$binary" || -L "$binary" || ! -x "$binary" ]]; then
  echo "Pinned GitHub CLI binary is not a regular executable." >&2
  exit 1
fi
binary_description="$(file --brief "$binary")"
if [[ "$binary_description" != *"ELF 64-bit LSB executable, x86-64"* ]]; then
  echo "Pinned GitHub CLI binary architecture differs: $binary_description" >&2
  exit 1
fi
reported_output="$("$binary" --version)"
reported_version="${reported_output%%$'\n'*}"
if [[ "$reported_version" != "$expected_version_line" ]]; then
  echo "Pinned GitHub CLI version differs: $reported_version" >&2
  exit 1
fi

printf '%s\n' "$install_root/bin" >>"$GITHUB_PATH"
