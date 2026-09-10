#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 3 ]] || { echo 'expected bundle directory, version, source SHA' >&2; exit 1; }
cd "$(dirname "$0")/.."
bundle=$(realpath -- "$1")
version=$2
source_sha=$3
# Never execute downloaded bytes before independent identity/inventory checks.
python3 scripts/verify-cli-release.py --directory "$bundle" --version "$version" --source-sha "$source_sha"
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/provenance-cli-release-native.XXXXXXXX")
fixture_image="provenance-cli-release-native:$(basename "$fixture_dir" | tr '[:upper:]' '[:lower:]')"
fixture_container="$(basename "$fixture_dir" | tr '[:upper:]' '[:lower:]')"
cleanup() {
  docker rm -f "$fixture_container" >/dev/null 2>&1 || true
  docker image rm "$fixture_image" >/dev/null 2>&1 || true
  case "$fixture_dir" in */provenance-cli-release-native.????????) rm -r -- "$fixture_dir" ;; *) return 1 ;; esac
}
trap cleanup EXIT
tar -xzf "$bundle/provenance-cli-$version-linux-amd64.tar.gz" -C "$fixture_dir"
docker build -f scripts/fixtures/cli-release/Dockerfile -t "$fixture_image" scripts/fixtures/cli-release
docker run --rm --name "$fixture_container" --network none \
  -v "$fixture_dir/provenance-cli-$version-linux-amd64/provenance:/proof/provenance:ro" \
  -v "$PWD/schemas/fixtures/attestation/interop/small-artifact.json:/proof/vector.json:ro" \
  -v "$PWD/schemas/fixtures/attestation/interop/small-artifact-v2.json:/proof/vector-v2.json:ro" \
  "$fixture_image"
