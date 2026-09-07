#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/provenance-cli-native.XXXXXXXX")
fixture_image="provenance-cli-native-fixture:$(basename "$fixture_dir" | tr '[:upper:]' '[:lower:]')"
cleanup() {
  docker image rm "$fixture_image" >/dev/null 2>&1 || true
  case "$fixture_dir" in */provenance-cli-native.????????) rm -r -- "$fixture_dir" ;; *) return 1 ;; esac
}
trap cleanup EXIT
CGO_ENABLED=0 go -C packages/cli-go test -c -o "$fixture_dir/native-store.test" ./internal/securestore
docker build -f packages/cli-go/testdata/native-store.Dockerfile -t "$fixture_image" packages/cli-go/testdata
# The fixture has its own bus, daemon and throwaway filesystem, no host bus or
# credential directories. Network access is disabled during native acceptance.
docker run --rm --network none -v "$fixture_dir/native-store.test:/proof/native-store.test:ro" "$fixture_image"
