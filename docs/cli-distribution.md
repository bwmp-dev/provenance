# CLI distribution

The inspected Linux amd64 release is
[`cli-v0.1.0-alpha.1`](https://github.com/bwmp-dev/provenance/releases/tag/cli-v0.1.0-alpha.1),
published by [run 34112911716, attempt 1](https://github.com/bwmp-dev/provenance/actions/runs/34112911716/attempts/1).
Its source and workflow/policy commit are both
`aff412c803552b595ba37fa708845c9c488f56a7`.

The archive `provenance-cli-0.1.0-alpha.1-linux-amd64.tar.gz` has SHA-256
`f6aff3e25f9109f87cac34c52a2abf51eb0f10f9e98755b4e8b467cb22260a48`;
the extracted binary has SHA-256
`20a44fe51857f5d1bdc74afb046b5037fbd1a760d77530ef886ea86d16fc4063`.
Inspection verified all four provenance subjects and the archive SPDX attestation,
then the independent non-executing bundle verifier, before running the actual
downloaded binary in the isolated native fixture described below. These pins
do not replace that verification order for a fresh download. The separate CLI
release does not change contract tags or their archive inventories.

## Assets

`cli-v0.1.0-alpha.1` shipped only the four Linux amd64 assets. Later releases
add cross-compiled macOS amd64/arm64 and Windows amd64 targets, for thirteen
assets. Linux keeps its original unsuffixed manifest/SBOM names:

- `provenance-cli-<version>-linux-amd64.tar.gz`
- `provenance-cli-<version>.manifest.json`
- `provenance-cli-<version>.spdx.json`
- `provenance-cli-<version>-<target>.tar.gz`, `-<target>.manifest.json` and
  `-<target>.spdx.json` for `darwin-amd64`, `darwin-arm64` and `windows-amd64`
- `provenance-cli-<version>.sha256`

The checksum file covers the other twelve assets. Provenance attestations cover
all thirteen, and each archive receives an SPDX attestation for its own
target SBOM. The Windows archive is also a `.tar.gz` (Windows 10+ includes
`tar`) and contains `provenance.exe`. An annotated Git tag is
not a signed Git tag; this does not claim immutable release hosting or a SLSA
level.

## Build and inspect

Use a complete repository checkout, Node 24, Python 3, Git, the locked pnpm
dependencies and **Go 1.25.13 on Linux amd64**; every target is cross-compiled
there with CGO disabled. No Node runtime is needed by the
resulting binary. Go dependency provisioning uses the public module proxy and
checksum database. Compilation then uses the populated task-private module
cache with the proxy disabled; this is not an offline cold-install claim.

```sh
node scripts/cli-release.mjs build --version 0.1.0-alpha.1 \
  --source-commit <exact-reviewed-40-character-SHA> --output /absolute/new/bundle
python3 scripts/verify-cli-release.py --version 0.1.0-alpha.1 \
  --source-sha <exact-reviewed-40-character-SHA> --directory /absolute/new/bundle
bash scripts/test-cli-release-native.sh /absolute/new/bundle 0.1.0-alpha.1 \
  <exact-reviewed-40-character-SHA>
```

The builder clones the exact source twice into different absolute directories,
requires clean source identity, sets CGO=0/GOAMD64=v1 (GOARM64=v8.0 for arm64),
trims paths and compares every binary and all thirteen asset bytes. Archive entries have fixed modes, sorted paths, numeric owner
zero and the source commit timestamp. It refuses existing output directories.
Only its newly allocated temporary cache is made writable for cleanup.

The manifest records every CLI/verifier source file and actual binary module
information. The local verifier replacement is labeled with the same repository
commit, not its placeholder Go module version. The archive carries repository
Apache-2.0 text, Go LICENSE/PATENTS, all audited linked-module license files,
Goja's nested Lucene/V8 notices and the pinned regexpp MIT license. Some modules
contain extra notices beyond their linked code; those notices are conservatively
included. Each target's manifest/SBOM lists only the modules actually linked for
that target: libsecret only for Linux, wincred only for Windows, and no Keychain
module for CGO-disabled macOS.
The SBOM uses `NOASSERTION` for unclassified aggregate license expressions rather
than guessing an SPDX expression; actual pinned license texts are included.

The independent Python verifier never invokes the binary, Go, Node or the
builder. It checks source bytes through Git, bounded decompression, safe archive
inventory, static Linux amd64 ELF identity, Mach-O CPU type with only the
system dynamic libraries Go's CGO-disabled darwin runtime uses, PE32+ amd64
console identity, embedded Go build information (including target GOOS/GOARCH),
linked module checksums against source `go.sum`, audited license hashes and
complete SPDX relationships. Source/code authenticity still depends on trusted
GitHub provenance, not a self-consistent checksum file alone.

The isolated native fixture installs its own test service packages in a
disposable image, then runs network-disabled with UID 10001, a private D-Bus and
Secret Service. It executes the verified extracted binary against synthetic
loopback HTTPS endpoints: shown-once login, native stored-session status,
locked-store preissuance failure, a valid signed artifact and a tampered artifact.
It mounts no repository checkout or host credential directory. Image package
provisioning is online and is not claimed hermetic.

## Publication boundary

Only an explicitly dispatched `release-cli.yml` on reviewed `main` publishes.
The build job is read-only. The write-enabled job checks out the immutable
workflow policy SHA, independently verifies the build artifact, rechecks source
ancestry/tag identity and attests subjects before publication. An absent tag is
distinguished from failed discovery. Existing annotated tags must identify the
same source. Existing releases must match metadata and all asset bytes; uploads
never use `--clobber`. A matching published repeat is read-only; conflicting,
extra, incomplete or partially uploaded assets fail closed. Draft recovery may
upload only missing names, then reads back every asset before publishing.

Before executing a downloaded release, an operator must independently verify
every provenance subject and each archive's SPDX attestation with a modern
GitHub CLI, pinning repository `bwmp-dev/provenance`, the trusted workflow/policy
commit, signer workflow `.github/workflows/release-cli.yml` and
`refs/heads/main` (including the signer certificate identity/SAN). Independently
pin the source commit in the annotated tag, manifest, source inventory and binary.
First publication has source SHA equal to workflow/policy SHA. Reconciliation of
an older annotated tag from newer accepted main can have different identities:
new attestations identify the newer policy invocation, not an old signer or an
assertion that the binary was built from that newer policy commit. Trust that
policy explicitly; do not substitute either identity for the other. Inspect the
annotated tag object and the release's actual asset inventory. Download into a
fresh directory, then run the independent verifier from the trusted policy
checkout. Never execute an unverified archive to inspect its identity.

Only the Linux amd64 archive is executed at release time (the isolated native
fixture above). macOS and Windows archives are built and statically verified on
Linux, not executed there; the CLI source is separately exercised by the
test-only GitHub-hosted macOS/Windows CI matrix. Session login needs an unlocked
native store with no plaintext fallback: Linux Secret Service or Windows
Credential Manager. **Cross-compiled macOS binaries have no Keychain backend,
so session login fails closed**; `verify` works. macOS login requires a native
cgo build. macOS binaries are ad-hoc signed by the Go linker only (not
Developer ID signed or notarized) and Windows binaries are not Authenticode
signed. No live platform, browser confirmation, automatic update channel or
default platform origin is supplied. The archive README
documents all four verbs and explicit origin/key trust requirements.
