# Paper test fixtures

`pnpm check` invokes the default Gradle check, which builds and hash-verifies all
16 benign and hostile fixture JARs and runs the focused `fork-pid-bomb`,
`matrix-compatibility` and `test-secret-delivery` unit suites:

```text
node scripts/run-gradle.mjs :check
```

Sandbox-attack fixtures live under `hostile/`. The default check invokes the
explicit `verifyHostileFixtureArtifacts` task to build and hash them, but neither
that task nor the focused unit suite executes hostile payloads. Actual hostile
execution requires the Paper process property
`-Dprovenance.fixture.hostile.enabled=true` and must occur only inside a
disposable, resource-limited Plan 03 runner.

To reproduce and verify every published fixture hash:

```text
node scripts/run-gradle.mjs writeFixtureHashes
node scripts/run-gradle.mjs verifyHostileFixtureArtifacts
```

The fixtures compile against the local `paper-api-stubs` module. It contains only
the stable Bukkit method descriptors used by the fixtures and is never packaged
inside a fixture JAR.

## Development Paper acceptance harness

Run the six benign fixtures in separate real Paper processes with the manual,
networked acceptance command:

```text
pnpm run paper:behavioral -- --java /path/to/java
```

The Paper version, build, download URL, size, and SHA-256 digest are pinned in
`test-data/paper-development.json`. The harness verifies that artifact and the
fixture hash manifest before execution. It evaluates the probe NDJSON rather
than Paper log prose, enforces per-process time and output bounds, and retains
the exact Paper, probe, fixture, Java, event, and log identities in a JSON
summary under `build/paper-behavioral/`.

This command is intentionally outside the default check because it downloads a
Paper runtime and starts six Minecraft servers. Its allowlist is fixed to the
six original directories under `benign/`; it cannot select or execute a hostile fixture.

## Same-artifact matrix producer proof

`matrix-compatibility` is a separate benign acceptance fixture. Its single JAR
loads on the supported API floor (1.20.6), deliberately throws from `onEnable`
on 1.20.6 and 1.21.4, and enables on exactly 1.21.8. Unknown versions fail closed.
A fixed ten-second fixture-only observation window precedes classification so
the hosted restart driver can observe the already-running attempt. Interruption
is preserved; no runner, startup, or gate deadline is extended.

Build the probe and fixture, then run the opt-in producer proof:

```text
node scripts/run-gradle.mjs :paper-probe:jar verifySafeFixtureArtifacts
pnpm paper:matrix /path/to/assets /path/to/temurin-21.0.8+9/bin/java /new/evidence/path
```

The asset directory contains the three exact `runtime-VERSION.tar.gz` prepared
archives and `paper-VERSION-BUILD.jar` files pinned in
`scripts/run-matrix-behavioral.mjs`. The command verifies their hashes, uses the
same fixture/probe bytes for every environment, binds only loopback on an
ephemeral port, limits each process to 180 seconds and four MiB of console
output, and validates structured lifecycle evidence rather than log prose.
The summary retains artifact/runtime identities and bounded classifications;
raw probe/log files remain local to the owner-only evidence directory.

This proves producer behavior, not gVisor isolation, component restarts, remote
storage, or the Plan 05/06 hosted exit gate. Release bundles add this fixture
without replacing or changing the existing success fixture.

## Synthetic test-secret delivery fixture

`test-secret-delivery` is built and unit-tested by default, but is not added to
the real-Paper behavioral harness's execution allowlist. Explicitly select its
JAR and the project secret `fixture-token` for a controlled acceptance job.
The value must be `provenance-synthetic-alpha-` followed by 32–128 lowercase
hexadecimal characters. Never provision a real credential for this fixture.

Startup requires the fixed job-private file to be regular, non-symlink and
read-only. The `provenance-test-secret` console command reads it again and emits
`PROVENANCE_SECRET_FIXTURE_VALUE=<synthetic value>` followed by
`PROVENANCE_SECRET_FIXTURE_OK`. The acceptance driver must independently verify
that the actual secret is replaced by `[REDACTED]` in live and complete logs;
the OK marker alone does not prove redaction. Refusals contain no value or path.
Input is bounded to 256 bytes; no host path, environment override or network
access is accepted. Byte-buffer clearing does not claim complete JVM heap erasure.

Focused tests use temporary synthetic files, not a server or hosted secret.
They do not prove end-to-end delivery, revocation, rotation, restart or cleanup;
those require the deployed platform/gateway/runner acceptance record.
