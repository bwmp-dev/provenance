# Paper test fixtures

`pnpm check` invokes the default Gradle check, which builds and hash-verifies all
14 benign and hostile fixture JARs and runs the focused `fork-pid-bomb` unit
suite:

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
six directories under `benign/`; it cannot select or execute a hostile fixture.
