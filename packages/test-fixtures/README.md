# Paper test fixtures

The default Gradle check builds and hash-verifies only bounded behavioral
fixtures:

```text
node scripts/run-gradle.mjs :check
```

Sandbox-attack fixtures live under `hostile/` and are excluded from the default
check. Building and hash-verifying them requires the explicit
`verifyHostileFixtureArtifacts` task; merely building them does not execute
their payloads. Running a hostile fixture also requires the Paper process
property
`-Dprovenance.fixture.hostile.enabled=true`. Run hostile fixtures only inside a
disposable, resource-limited Plan 03 runner.

To reproduce and verify every published fixture hash:

```text
node scripts/run-gradle.mjs writeFixtureHashes
node scripts/run-gradle.mjs verifyHostileFixtureArtifacts
```

The fixtures compile against the local `paper-api-stubs` module. It contains only
the stable Bukkit method descriptors used by the fixtures and is never packaged
inside a fixture JAR.
