# Provenance Paper probe

Install the probe JAR beside the plugin under test and set:

```text
-Dprovenance.probe.target=TargetPlugin
-Dprovenance.probe.requiredDependencies=DependencyOne,DependencyTwo
-Dprovenance.probe.events=provenance-probe-events.ndjson
-Dprovenance.probe.stabilizationMillis=3000
```

The probe writes flushed NDJSON lifecycle events to the configured event file.
The happy path is driven by Paper events and plugin-manager state, not ordinary
log text. Load/enable exceptions are taken from attached JVM `Throwable` values;
message prose is not parsed. Metadata inspection reads `plugin.yml` and
`paper-plugin.yml` directly from plugin JARs without loading plugin classes or
downloading dependencies. It records commands, permissions, and required
dependencies and suggests configured dependencies that the target does not
declare.

After the stabilization window the probe emits public-contract lifecycle kinds,
a stable failure classification when available, and a clean-shutdown request
before calling `Bukkit.shutdown()`. Set
`-Dprovenance.probe.requestShutdown=false` only for manual observation.

This slice does not execute console commands. The command fixtures are inputs for
the command orchestration work in WP-02C.
