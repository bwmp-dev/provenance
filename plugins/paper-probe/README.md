# Provenance Paper probe

Install the probe JAR beside the plugin under test and set:

```text
-Dprovenance.probe.target=TargetPlugin
-Dprovenance.probe.requiredDependencies=DependencyOne,DependencyTwo
-Dprovenance.probe.events=provenance-probe-events.ndjson
-Dprovenance.probe.testPlan=provenance-test-plan.json
-Dprovenance.probe.stabilizationMillis=3000
-Dprovenance.probe.maximumCommandOutputBytes=4096
```

The probe writes flushed NDJSON lifecycle events to the configured event file.
The happy path is driven by Paper events and plugin-manager state, not ordinary
log text. Load/enable exceptions are taken from attached JVM `Throwable` values;
message prose is not parsed. Metadata inspection reads `plugin.yml` and
`paper-plugin.yml` directly from plugin JARs without loading plugin classes or
downloading dependencies. It records commands, permissions, and required
dependencies and suggests configured dependencies that the target does not
declare.

The JSON test plan may include a `console` array matching `tests.console` in the
v1 configuration schema. Each assertion has an optional `operator` of
`contains` or `regex`; the default is `regex` for compatibility with existing
v1 configuration. Regular expressions use RE2 syntax and linear-time matching.
Command sender output is normalized to plain NFC text with LF line endings and
bounded independently for each command. A watchdog emits timeout evidence even
when a command blocks Paper's server thread; the runner's wall-clock boundary is
still responsible for terminating a command that never returns.
Sender messages are `stdout` and `combined`; `stderr` is empty because command
exceptions are reported as structured execution classifications instead.
The output bound may be set from 1,024 through 16,384 bytes, and plans are
rejected if their worst-case command events exceed the reserved 512-event
budget.

After the stabilization window the probe emits public-contract lifecycle kinds,
a stable failure classification when available, and a clean-shutdown request
before calling `Bukkit.shutdown()`. Set
`-Dprovenance.probe.requestShutdown=false` only for manual observation.

Registration, execution, timeout, output, and assertion results are emitted as
separate structured events. The probe stops scheduling additional commands after
a timeout. As with lifecycle evidence, a malicious plugin sharing the JVM can
tamper with probe behavior; process isolation and evidence limits remain runner
responsibilities.
