package dev.provenance.probe;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.server.PluginDisableEvent;
import org.bukkit.event.server.PluginEnableEvent;
import org.bukkit.event.server.ServerLoadEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

public final class PaperProbePlugin extends JavaPlugin implements Listener {
  private static final PlainTextComponentSerializer PLAIN_TEXT =
      PlainTextComponentSerializer.plainText();

  private final PluginMetadataDiscovery discovery = new PluginMetadataDiscovery();
  private final LifecycleValidator validator = new LifecycleValidator();
  private final Set<Logger> observedLoggers = new LinkedHashSet<>();
  private List<PluginDescriptor> discoveredPlugins = List.of();
  private ProbeConfiguration configuration;
  private EventSink sink;
  private LifecycleExceptionHandler exceptionHandler;
  private CommandTestPlan commandTestPlan = new CommandTestPlan(List.of());
  private boolean commandTestPlanValid;
  private CommandTestRunner commandTestRunner;
  private boolean shutdownRequested;

  @Override
  public void onLoad() {
    configuration = ProbeConfiguration.fromSystemProperties();
    try {
      sink = new NdjsonEventSink(configuration.eventFile());
      List<MetadataInspection> inspections =
          discovery.inspectDirectory(Bukkit.getPluginsFolder().toPath());
      discoveredPlugins =
          inspections.stream()
              .filter(inspection -> inspection.status() == MetadataStatus.VALID)
              .map(MetadataInspection::descriptor)
              .toList();
      inspections.forEach(this::emitMetadataInspection);
      readCommandTestPlan();
    } catch (IOException exception) {
      throw new IllegalStateException("could not initialize Paper probe", exception);
    }

    Map<String, String> pluginByMainClass = new LinkedHashMap<>();
    for (PluginDescriptor plugin : discoveredPlugins) {
      pluginByMainClass.put(plugin.mainClass(), plugin.name());
      emitPluginState(
          plugin.name(),
          plugin.source().getFileName().toString(),
          plugin.mainClass(),
          true,
          false,
          false);
    }
    exceptionHandler = new LifecycleExceptionHandler(sink, pluginByMainClass);
    observe(Logger.getLogger(""));
    observe(Bukkit.getLogger());
    emit(
        EventType.PROBE_LOADED,
        Map.of(
            "eventFile",
            configuration.eventFile().toString(),
            "lifecycleKind",
            "LIFECYCLE_EVENT_KIND_SERVER_STARTING"));
    emitConfiguredDependencySuggestions();
  }

  @Override
  public void onEnable() {
    Bukkit.getPluginManager().registerEvents(this, this);
    commandTestRunner =
        new CommandTestRunner(sink, configuration.maximumCommandOutputBytes());
    emitLoadedPluginStates();
  }

  @Override
  public void onDisable() {
    if (commandTestRunner != null) {
      commandTestRunner.close();
    }
    if (exceptionHandler != null) {
      for (Logger logger : observedLoggers) {
        logger.removeHandler(exceptionHandler);
      }
    }
    if (sink != null) {
      emit(
          EventType.SERVER_STOPPED,
          Map.of(
              "lifecycleKind",
              "LIFECYCLE_EVENT_KIND_SERVER_STOPPED",
              "shutdownRequested",
              shutdownRequested));
      sink.close();
    }
  }

  @EventHandler(priority = EventPriority.MONITOR)
  public void onPluginEnable(PluginEnableEvent event) {
    Plugin plugin = event.getPlugin();
    emitPluginState(plugin.getName(), "", mainClass(plugin), true, true, true);
  }

  @EventHandler(priority = EventPriority.MONITOR)
  public void onPluginDisable(PluginDisableEvent event) {
    Plugin plugin = event.getPlugin();
    emitPluginState(plugin.getName(), "", mainClass(plugin), true, true, false);
  }

  @EventHandler(priority = EventPriority.MONITOR)
  public void onServerLoaded(ServerLoadEvent event) {
    emit(EventType.SERVER_LOADED, Map.of("loadType", event.getType().name()));
    List<PluginSnapshot> snapshots = snapshots();
    for (PluginSnapshot plugin : snapshots) {
      emitPluginState(plugin.name(), "", "", true, plugin.loaded(), plugin.enabled());
    }
    emit(
        EventType.STABILIZATION_STARTED,
        Map.of("durationMillis", configuration.stabilizationMillis()));
    long delayTicks = Math.max(1, (configuration.stabilizationMillis() + 49) / 50);
    Bukkit.getScheduler().runTaskLater(this, this::finishStabilization, delayTicks);
  }

  private void finishStabilization() {
    boolean requirementsSatisfied = emitRequirementStatuses(snapshots());
    emit(
        EventType.STABILIZATION_COMPLETED,
        Map.of("durationMillis", configuration.stabilizationMillis()));
    emit(
        EventType.SERVER_READY,
        Map.of(
            "requirementsSatisfied",
            requirementsSatisfied,
            "lifecycleKind",
            "LIFECYCLE_EVENT_KIND_SERVER_READY"));
    if (requirementsSatisfied && commandTestPlanValid && !commandTestPlan.console().isEmpty()) {
      CommandTestRunner.CommandSuiteResult result =
          commandTestRunner.run(commandTestPlan.console(), new PaperCommandDispatcher());
      emit(
          EventType.TEST_PLAN,
          Map.of(
              "status", "COMPLETED",
              "consoleTests", commandTestPlan.console().size(),
              "passed", result.passed(),
              "timedOut", result.timedOut()));
    }
    if (configuration.requestShutdown()) {
      emit(EventType.CLEAN_SHUTDOWN_REQUESTED, Map.of("reason", "probe test plan complete"));
      shutdownRequested = true;
      Bukkit.shutdown();
    }
  }

  private void readCommandTestPlan() {
    try {
      commandTestPlan = new CommandTestPlanReader().read(configuration.testPlanFile());
      commandTestPlanValid = true;
      emit(
          EventType.TEST_PLAN,
          Map.of(
              "status", "LOADED",
              "consoleTests", commandTestPlan.console().size(),
              "maximumCommandOutputBytes", configuration.maximumCommandOutputBytes()));
    } catch (IOException | TestPlanException exception) {
      commandTestPlanValid = false;
      String issue =
          exception instanceof TestPlanException
              ? exception.getMessage()
              : "could not read test plan";
      emit(
          EventType.TEST_PLAN,
          Map.of("status", "INVALID", "issue", issue));
      emit(
          EventType.CLASSIFICATION,
          ProbeClassification.INVALID_TEST_PLAN.data(Map.of("issue", issue)));
    }
  }

  private boolean emitRequirementStatuses(List<PluginSnapshot> snapshots) {
    LinkedHashSet<String> requiredDependencies =
        new LinkedHashSet<>(configuration.requiredDependencies());
    if (configuration.target() != null) {
      discoveredPlugins.stream()
          .filter(plugin -> plugin.name().equalsIgnoreCase(configuration.target()))
          .findFirst()
          .ifPresent(plugin -> requiredDependencies.addAll(plugin.requiredDependencies()));
      Plugin target = Bukkit.getPluginManager().getPlugin(configuration.target());
      if (target != null) {
        requiredDependencies.addAll(target.getPluginMeta().getPluginDependencies());
      }
    }

    boolean satisfied = true;
    for (RequirementStatus status :
        validator.evaluate(configuration.target(), requiredDependencies, snapshots)) {
      LinkedHashMap<String, Object> data = new LinkedHashMap<>();
      data.put("role", status.role());
      data.put("name", status.name());
      data.put("configured", status.configured());
      data.put("loaded", status.loaded());
      data.put("enabled", status.enabled());
      emit(EventType.TARGET_REQUIREMENT, data);
      emitRequirementClassification(status);
      satisfied &= status.configured() && status.loaded() && status.enabled();
    }
    return satisfied;
  }

  private void emitLoadedPluginStates() {
    for (Plugin plugin : Bukkit.getPluginManager().getPlugins()) {
      emitPluginState(plugin.getName(), "", mainClass(plugin), true, true, plugin.isEnabled());
    }
  }

  private void emitMetadataInspection(MetadataInspection inspection) {
    LinkedHashMap<String, Object> data = new LinkedHashMap<>();
    data.put("artifact", inspection.source().getFileName().toString());
    data.put("status", inspection.status().name());
    data.put("issues", inspection.issues());
    if (inspection.descriptor() != null) {
      PluginDescriptor descriptor = inspection.descriptor();
      data.put("name", descriptor.name());
      data.put("version", descriptor.version());
      data.put("mainClass", descriptor.mainClass());
      data.put("apiVersion", descriptor.apiVersion());
      data.put("requiredDependencies", descriptor.requiredDependencies());
      data.put("permissions", descriptor.permissions());
      data.put("commands", descriptor.commands());
    }
    emit(EventType.METADATA_INSPECTION, data);
    if (inspection.status() != MetadataStatus.VALID) {
      emit(
          EventType.CLASSIFICATION,
          ProbeClassification.INVALID_METADATA.data(
              Map.of(
                  "artifact", inspection.source().getFileName().toString(),
                  "issues", inspection.issues())));
    }
  }

  private void emitRequirementClassification(RequirementStatus status) {
    if (status.enabled()) {
      return;
    }
    ProbeClassification classification;
    if (status.role().equals("TARGET")) {
      boolean discovered =
          discoveredPlugins.stream()
              .anyMatch(plugin -> plugin.name().equalsIgnoreCase(status.name()));
      if (discovered || status.loaded()) {
        return;
      }
      classification = ProbeClassification.PLUGIN_NOT_FOUND;
    } else if (!status.loaded()) {
      classification = ProbeClassification.MISSING_REQUIRED_DEPENDENCY;
    } else {
      classification = ProbeClassification.FAILED_REQUIRED_DEPENDENCY;
    }
    emit(
        EventType.CLASSIFICATION,
        classification.data(Map.of("plugin", status.name(), "role", status.role())));
  }

  private void emitConfiguredDependencySuggestions() {
    if (configuration.target() == null) {
      return;
    }
    discoveredPlugins.stream()
        .filter(plugin -> plugin.name().equalsIgnoreCase(configuration.target()))
        .findFirst()
        .ifPresent(
            target ->
                discovery
                    .undeclaredConfiguredDependencies(target, configuration.requiredDependencies())
                    .forEach(
                        dependency ->
                            emit(
                                EventType.METADATA_SUGGESTION,
                                Map.of(
                                    "plugin",
                                    target.name(),
                                    "dependency",
                                    dependency,
                                    "suggestion",
                                    "declare as a required dependency"))));
  }

  private List<PluginSnapshot> snapshots() {
    List<PluginSnapshot> snapshots = new ArrayList<>();
    for (Plugin plugin : Bukkit.getPluginManager().getPlugins()) {
      snapshots.add(new PluginSnapshot(plugin.getName(), true, plugin.isEnabled()));
    }
    return List.copyOf(snapshots);
  }

  private String mainClass(Plugin plugin) {
    return plugin.getPluginMeta().getMainClass();
  }

  private void emitPluginState(
      String name,
      String artifact,
      String mainClass,
      boolean discovered,
      boolean loaded,
      boolean enabled) {
    LinkedHashMap<String, Object> data = new LinkedHashMap<>();
    data.put("name", name);
    data.put("artifact", artifact);
    data.put("mainClass", mainClass);
    data.put("discovered", discovered);
    data.put("loaded", loaded);
    data.put("enabled", enabled);
    if (loaded) {
      data.put(
          "lifecycleKind",
          enabled ? "LIFECYCLE_EVENT_KIND_PLUGIN_ENABLED" : "LIFECYCLE_EVENT_KIND_PLUGIN_DISABLED");
    }
    emit(EventType.PLUGIN_STATE, data);
  }

  private void observe(Logger logger) {
    if (observedLoggers.add(logger)) {
      logger.addHandler(exceptionHandler);
    }
  }

  private void emit(EventType type, Map<String, Object> data) {
    sink.emit(ProbeEvent.now(type, data));
  }

  private final class PaperCommandDispatcher implements CommandTestRunner.CommandDispatcher {
    @Override
    public boolean isRegistered(String commandLabel) {
      return Bukkit.getServer().getCommandMap().getCommand(commandLabel) != null;
    }

    @Override
    public boolean dispatch(String command, CommandOutputCapture output) {
      CommandSender sender =
          Bukkit.getServer()
              .createCommandSender(component -> output.append(PLAIN_TEXT.serialize(component)));
      sender.setOp(true);
      return Bukkit.dispatchCommand(sender, command);
    }
  }
}
