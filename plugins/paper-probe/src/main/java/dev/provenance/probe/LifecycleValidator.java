package dev.provenance.probe;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class LifecycleValidator {
  public List<RequirementStatus> evaluate(
      String target, Collection<String> dependencies, Collection<PluginSnapshot> plugins) {
    Map<String, PluginSnapshot> byName = new LinkedHashMap<>();
    for (PluginSnapshot plugin : plugins) {
      byName.put(plugin.name().toLowerCase(Locale.ROOT), plugin);
    }

    List<RequirementStatus> statuses = new ArrayList<>();
    if (target == null) {
      statuses.add(new RequirementStatus("TARGET", "", false, false, false));
    } else {
      statuses.add(status("TARGET", target, byName));
    }
    for (String dependency : dependencies) {
      statuses.add(status("REQUIRED_DEPENDENCY", dependency, byName));
    }
    return List.copyOf(statuses);
  }

  private RequirementStatus status(String role, String name, Map<String, PluginSnapshot> plugins) {
    PluginSnapshot plugin = plugins.get(name.toLowerCase(Locale.ROOT));
    return new RequirementStatus(
        role, name, true, plugin != null && plugin.loaded(), plugin != null && plugin.enabled());
  }
}
