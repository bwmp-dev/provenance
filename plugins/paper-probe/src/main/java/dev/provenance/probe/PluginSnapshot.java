package dev.provenance.probe;

public final class PluginSnapshot {
  private final String name;
  private final boolean loaded;
  private final boolean enabled;

  public PluginSnapshot(String name, boolean loaded, boolean enabled) {

    this.name = name;
    this.loaded = loaded;
    this.enabled = enabled;
  }

  public String name() {
    return name;
  }

  public boolean loaded() {
    return loaded;
  }

  public boolean enabled() {
    return enabled;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof PluginSnapshot)) return false;
    PluginSnapshot that = (PluginSnapshot) other;
    return java.util.Objects.equals(name, that.name)
        && java.util.Objects.equals(loaded, that.loaded)
        && java.util.Objects.equals(enabled, that.enabled);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(name, loaded, enabled);
  }
}
