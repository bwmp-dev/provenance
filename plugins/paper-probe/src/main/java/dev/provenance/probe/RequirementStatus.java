package dev.provenance.probe;

public final class RequirementStatus {
  private final String role;
  private final String name;
  private final boolean configured;
  private final boolean loaded;
  private final boolean enabled;

  public RequirementStatus(
      String role, String name, boolean configured, boolean loaded, boolean enabled) {

    this.role = role;
    this.name = name;
    this.configured = configured;
    this.loaded = loaded;
    this.enabled = enabled;
  }

  public String role() {
    return role;
  }

  public String name() {
    return name;
  }

  public boolean configured() {
    return configured;
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
    if (!(other instanceof RequirementStatus)) return false;
    RequirementStatus that = (RequirementStatus) other;
    return java.util.Objects.equals(role, that.role)
        && java.util.Objects.equals(name, that.name)
        && java.util.Objects.equals(configured, that.configured)
        && java.util.Objects.equals(loaded, that.loaded)
        && java.util.Objects.equals(enabled, that.enabled);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(role, name, configured, loaded, enabled);
  }
}
