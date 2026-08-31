package dev.provenance.fixtures;

import org.bukkit.plugin.java.JavaPlugin;

public final class OnEnableFailurePlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    throw new IllegalStateException("provenance fixture onEnable failure");
  }
}
