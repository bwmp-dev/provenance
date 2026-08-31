package dev.provenance.fixtures;

import org.bukkit.plugin.java.JavaPlugin;

public final class OnLoadFailurePlugin extends JavaPlugin {
  @Override
  public void onLoad() {
    throw new IllegalStateException("provenance fixture onLoad failure");
  }
}
