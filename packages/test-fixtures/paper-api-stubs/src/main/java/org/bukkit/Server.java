package org.bukkit;

import org.bukkit.plugin.PluginManager;

public interface Server {
  String getMinecraftVersion();
  PluginManager getPluginManager();
}
