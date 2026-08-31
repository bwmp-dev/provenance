package org.bukkit.plugin.java;

import java.io.File;
import java.util.logging.Logger;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;

public abstract class JavaPlugin {
  public void onLoad() {}

  public void onEnable() {}

  public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
    return false;
  }

  public final Logger getLogger() {
    return Logger.getLogger(getClass().getName());
  }

  public final File getDataFolder() {
    return new File("plugins", getClass().getSimpleName());
  }
}
