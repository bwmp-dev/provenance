package dev.provenance.fixtures;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;

public final class CommandAssertionFailurePlugin extends JavaPlugin {
  @Override
  public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
    sender.sendMessage("PROVENANCE_FIXTURE_ACTUAL_OUTPUT");
    return true;
  }
}
