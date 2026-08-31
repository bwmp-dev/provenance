package dev.provenance.fixtures;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;

public final class CommandSuccessPlugin extends JavaPlugin {
  @Override
  public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
    sender.sendMessage("PROVENANCE_FIXTURE_COMMAND_OK");
    return true;
  }
}
