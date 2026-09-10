package dev.provenance.probe;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandMap;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;

/** Keep optional Paper APIs out of the probe's class-loading path. */
final class BukkitCompatibility {
  private BukkitCompatibility() {}

  static CommandMap commandMap() {
    try {
      return (CommandMap)
          Bukkit.getServer().getClass().getMethod("getCommandMap").invoke(Bukkit.getServer());
    } catch (ReflectiveOperationException exception) {
      throw new IllegalStateException("server command map is unavailable", exception);
    }
  }

  static CommandSender commandSender(CommandOutputCapture output) {
    // Modern Paper's sender captures Adventure and legacy output correctly.
    // Resolve it lazily: older servers do not provide Adventure at all.
    try {
      Method factory =
          Bukkit.getServer()
              .getClass()
              .getMethod("createCommandSender", java.util.function.Consumer.class);
      Class<?> serializerType =
          Class.forName("net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer");
      Object serializer = serializerType.getMethod("plainText").invoke(null);
      Method serialize =
          serializerType.getMethod(
              "serialize", Class.forName("net.kyori.adventure.text.Component"));
      java.util.function.Consumer<Object> capture =
          component -> {
            try {
              output.append((String) serialize.invoke(serializer, component));
            } catch (ReflectiveOperationException exception) {
              throw new IllegalStateException("could not capture command output", exception);
            }
          };
      return (CommandSender) factory.invoke(Bukkit.getServer(), capture);
    } catch (NoSuchMethodException | ClassNotFoundException unavailable) {
      return legacyCommandSender(Bukkit.getConsoleSender(), output);
    } catch (ReflectiveOperationException exception) {
      throw new IllegalStateException("could not create command sender", exception);
    }
  }

  static ConsoleCommandSender legacyCommandSender(
      ConsoleCommandSender console, CommandOutputCapture output) {
    return (ConsoleCommandSender)
        Proxy.newProxyInstance(
            ConsoleCommandSender.class.getClassLoader(),
            new Class<?>[] {ConsoleCommandSender.class},
            (proxy, method, arguments) -> {
              if (method.getName().equals("sendMessage")
                  || method.getName().equals("sendRawMessage")) {
                for (Object argument : arguments) {
                  if (argument instanceof String) {
                    output.append((String) argument);
                  } else if (argument instanceof String[]) {
                    for (String message : (String[]) argument) output.append(message);
                  }
                }
                return null;
              }
              try {
                return method.invoke(console, arguments);
              } catch (InvocationTargetException exception) {
                throw exception.getCause();
              }
            });
  }
}
