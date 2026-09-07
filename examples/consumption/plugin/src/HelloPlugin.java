package example;

import org.bukkit.plugin.java.JavaPlugin;

/** Benign lifecycle-only example: no network, file, process or credential access. */
public final class HelloPlugin extends JavaPlugin {
    @Override
    public void onEnable() {
        getLogger().info("Provenance example enabled");
    }
}
