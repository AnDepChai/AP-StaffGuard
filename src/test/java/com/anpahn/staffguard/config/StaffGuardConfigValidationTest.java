package com.anpahn.staffguard.config;

import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StaffGuardConfigValidationTest {
    @Test
    void invalidSecuritySecretExplainsExactlyWhatIsMissing() {
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.set("security.enabled", true);
        yaml.set("server-secret.value", "");
        yaml.set("database.file", "staffguard.db");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> StaffGuardConfig.from(yaml));
        assertTrue(ex.getMessage().contains("server-secret.value"));
        assertTrue(ex.getMessage().contains("256-bit"));
        assertTrue(ex.getMessage().contains("config.yml"));
    }

    @Test
    void discordConfigurationIsValidatedAsAGroup() {
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.set("security.enabled", true);
        yaml.set("server-secret.value", "00".repeat(32));
        yaml.set("database.file", "staffguard.db");
        yaml.set("discord.enabled", true);
        yaml.set("discord.bot-token", "");
        yaml.set("discord.channel-id", "");
        yaml.set("discord.owner-user-ids", java.util.List.of());
        yaml.set("discord.staff-user-ids", java.util.List.of());
        yaml.set("discord.allow-self-approval", false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> StaffGuardConfig.from(yaml));
        assertTrue(ex.getMessage().contains("discord.bot-token"));
        assertTrue(ex.getMessage().contains("discord.channel-id"));
        assertTrue(ex.getMessage().contains("owner-user-ids/staff-user-ids"));
    }

    @Test
    void databasePathCannotEscapePluginDataDirectory() {
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.set("security.enabled", true);
        yaml.set("server-secret.value", "00".repeat(32));
        yaml.set("database.file", "../outside.db");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> StaffGuardConfig.from(yaml));
        assertTrue(ex.getMessage().contains("database.file"));
    }
}
