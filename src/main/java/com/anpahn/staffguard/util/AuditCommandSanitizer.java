package com.anpahn.staffguard.util;

import com.anpahn.staffguard.config.StaffGuardConfig;

import java.util.List;
import java.util.Set;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AuditCommandSanitizer {
    private static final Pattern IP = Pattern.compile("(?<![0-9A-Fa-f:])(?:\\d{1,3}\\.){3}\\d{1,3}(?![0-9A-Fa-f:])|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])");
    private static final Pattern COORDINATES = Pattern.compile("(?<![A-Za-z0-9_.-])-?\\d+(?:\\.\\d+)?[ ]+(-?\\d+(?:\\.\\d+)?)[ ]+(-?\\d+(?:\\.\\d+)?)");
    private static final List<String> SENSITIVE = List.of("password", "passwd", "token", "secret", "apikey", "api-key", "login", "auth");
    private static final Set<String> COORDINATE_COMMANDS = Set.of("tp", "teleport", "spreadplayers", "setworldspawn", "spawnpoint", "summon", "particle", "execute");

    private AuditCommandSanitizer() { }

    public static String sanitize(String input, StaffGuardConfig cfg) {
        String value = input == null ? "" : input.trim();
        String base = value.startsWith("/") ? value : "/" + value;
        String[] parts = base.substring(1).split("\\s+");
        if (parts.length > 1 && cfg.commandAudit().redactSensitiveArguments()) {
            String command = parts[0].toLowerCase(Locale.ROOT);
            if (SENSITIVE.contains(command)) return "/" + parts[0] + " <redacted>";
            for (String s : SENSITIVE) {
                if (command.contains(s)) return "/" + parts[0] + " <redacted>";
            }
        }
        if (cfg.privacy().redactIpInCommandAudit()) base = IP.matcher(base).replaceAll("<ip-redacted>");
        if (cfg.privacy().redactCoordinatesInCommandAudit() && isCoordinateCommand(base)) base = redactCoordinates(base);
        return base;
    }

    private static boolean isCoordinateCommand(String value) {
        String normalized = value.startsWith("/") ? value.substring(1) : value;
        String command = normalized.split("\\s+", 2)[0].toLowerCase(Locale.ROOT);
        return COORDINATE_COMMANDS.contains(command);
    }

    private static String redactCoordinates(String value) {
        Matcher m = COORDINATES.matcher(value);
        StringBuffer out = new StringBuffer();
        while (m.find()) m.appendReplacement(out, "<coordinates-redacted>");
        m.appendTail(out);
        return out.toString();
    }

    public static boolean isDangerous(String command, List<String> dangerous) {
        String normalized = command == null ? "" : command.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("/")) normalized = normalized.substring(1);
        String name = normalized.split("\\s+", 2)[0];
        for (String pattern : dangerous) {
            if (pattern == null || pattern.isBlank()) continue;
            String p = pattern.trim().toLowerCase(Locale.ROOT);
            if (p.startsWith("/")) p = p.substring(1);
            if (name.equals(p)) return true;
        }
        return false;
    }
}
