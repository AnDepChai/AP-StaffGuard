package com.anpahn.staffguard.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

public final class SecurityUtil {
    private static final SecureRandom RANDOM = new SecureRandom();
    private SecurityUtil() {}

    public static String randomToken(int bytes) {
        if (bytes < 16 || bytes > 128) throw new IllegalArgumentException("Token byte length must be 16..128");
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    public static String sha256Hex(String input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static byte[] parseServerSecret(String value) {
        if (value == null || value.isBlank() || !value.equals(value.trim())) {
            throw new IllegalArgumentException("server-secret.value must be non-empty and have no surrounding/embedded whitespace");
        }
        String secret = value.trim();
        byte[] decoded = null;
        if (secret.matches("[0-9a-fA-F]{64}")) {
            decoded = HexFormat.of().parseHex(secret);
        } else {
            try {
                decoded = Base64.getUrlDecoder().decode(secret);
            } catch (IllegalArgumentException ignored) {
                try {
                    decoded = Base64.getDecoder().decode(secret);
                } catch (IllegalArgumentException ignoredAgain) {
                    // handled below
                }
            }
        }
        if (decoded == null || decoded.length != 32) {
            throw new IllegalArgumentException("server-secret.value must encode exactly 256 bits (64 hex chars or base64/base64url for 32 bytes)");
        }
        return decoded;
    }

    public static String hmacSha256Hex(byte[] secret, String input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    public static boolean constantTimeEquals(String a, String b) {
        return a != null && b != null && MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    public static String maskIp(String ip) {
        if (ip == null || ip.isBlank()) return "unknown";
        String value = ip.trim();
        if (value.contains(":")) {
            String[] groups = value.split(":", -1);
            if (groups.length > 1) return value.substring(0, Math.max(1, value.length() / 2)) + "***";
            return "***";
        }
        int last = value.lastIndexOf('.');
        return last > 0 ? value.substring(0, last + 1) + "***" : "***";
    }
}
