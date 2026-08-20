package com.anpahn.staffguard.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/** IP-literal parsing that never treats arbitrary user input as a DNS hostname. */
public final class IpAddressUtil {
    private IpAddressUtil() {}

    public static InetAddress parseLiteral(String value) {
        if (value == null) return null;
        String input = value.trim();
        if (input.isEmpty()) return null;

        if (input.startsWith("[") && input.endsWith("]")) {
            input = input.substring(1, input.length() - 1).trim();
        }

        if (isIpv4Literal(input)) return parseIpv4(input);
        if (!input.contains(":")) return null;
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (!(Character.digit(ch, 16) >= 0 || ch == ':' || ch == '.' || ch == '%')) return null;
        }

        // A colon-containing input is only accepted as an IPv6 literal. Java does not perform
        // hostname DNS lookup for a syntactically valid IPv6 literal here; reject any result that
        // is not actually an IPv6 address to keep the method's contract explicit.
        try {
            InetAddress address = InetAddress.getByName(input);
            return address instanceof Inet6Address ? address : null;
        } catch (UnknownHostException ex) {
            return null;
        }
    }

    public static boolean isValidLiteral(String value) {
        return parseLiteral(value) != null;
    }

    private static boolean isIpv4Literal(String input) {
        String[] parts = input.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) return false;
            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) return false;
            }
            try {
                if (Integer.parseInt(part) > 255) return false;
            } catch (NumberFormatException ex) {
                return false;
            }
        }
        return true;
    }

    private static InetAddress parseIpv4(String input) {
        String[] parts = input.split("\\.", -1);
        byte[] address = new byte[4];
        for (int i = 0; i < 4; i++) address[i] = (byte) Integer.parseInt(parts[i]);
        try {
            return InetAddress.getByAddress(address);
        } catch (UnknownHostException impossible) {
            throw new IllegalStateException("JVM rejected a valid IPv4 address", impossible);
        }
    }
}
