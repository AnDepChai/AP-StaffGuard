package com.anpahn.staffguard.util;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

public final class IpMatcher {
    private final List<Range> ranges;

    public IpMatcher(List<String> definitions) {
        this.ranges = definitions == null ? List.of() : definitions.stream()
                .filter(s -> s != null && !s.isBlank())
                .map(String::trim)
                .map(Range::parse)
                .toList();
    }

    public boolean isAllowed(InetAddress address) {
        if (address == null) return false;
        for (Range range : ranges) if (range.contains(address)) return true;
        return false;
    }

    private record Range(InetAddress network, int prefix) {
        static Range parse(String value) {
            String[] parts = value.split("/", -1);
            if (parts.length > 2) throw new IllegalArgumentException("Invalid CIDR: " + value);
            InetAddress base = IpAddressUtil.parseLiteral(parts[0]);
            if (base == null) throw new IllegalArgumentException("Invalid proxy address/range: " + value);
            int bits = base.getAddress().length * 8;
            int prefix = parts.length == 1 ? bits : parsePrefix(parts[1], value, bits);
            byte[] masked = mask(base.getAddress(), prefix);
            try {
                base = InetAddress.getByAddress(masked);
            } catch (Exception ex) {
                throw new IllegalArgumentException("Invalid network address: " + value, ex);
            }
            return new Range(base, prefix);
        }

        private static int parsePrefix(String raw, String original, int max) {
            try {
                int prefix = Integer.parseInt(raw);
                if (prefix < 0 || prefix > max) throw new IllegalArgumentException("Invalid CIDR prefix: " + original);
                return prefix;
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid CIDR prefix: " + original, ex);
            }
        }

        boolean contains(InetAddress candidate) {
            byte[] bytes = candidate.getAddress();
            byte[] networkBytes = network.getAddress();
            return bytes.length == networkBytes.length && Arrays.equals(mask(bytes, prefix), networkBytes);
        }

        private static byte[] mask(byte[] input, int prefix) {
            byte[] out = input.clone();
            int fullBytes = prefix / 8;
            int remainder = prefix % 8;
            if (fullBytes < out.length) {
                if (remainder == 0) Arrays.fill(out, fullBytes, out.length, (byte) 0);
                else {
                    int mask = 0xFF << (8 - remainder);
                    out[fullBytes] = (byte) (out[fullBytes] & mask);
                    Arrays.fill(out, fullBytes + 1, out.length, (byte) 0);
                }
            }
            return out;
        }
    }
}
