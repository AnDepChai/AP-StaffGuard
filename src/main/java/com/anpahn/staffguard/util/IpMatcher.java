package com.anpahn.staffguard.util;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

public final class IpMatcher {
    private final List<Range> ranges;

    public IpMatcher(List<String> definitions) {
        this.ranges = definitions.stream().filter(s -> s != null && !s.isBlank()).map(String::trim).map(Range::parse).toList();
    }

    public boolean isAllowed(InetAddress address) {
        if (ranges.isEmpty()) return false;
        byte[] bytes = address.getAddress();
        BigInteger value = new BigInteger(1, bytes);
        for (Range range : ranges) {
            if (range.contains(address, value)) return true;
        }
        return false;
    }

    private record Range(InetAddress network, int prefix) {
        static Range parse(String value) {
            String[] parts = value.split("/", 2);
            InetAddress base = IpAddressUtil.parseLiteral(parts[0].trim());
            if (base == null) throw new IllegalArgumentException("Invalid proxy address/range: " + value);
            int max = base.getAddress().length * 8;
            int prefix;
            try {
                prefix = parts.length == 1 ? max : Integer.parseInt(parts[1]);
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid CIDR prefix: " + value, ex);
            }
            if (prefix < 0 || prefix > max) throw new IllegalArgumentException("Invalid CIDR prefix: " + value);
            return new Range(base, prefix);
        }

        boolean contains(InetAddress candidate, BigInteger candidateValue) {
            if (candidate.getAddress().length != network.getAddress().length) return false;
            if (prefix == network.getAddress().length * 8) return network.equals(candidate);
            int bits = network.getAddress().length * 8;
            BigInteger mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE).xor(BigInteger.ONE.shiftLeft(bits - prefix).subtract(BigInteger.ONE));
            BigInteger networkValue = new BigInteger(1, network.getAddress()).and(mask);
            return candidateValue.and(mask).equals(networkValue);
        }
    }
}
