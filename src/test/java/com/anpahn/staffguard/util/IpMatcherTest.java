package com.anpahn.staffguard.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class IpMatcherTest {
    @Test void ipv4CidrBoundaries(){IpMatcher m=new IpMatcher(java.util.List.of("192.0.2.0/24","198.51.100.7/32"));assertTrue(m.isAllowed(IpAddressUtil.parseLiteral("192.0.2.255")));assertFalse(m.isAllowed(IpAddressUtil.parseLiteral("192.0.3.1")));assertTrue(m.isAllowed(IpAddressUtil.parseLiteral("198.51.100.7")));}
    @Test void ipv6CidrAndZeroPrefix(){IpMatcher m=new IpMatcher(java.util.List.of("2001:db8::/32"));assertTrue(m.isAllowed(IpAddressUtil.parseLiteral("2001:db8::1")));assertFalse(m.isAllowed(IpAddressUtil.parseLiteral("2001:db9::1")));assertTrue(new IpMatcher(java.util.List.of("0.0.0.0/0")).isAllowed(IpAddressUtil.parseLiteral("203.0.113.9")));}
}
