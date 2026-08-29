package com.anpahn.staffguard.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class IpAddressUtilTest {
    @Test void ipv4Canonicalization(){assertEquals("192.0.2.1",IpAddressUtil.normalizeLiteral("192.0.2.1"));assertNull(IpAddressUtil.normalizeLiteral("256.1.1.1"));}
    @Test void ipv6AndMappedIpv4(){assertEquals("2001:db8:0:0:0:0:0:1",IpAddressUtil.normalizeLiteral("2001:db8::1"));assertEquals("192.0.2.1",IpAddressUtil.normalizeLiteral("::ffff:192.0.2.1"));}
    @Test void rejectsNonCanonicalIpv4AndScopeAndHostname(){assertNull(IpAddressUtil.normalizeLiteral("192.168.001.1"));assertNull(IpAddressUtil.parseLiteral("fe80::1%eth0"));assertNull(IpAddressUtil.parseLiteral("example.com"));}
    @Test void rejectsMulticastAndLoopbackForTrust(){assertFalse(IpAddressUtil.isUsableUnicastLiteral("127.0.0.1"));assertFalse(IpAddressUtil.isUsableUnicastLiteral("224.0.0.1"));assertTrue(IpAddressUtil.isUsableUnicastLiteral("192.0.2.1"));}
}
