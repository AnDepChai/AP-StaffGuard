package com.anpahn.staffguard.util;

import org.junit.jupiter.api.Test;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class SecurityUtilTest {
    @Test void acceptsExactly256BitHexSecret(){
        byte[] secret=SecurityUtil.parseServerSecret("00".repeat(32));
        assertEquals(32,secret.length);
    }
    @Test void rejectsShortSecret(){assertThrows(IllegalArgumentException.class,()->SecurityUtil.parseServerSecret("abcd"));}
    @Test void hmacIsStableAndConstantTimeComparatorWorks(){
        byte[] key=HexFormat.of().parseHex("11".repeat(32));
        String a=SecurityUtil.hmacSha256Hex(key,"ip");
        String b=SecurityUtil.hmacSha256Hex(key,"ip");
        assertEquals(a,b); assertTrue(SecurityUtil.constantTimeEquals(a,b)); assertFalse(SecurityUtil.constantTimeEquals(a,a+"0"));
    }
}
