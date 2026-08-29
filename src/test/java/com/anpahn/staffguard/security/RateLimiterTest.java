package com.anpahn.staffguard.security;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {
    @Test void usesMonotonicWindowAndIsBounded(){RateLimiter<String> r=new RateLimiter<>(2,Duration.ofMillis(50),2);assertTrue(r.tryAcquire("a"));assertTrue(r.tryAcquire("a"));assertFalse(r.tryAcquire("a"));assertTrue(r.tryAcquire("b"));assertFalse(r.tryAcquire("c"));assertEquals(2,r.size());}
}
