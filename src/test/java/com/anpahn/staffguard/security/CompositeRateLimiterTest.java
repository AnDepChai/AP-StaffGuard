package com.anpahn.staffguard.security;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class CompositeRateLimiterTest {
    @Test void accountAndIpQuotaAreAtomic(){
        CompositeRateLimiter r=new CompositeRateLimiter(2,1,Duration.ofMinutes(1),100);
        UUID account=UUID.randomUUID();
        var first=r.tryReserve(account,"192.0.2.1"); assertTrue(first.accepted()); first.commit();
        var second=r.tryReserve(account,"192.0.2.2"); assertFalse(second.accepted());
    }
    @Test void concurrentReservationsCannotOverconsume(){
        CompositeRateLimiter r=new CompositeRateLimiter(10,10,Duration.ofMinutes(1),1000);UUID a=UUID.randomUUID();ExecutorService pool=Executors.newFixedThreadPool(8);AtomicInteger accepted=new AtomicInteger();
        try{var tasks=java.util.stream.IntStream.range(0,50).mapToObj(i->pool.submit(()->{var res=r.tryReserve(a,"192.0.2."+(i%5+1));if(res.accepted()){accepted.incrementAndGet();res.commit();}})).toList();for(var f:tasks)f.get();assertEquals(10,accepted.get());}catch(Exception e){throw new AssertionError(e);}finally{pool.shutdownNow();}
    }
}
