package com.anpahn.staffguard.database;

import com.anpahn.staffguard.model.*;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import static org.junit.jupiter.api.Assertions.*;

class DatabaseLifecycleTest {
    @Test void resetInvalidatesTrustedAndOldSession(){
        var dir=Files.createTempDirectory("sg-lifecycle");
        Database db=new Database(null,dir.resolve("test.db").toFile(),name->DatabaseLifecycleTest.class.getClassLoader().getResourceAsStream(name));
        db.start();
        var uuid=java.util.UUID.randomUUID();
        try {
            var a=db.upsertAccount(uuid,"Alice",Role.STAFF,"12345678901234567",2).join();
            assertTrue(db.addTrustedIpHash(uuid,"h1",System.currentTimeMillis(),10).join());
            var session=db.createVerificationSession(uuid,a.discordId(),"h2","t",System.currentTimeMillis(),System.currentTimeMillis()+60000,100,System.currentTimeMillis()+300000).join().orElseThrow();
            assertTrue(db.resetSecurity(uuid).join());
            assertFalse(db.authorizeTrustedLogin(uuid,"h1",System.currentTimeMillis()).join());
            assertEquals(VerificationState.EXPIRED,db.findSession(session.sessionId()).join().orElseThrow().state());
            var newer=db.upsertAccount(uuid,"Alice",Role.STAFF,"22345678901234567",2).join();
            assertTrue(newer.securityGeneration()>a.securityGeneration());
            assertFalse(db.authorizeTrustedLogin(uuid,"h1",System.currentTimeMillis()).join());
        } finally { db.close(); }
    }
}
