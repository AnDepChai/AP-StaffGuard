package com.anpahn.staffguard.database;

import com.anpahn.staffguard.model.Role;
import com.anpahn.staffguard.model.VerificationState;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import static org.junit.jupiter.api.Assertions.*;

class DatabaseConcurrencyTest {
    @Test void concurrentApprovalHasSingleWinner() throws Exception {
        var dir=Files.createTempDirectory("sg-db");
        Database db=TestDatabaseFactory.create(dir.resolve("test.db").toFile(),name->DatabaseConcurrencyTest.class.getClassLoader().getResourceAsStream(name));
        db.start();
        UUID account=UUID.randomUUID();
        try {
            var created=db.upsertAccount(account,"Alice",Role.STAFF,"12345678901234567",2).join();
            String hash="hash";String token="token";
            var session=db.createVerificationSession(account,created.discordId(),hash,token,System.currentTimeMillis(),System.currentTimeMillis()+60_000,100,System.currentTimeMillis()+300_000).join().orElseThrow();
            var executor=java.util.concurrent.Executors.newFixedThreadPool(2);
            try {
                var a=CompletableFuture.supplyAsync(() -> db.approveSession(session.sessionId(),"a",System.currentTimeMillis(),10).join(), executor);
                var b=CompletableFuture.supplyAsync(() -> db.approveSession(session.sessionId(),"b",System.currentTimeMillis(),10).join(), executor);
                assertTrue(a.join().isPresent() ^ b.join().isPresent());
            } finally { executor.shutdownNow(); }
            assertEquals(VerificationState.APPROVED,db.findSession(session.sessionId()).join().orElseThrow().state());
        } finally { db.close(); }
    }
}
