package com.anpahn.staffguard.security;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.AccountStatus;
import com.anpahn.staffguard.model.Role;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseStatusAuthorizationTest {
    @Test
    void lockedAndRevokedAccountsAreNotAuthorizable() throws Exception {
        var dir = Files.createTempDirectory("sg-status");
        Database db = new Database(null, dir.resolve("test.db").toFile(),
                name -> DatabaseStatusAuthorizationTest.class.getClassLoader().getResourceAsStream(name));
        db.start();
        UUID uuid = UUID.randomUUID();
        try {
            db.upsertAccount(uuid, "Alice", Role.STAFF, "12345678901234567", 2).join();
            assertEquals(Database.TrustedLoginDecision.ACCOUNT_NOT_AUTHORIZABLE,
                    db.authorizeTrustedLogin(uuid, "hash", System.currentTimeMillis()).join());

            assertTrue(db.transitionStatus(uuid, AccountStatus.LOCKED).join());
            assertEquals(Database.TrustedLoginDecision.ACCOUNT_NOT_AUTHORIZABLE,
                    db.authorizeTrustedLogin(uuid, "hash", System.currentTimeMillis()).join());

            // A locked account must be explicitly restored to ACTIVE before it can be revoked.
            assertTrue(db.transitionStatus(uuid, AccountStatus.ACTIVE).join());
            assertTrue(db.transitionStatus(uuid, AccountStatus.REVOKED).join());
            assertEquals(Database.TrustedLoginDecision.ACCOUNT_NOT_AUTHORIZABLE,
                    db.authorizeTrustedLogin(uuid, "hash", System.currentTimeMillis()).join());

            assertFalse(db.transitionStatus(uuid, AccountStatus.ACTIVE).join(),
                    "REVOKED is terminal in the current lifecycle and must not silently reactivate");
        } finally {
            db.close();
        }
    }

    @Test
    void statusChangeInvalidatesPreviouslyTrustedGeneration() throws Exception {
        var dir = Files.createTempDirectory("sg-status-generation");
        Database db = new Database(null, dir.resolve("test.db").toFile(),
                name -> DatabaseStatusAuthorizationTest.class.getClassLoader().getResourceAsStream(name));
        db.start();
        UUID uuid = UUID.randomUUID();
        try {
            var account = db.upsertAccount(uuid, "Alice", Role.STAFF, "12345678901234567", 2).join();
            assertTrue(db.addTrustedIpHash(uuid, "hash", System.currentTimeMillis(), 10).join());
            assertTrue(db.transitionStatus(uuid, AccountStatus.LOCKED).join());
            assertEquals(Database.TrustedLoginDecision.ACCOUNT_NOT_AUTHORIZABLE,
                    db.authorizeTrustedLogin(uuid, "hash", System.currentTimeMillis()).join());
            assertNotEquals(account.securityGeneration(),
                    db.findAccount(uuid).join().orElseThrow().securityGeneration());
        } finally {
            db.close();
        }
    }
}
