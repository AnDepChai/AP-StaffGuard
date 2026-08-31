package com.anpahn.staffguard.security;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.Role;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseBanAuthorizationTest {
    @Test
    void activeManagedBanCannotBeBypassedByPreviouslyTrustedIp() throws Exception {
        var dir = Files.createTempDirectory("sg-ban");
        Database db = new Database(null, dir.resolve("test.db").toFile(),
                name -> DatabaseBanAuthorizationTest.class.getClassLoader().getResourceAsStream(name));
        db.start();
        UUID uuid = UUID.randomUUID();
        try {
            var account = db.upsertAccount(uuid, "Alice", Role.STAFF, "12345678901234567", 2).join();
            assertTrue(db.addTrustedIpHash(uuid, "ip-hash", System.currentTimeMillis(), 10).join());
            assertTrue(db.setBan(uuid, "AP-StaffGuard", System.currentTimeMillis() + 60_000).join());

            assertEquals(Database.TrustedLoginDecision.TEMPORARY_SECURITY_BLOCK,
                    db.authorizeTrustedLogin(uuid, "ip-hash", System.currentTimeMillis()).join());
        } finally {
            db.close();
        }
    }

    @Test
    void expiredManagedBanDoesNotBlockTrustedIp() throws Exception {
        var dir = Files.createTempDirectory("sg-ban-expired");
        Database db = new Database(null, dir.resolve("test.db").toFile(),
                name -> DatabaseBanAuthorizationTest.class.getClassLoader().getResourceAsStream(name));
        db.start();
        UUID uuid = UUID.randomUUID();
        try {
            db.upsertAccount(uuid, "Alice", Role.STAFF, "12345678901234567", 2).join();
            assertTrue(db.addTrustedIpHash(uuid, "ip-hash", System.currentTimeMillis(), 10).join());
            assertTrue(db.setBan(uuid, "AP-StaffGuard", System.currentTimeMillis() - 1).join());

            assertEquals(Database.TrustedLoginDecision.TRUSTED,
                    db.authorizeTrustedLogin(uuid, "ip-hash", System.currentTimeMillis()).join());
        } finally {
            db.close();
        }
    }
}
