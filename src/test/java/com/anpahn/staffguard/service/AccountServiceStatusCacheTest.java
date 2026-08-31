package com.anpahn.staffguard.service;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.database.TestDatabaseFactory;
import com.anpahn.staffguard.model.AccountStatus;
import com.anpahn.staffguard.model.Role;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AccountServiceStatusCacheTest {
    @Test
    void lockedAndRevokedAccountsRemainVisibleToLoginGate() throws Exception {
        var dir = Files.createTempDirectory("sg-account-status");
        Database db = TestDatabaseFactory.create(dir.resolve("test.db").toFile(), name -> AccountServiceStatusCacheTest.class.getClassLoader().getResourceAsStream(name));
        db.start();
        UUID uuid = UUID.randomUUID();
        try {
            db.upsertAccount(uuid, "Alice", Role.STAFF, "12345678901234567", 2).join();
            AccountService accounts = new AccountService(db);
            accounts.load().join();
            assertEquals(AccountStatus.ACTIVE, accounts.getCached(uuid).status());

            assertTrue(accounts.setStatus(uuid, AccountStatus.LOCKED).join());
            assertEquals(AccountStatus.LOCKED, accounts.getCached(uuid).status());

            assertTrue(db.transitionStatus(uuid, AccountStatus.ACTIVE).join());
            assertTrue(accounts.refresh(uuid).join() == null);
            assertTrue(accounts.setStatus(uuid, AccountStatus.REVOKED).join());
            assertEquals(AccountStatus.REVOKED, accounts.getCached(uuid).status());
        } finally {
            db.close();
        }
    }
}
