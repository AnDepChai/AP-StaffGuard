package com.anpahn.staffguard.util;

import com.anpahn.staffguard.config.StaffGuardConfig;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class AuditCommandSanitizerTest {
    private static StaffGuardConfig cfg(boolean redact){
        return new StaffGuardConfig(true,Duration.ofMinutes(5),Duration.ofMinutes(2),10,3,5,100,30,2,32,3,Duration.ofSeconds(30),30,true,false,"","",List.of(),List.of(),true,false,"staffguard.db","server","11".repeat(32),com.anpahn.staffguard.model.ProxyMode.NONE,List.of(),"ip","lock","unavailable",new StaffGuardConfig.PrivacyConfig(true,true,true,true),new StaffGuardConfig.VerificationEmbedConfig("t",1,"d","m","r","i","v","e","s","f","a","d"),new StaffGuardConfig.CommandAuditConfig(true,"12345678901234567",true,true,true,List.of("op","bukkit:ban"),redact),new StaffGuardConfig.CommandAuditEmbedConfig("t",1,2,"d","c","s","p","sv","ch","f"));
    }
    @Test void normalizesNamespacedCommands(){ assertTrue(AuditCommandSanitizer.isDangerous("/minecraft:op Alice",List.of("op"))); assertTrue(AuditCommandSanitizer.isDangerous("/bukkit:ban Alice",List.of("ban"))); }
    @Test void redactsSensitiveArgumentsBeforeBoundedOutput(){ String s=AuditCommandSanitizer.sanitize("/execute token=abc password=secret --api-key xyz Bearer topsecret",cfg(true)); assertFalse(s.contains("abc")); assertFalse(s.contains("secret")); assertFalse(s.contains("xyz")); assertFalse(s.contains("topsecret")); }
}
