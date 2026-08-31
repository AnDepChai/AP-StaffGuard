package com.anpahn.staffguard.security;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PomLoggingConfigurationTest {
    @Test
    void pomIncludesSlf4jNopAndDoesNotRelocateSlf4j() throws Exception {
        Path pom = Path.of("pom.xml");
        if (!Files.exists(pom)) return;
        String xml = Files.readString(pom);
        assertTrue(xml.contains("slf4j-nop"));
        assertFalse(xml.contains("<pattern>org.slf4j</pattern>"));
    }
}
