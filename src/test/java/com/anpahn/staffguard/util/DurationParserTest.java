package com.anpahn.staffguard.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DurationParserTest {
    @Test void parsesCompoundDuration(){ assertEquals(3723, DurationParser.parse("1h 2m 3s").toSeconds()); }
    @Test void rejectsInvalidAndOverflow(){ assertThrows(IllegalArgumentException.class, () -> DurationParser.parse("0s")); assertThrows(IllegalArgumentException.class, () -> DurationParser.parse("5x")); assertThrows(IllegalArgumentException.class, () -> DurationParser.parse("999999999999999999999d")); }
}
