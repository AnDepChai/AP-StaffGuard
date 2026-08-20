package com.anpahn.staffguard.util;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
public final class DurationParser {
    private static final Pattern TOKEN = Pattern.compile("(\\d+)([smhd])", Pattern.CASE_INSENSITIVE);
    private DurationParser() {}
    public static Duration parse(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Duration is empty");
        String compact = value.replaceAll("\\s+", ""); Matcher m = TOKEN.matcher(compact); long seconds = 0; int end = 0;
        while (m.find()) { if (m.start()!=end) throw new IllegalArgumentException("Invalid duration: "+value); long n=Long.parseLong(m.group(1));
            seconds = Math.addExact(seconds, switch(m.group(2).toLowerCase()) { case "s"->n; case "m"->Math.multiplyExact(n,60); case "h"->Math.multiplyExact(n,3600); case "d"->Math.multiplyExact(n,86400); default->0; }); end=m.end(); }
        if (end!=compact.length() || seconds<=0) throw new IllegalArgumentException("Invalid duration: "+value); return Duration.ofSeconds(seconds);
    }
}
