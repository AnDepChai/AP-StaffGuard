package com.anpahn.staffguard.util;

import com.anpahn.staffguard.config.StaffGuardConfig;

import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AuditCommandSanitizer {
    private static final Pattern IP=Pattern.compile("(?<![\\w.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\w.])|(?<![\\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]{1,4}(?![\\w:])");
    private static final Pattern SENSITIVE_ASSIGN=Pattern.compile("(?i)\\b(password|passwd|token|secret|apikey|api-key|authorization|cookie)\\s*=\\s*[^\\s]+(?=$|\\s)");
    private static final Pattern SENSITIVE_FLAG = Pattern.compile("(?i)(--(?:password|passwd|token|secret|apikey|api-key|authorization|cookie))\\s+(?:\"[^\"]*\"|'[^']*'|[^\\s]+)");
    private static final Pattern SENSITIVE_COLON = Pattern.compile("(?i)[\"\']?(password|passwd|token|secret|apikey|api-key|authorization|cookie)[\"\']?\\s*[:=]\\s*(?:[\"\'][^\"\']*[\"\']|[^\\s,}]+)");
    private static final Pattern BEARER=Pattern.compile("(?i)\\bBearer\\s+[^\\s]+");
    private static final Pattern COORD=Pattern.compile("(?<![\\w.-])-?\\d+(?:\\.\\d+)?(?![\\w.-])");

    private AuditCommandSanitizer(){}

    public static String normalizeCommandName(String input){
        String v=input==null?"":input.trim();if(v.startsWith("/"))v=v.substring(1).trim();if(v.isEmpty())return "";
        String token=v.split("\\s+",2)[0].toLowerCase(Locale.ROOT);
        int colon=token.lastIndexOf(':');return colon>=0?token.substring(colon+1):token;
    }

    public static String sanitize(String input,StaffGuardConfig cfg){
        String value=input==null?"":input.trim();String base=value.startsWith("/")?value:"/"+value;
        if(cfg.commandAudit().redactSensitiveArguments()){
            base=SENSITIVE_ASSIGN.matcher(base).replaceAll(m->m.group(1)+"=<redacted>");
            base=SENSITIVE_FLAG.matcher(base).replaceAll("$1 <redacted>");
            base=SENSITIVE_COLON.matcher(base).replaceAll(m->m.group(1)+":<redacted>");
            base=BEARER.matcher(base).replaceAll("Bearer <redacted>");
        }
        if(cfg.privacy().redactIpInCommandAudit())base=IP.matcher(base).replaceAll("<ip-redacted>");
        if(cfg.privacy().redactCoordinatesInCommandAudit()&&isCoordinateCommand(base))base=redactCoordinates(base);
        return bound(base,1800);
    }

    public static boolean isDangerous(String command,List<String> dangerous){
        String name=normalizeCommandName(command);if(name.isEmpty())return false;
        for(String configured:dangerous){if(configured==null||configured.isBlank())continue;if(name.equals(normalizeCommandName(configured)))return true;}
        return false;
    }

    private static boolean isCoordinateCommand(String value){String c=normalizeCommandName(value);return switch(c){case "tp","teleport","spreadplayers","setworldspawn","spawnpoint","summon","particle","execute","locate"->true;default->false;};}
    private static String redactCoordinates(String value){Matcher m=COORD.matcher(value);StringBuffer out=new StringBuffer();while(m.find())m.appendReplacement(out,"<coordinates-redacted>");m.appendTail(out);return out.toString();}
    private static String bound(String v,int max){return v.length()>max?v.substring(0,max-3)+"...":v;}
}
