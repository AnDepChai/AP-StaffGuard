package com.anpahn.staffguard.util;
import javax.crypto.Mac; import javax.crypto.spec.SecretKeySpec; import java.nio.charset.StandardCharsets; import java.security.MessageDigest; import java.security.SecureRandom; import java.util.Base64;
public final class SecurityUtil {
    private static final SecureRandom RANDOM = new SecureRandom(); private SecurityUtil() {}
    public static String randomToken(int bytes) { byte[] raw=new byte[bytes]; RANDOM.nextBytes(raw); return Base64.getUrlEncoder().withoutPadding().encodeToString(raw); }
    public static String sha256Hex(String input) { try { return hex(MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8))); } catch(Exception e){ throw new IllegalStateException("SHA-256 unavailable",e); } }
    public static String hmacSha256Hex(String secret,String input){ try{ Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),"HmacSHA256")); return hex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8))); }catch(Exception e){throw new IllegalStateException("HMAC unavailable",e);} }
    public static boolean constantTimeEquals(String a,String b){return a!=null&&b!=null&&MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),b.getBytes(StandardCharsets.UTF_8));}
    public static String maskIp(String ip){
        if(ip==null||ip.isBlank()) return "unknown";
        String value=ip.trim();
        if(value.contains(":")){
            int colons=0;
            for(int i=0;i<value.length();i++){
                if(value.charAt(i)==':' && ++colons==4) return value.substring(0,i+1)+"***";
            }
            return value+"***";
        }
        int last=value.lastIndexOf('.');
        return last>0?value.substring(0,last+1)+"***":"***";
    }
    private static String hex(byte[] b){StringBuilder s=new StringBuilder(b.length*2); for(byte x:b)s.append(String.format("%02x",x)); return s.toString();}
}
