package com.anpahn.staffguard.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public final class IpAddressUtil {
    private IpAddressUtil() {}

    public static InetAddress parseLiteral(String value) {
        String input=normalizeInput(value);if(input==null||input.indexOf('%')>=0)return null;
        if(isIpv4Literal(input))return parseIpv4(input);
        if(!input.contains(":"))return null;
        try{return parseIpv6(input);}catch(IllegalArgumentException ex){return null;}
    }

    public static String normalizeLiteral(String value){InetAddress a=parseLiteral(value);return a==null?null:a.getHostAddress();}
    public static boolean isValidLiteral(String value){return parseLiteral(value)!=null;}
    public static boolean isUsableUnicastLiteral(String value){InetAddress a=parseLiteral(value);return a!=null&&!a.isAnyLocalAddress()&&!a.isMulticastAddress()&&!a.isLoopbackAddress();}

    private static String normalizeInput(String value){
        if(value==null)return null;String s=value.trim();if(s.isEmpty())return null;
        if(s.startsWith("[")&&s.endsWith("]"))s=s.substring(1,s.length()-1).trim();
        if(s.indexOf('[')>=0||s.indexOf(']')>=0||s.indexOf('/')>=0||s.indexOf('%')>=0)return null;return s;
    }

    private static boolean isIpv4Literal(String s){String[] p=s.split("\\.",-1);if(p.length!=4)return false;for(String x:p){if(x.isEmpty()||x.length()>3)return false;if(x.length()>1&&x.charAt(0)=='0')return false;for(int i=0;i<x.length();i++)if(!Character.isDigit(x.charAt(i)))return false;try{if(Integer.parseInt(x)>255)return false;}catch(NumberFormatException e){return false;}}return true;}
    private static InetAddress parseIpv4(String s){String[] p=s.split("\\.",-1);byte[] b=new byte[4];for(int i=0;i<4;i++)b[i]=(byte)Integer.parseInt(p[i]);try{return InetAddress.getByAddress(b);}catch(UnknownHostException e){throw new IllegalStateException(e);}}

    private static InetAddress parseIpv6(String input){
        if(input.chars().filter(c->c==':').count()<2)throw new IllegalArgumentException();
        String[] halves=input.split("::",-1);if(halves.length>2)throw new IllegalArgumentException("multiple ::");
        boolean compressed=halves.length==2;
        List<Integer> left=parseGroups(halves[0]);
        List<Integer> right=compressed?parseGroups(halves[1]):List.of();
        int total=left.size()+right.size();
        if(compressed){if(total>=8)throw new IllegalArgumentException(":: must compress at least one group");}else if(total!=8)throw new IllegalArgumentException("IPv6 must contain 8 groups");
        List<Integer> groups=new ArrayList<>(8);groups.addAll(left);if(compressed)for(int i=total;i<8;i++)groups.add(0);groups.addAll(right);
        if(groups.size()!=8)throw new IllegalArgumentException();
        byte[] out=new byte[16];for(int i=0;i<8;i++){int v=groups.get(i);out[i*2]=(byte)(v>>>8);out[i*2+1]=(byte)v;}
        try{InetAddress address=InetAddress.getByAddress(out);if(address instanceof Inet6Address){byte[] b=address.getAddress();boolean mapped=true;for(int i=0;i<10;i++)mapped&=b[i]==0;mapped&=(b[10]&255)==255&&(b[11]&255)==255;if(mapped)return InetAddress.getByAddress(new byte[]{b[12],b[13],b[14],b[15]});}return address;}catch(UnknownHostException e){throw new IllegalArgumentException(e);}
    }

    private static List<Integer> parseGroups(String text){
        if(text.isEmpty())return List.of();String[] pieces=text.split(":",-1);List<Integer> out=new ArrayList<>();
        for(int i=0;i<pieces.length;i++){
            String part=pieces[i];if(part.isEmpty())throw new IllegalArgumentException("empty IPv6 group");
            if(part.indexOf('.')>=0){if(i!=pieces.length-1||!isIpv4Literal(part))throw new IllegalArgumentException("invalid embedded IPv4");String[] oct=part.split("\\.",-1);out.add((Integer.parseInt(oct[0])<<8)|Integer.parseInt(oct[1]));out.add((Integer.parseInt(oct[2])<<8)|Integer.parseInt(oct[3]));continue;}
            if(part.length()>4)throw new IllegalArgumentException("IPv6 group too long");int value=0;for(int j=0;j<part.length();j++){int d=Character.digit(part.charAt(j),16);if(d<0)throw new IllegalArgumentException("non-hex");value=(value<<4)|d;}out.add(value);
        }
        if(out.size()>8)throw new IllegalArgumentException("too many groups");return out;
    }
}
