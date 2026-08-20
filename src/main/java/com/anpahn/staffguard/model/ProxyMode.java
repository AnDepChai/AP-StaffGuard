package com.anpahn.staffguard.model;

public enum ProxyMode {
    NONE,
    VELOCITY,
    BUNGEECORD;

    public static ProxyMode parse(String value) {
        if (value == null || value.isBlank()) return NONE;
        try {
            return valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("proxy.mode must be NONE, VELOCITY, or BUNGEECORD");
        }
    }
}
