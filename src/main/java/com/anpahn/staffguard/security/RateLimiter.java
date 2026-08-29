package com.anpahn.staffguard.security;

import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class RateLimiter<K> {
    private final int max;
    private final long windowNanos;
    private final int maxKeys;
    private final Map<K, Window> map = new LinkedHashMap<>(16, 0.75f, true);

    public RateLimiter(int max, Duration window) {
        this(max, window, 4096);
    }

    public RateLimiter(int max, Duration window, int maxKeys) {
        if (max < 1 || window == null || window.isZero() || window.isNegative() || maxKeys < 1) throw new IllegalArgumentException();
        this.max = max;
        this.windowNanos = window.toNanos();
        this.maxKeys = maxKeys;
    }

    public synchronized boolean tryAcquire(K key) {
        Objects.requireNonNull(key, "key");
        long now = System.nanoTime();
        evictExpired(now);
        Window w = map.get(key);
        if (w == null) {
            if (map.size() >= maxKeys) return false;
            w = new Window(now, 0);
            map.put(key, w);
        }
        if (now - w.startNanos >= windowNanos) {
            w = new Window(now, 0);
            map.put(key, w);
        }
        if (w.count >= max) return false;
        w.count++;
        return true;
    }

    public synchronized void cleanup() {
        evictExpired(System.nanoTime());
    }

    public synchronized int size() {
        evictExpired(System.nanoTime());
        return map.size();
    }

    private void evictExpired(long now) {
        Iterator<Map.Entry<K, Window>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (now - it.next().getValue().startNanos >= windowNanos) it.remove();
        }
    }

    private static final class Window {
        final long startNanos;
        int count;
        Window(long startNanos, int count) { this.startNanos = startNanos; this.count = count; }
    }
}
