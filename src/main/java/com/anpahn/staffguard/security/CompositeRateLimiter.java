package com.anpahn.staffguard.security;

import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public final class CompositeRateLimiter {
    public static final class Reservation implements AutoCloseable {
        private final boolean accepted;
        private final Runnable rollbackAction;
        private boolean closed;
        private Reservation(boolean accepted, Runnable rollbackAction) { this.accepted = accepted; this.rollbackAction = rollbackAction; }
        public boolean accepted() { return accepted; }
        public synchronized void rollback() {
            if (!accepted || closed) return;
            closed = true;
            if (rollbackAction != null) rollbackAction.run();
        }
        public synchronized void commit() { closed = true; }
        @Override public void close() { rollback(); }
    }

    private final int accountMax;
    private final int ipMax;
    private final long windowNanos;
    private final int maxKeys;
    private final Map<UUID, Window> accountWindows = new LinkedHashMap<>(16, 0.75f, true);
    private final Map<String, Window> ipWindows = new LinkedHashMap<>(16, 0.75f, true);

    public CompositeRateLimiter(int accountMax, int ipMax, Duration window, int maxKeys) {
        if (accountMax < 1 || ipMax < 1 || window == null || window.isZero() || window.isNegative() || maxKeys < 1) throw new IllegalArgumentException();
        this.accountMax = accountMax;
        this.ipMax = ipMax;
        this.windowNanos = window.toNanos();
        this.maxKeys = maxKeys;
    }

    public synchronized Reservation tryReserve(UUID account, String ip) {
        long now = System.nanoTime();
        cleanup(now);
        Window aw = accountWindows.get(account);
        Window iw = ipWindows.get(ip);
        boolean newAccount = aw == null;
        boolean newIp = iw == null;
        if (newAccount && accountWindows.size() >= maxKeys) return new Reservation(false, null);
        if (newIp && ipWindows.size() >= maxKeys) return new Reservation(false, null);
        if (aw == null) { aw = new Window(now); accountWindows.put(account, aw); }
        if (iw == null) { iw = new Window(now); ipWindows.put(ip, iw); }
        if (now - aw.startNanos >= windowNanos) aw.reset(now);
        if (now - iw.startNanos >= windowNanos) iw.reset(now);
        if (aw.count >= accountMax || iw.count >= ipMax) {
            if (newAccount && aw.count == 0) accountWindows.remove(account);
            if (newIp && iw.count == 0) ipWindows.remove(ip);
            return new Reservation(false, null);
        }
        aw.count++;
        iw.count++;
        return new Reservation(true, () -> rollback(account, ip));
    }

    private synchronized void rollback(UUID account, String ip) {
        Window aw = accountWindows.get(account);
        Window iw = ipWindows.get(ip);
        if (aw != null && aw.count > 0) aw.count--;
        if (iw != null && iw.count > 0) iw.count--;
    }

    public synchronized void cleanup() { cleanup(System.nanoTime()); }

    public synchronized int accountKeyCount() { cleanup(); return accountWindows.size(); }
    public synchronized int ipKeyCount() { cleanup(); return ipWindows.size(); }

    private void cleanup(long now) {
        removeExpired(accountWindows, now);
        removeExpired(ipWindows, now);
    }

    private void removeExpired(Map<?, Window> map, long now) {
        Iterator<? extends Map.Entry<?, Window>> it = map.entrySet().iterator();
        while (it.hasNext()) if (now - it.next().getValue().startNanos >= windowNanos) it.remove();
    }

    private static final class Window {
        long startNanos;
        int count;
        Window(long startNanos) { this.startNanos = startNanos; }
        void reset(long now) { startNanos = now; count = 0; }
    }
}
