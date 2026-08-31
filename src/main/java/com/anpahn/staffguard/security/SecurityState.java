package com.anpahn.staffguard.security;

import java.util.concurrent.atomic.AtomicReference;

public final class SecurityState {
    public enum Status { STARTING, READY, DEGRADED, FAIL_CLOSED, STOPPING }
    private final AtomicReference<Status> status=new AtomicReference<>(Status.STARTING);
    public Status status(){return status.get();}
    public boolean isReady(){return status.get()==Status.READY;}
    /**
     * READY means startup is healthy. DEGRADED means background maintenance had a
     * transient failure, but the actual DB-backed authentication path is still
     * allowed to run and will fail closed if the operation itself fails.
     */
    public boolean isOperational(){
        Status current=status.get();
        return current==Status.READY || current==Status.DEGRADED;
    }
    public void setReady(boolean value){status.set(value?Status.READY:Status.FAIL_CLOSED);}
    public boolean transition(Status expectedCurrent, Status next){
        return status.compareAndSet(expectedCurrent, next);
    }

    public boolean isStopping(){
        Status current = status.get();
        return current == Status.STOPPING;
    }

    public void set(Status next){status.set(next);}
}
