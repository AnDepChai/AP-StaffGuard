package com.anpahn.staffguard.security;

import java.util.concurrent.atomic.AtomicReference;

public final class SecurityState {
    public enum Status { STARTING, READY, DEGRADED, FAIL_CLOSED, STOPPING }
    private final AtomicReference<Status> status=new AtomicReference<>(Status.STARTING);
    public Status status(){return status.get();}
    public boolean isReady(){return status.get()==Status.READY;}
    public void setReady(boolean value){status.set(value?Status.READY:Status.FAIL_CLOSED);}
    public void set(Status next){status.set(next);}
}
