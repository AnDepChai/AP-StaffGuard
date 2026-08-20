package com.anpahn.staffguard.security;
import java.util.concurrent.atomic.AtomicBoolean;
public final class SecurityState {private final AtomicBoolean ready=new AtomicBoolean(false);public boolean isReady(){return ready.get();}public void setReady(boolean v){ready.set(v);}}
