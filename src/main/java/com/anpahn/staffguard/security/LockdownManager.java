package com.anpahn.staffguard.security;
import java.util.concurrent.atomic.AtomicBoolean;
public final class LockdownManager {private final AtomicBoolean enabled=new AtomicBoolean();public boolean isEnabled(){return enabled.get();}public boolean enable(){return enabled.compareAndSet(false,true);}public boolean disable(){return enabled.compareAndSet(true,false);}}
