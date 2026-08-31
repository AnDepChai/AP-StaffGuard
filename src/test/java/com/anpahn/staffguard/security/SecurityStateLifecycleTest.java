package com.anpahn.staffguard.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecurityStateLifecycleTest {
    @Test
    void stoppingStateIsNeverOperational() {
        SecurityState state = new SecurityState();
        state.set(SecurityState.Status.READY);
        assertTrue(state.isOperational());
        state.set(SecurityState.Status.STOPPING);
        assertFalse(state.isOperational());
        assertTrue(state.isStopping());
    }

    @Test
    void compareAndSetTransitionIsStrict() {
        SecurityState state = new SecurityState();
        assertTrue(state.transition(SecurityState.Status.STARTING, SecurityState.Status.READY));
        assertFalse(state.transition(SecurityState.Status.STARTING, SecurityState.Status.FAIL_CLOSED));
        assertEquals(SecurityState.Status.READY, state.status());
    }
}
