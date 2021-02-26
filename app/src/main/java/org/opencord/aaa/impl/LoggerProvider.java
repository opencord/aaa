package org.opencord.aaa.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provide logger for object classes.
 */
public final class LoggerProvider {
    private static Logger stateMachineLogger = LoggerFactory.getLogger("StateMachine.class");

    private LoggerProvider() {
    }

    public static Logger getStateMachineLogger() {
        return stateMachineLogger;
    }
}
