/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opencord.aaa.impl;

import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.opencord.aaa.AuthenticationEvent;
import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.StateMachineDelegate;
import org.slf4j.Logger;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * AAA Finite State Machine.
 */
public class StateMachine {
    //INDEX to identify the state in the transition table
    static final int STATE_IDLE = 0;
    static final int STATE_STARTED = 1;
    static final int STATE_PENDING = 2;
    static final int STATE_AUTHORIZED = 3;
    static final int STATE_UNAUTHORIZED = 4;

    // Defining the states where timeout can happen
    static final Set<Integer> TIMEOUT_ELIGIBLE_STATES = new HashSet<>();
    static {
        TIMEOUT_ELIGIBLE_STATES.add(STATE_STARTED);
        TIMEOUT_ELIGIBLE_STATES.add(STATE_PENDING);
    }
    // INDEX to identify the transition in the transition table
    static final int TRANSITION_START = 0; // --> started
    static final int TRANSITION_REQUEST_ACCESS = 1;
    static final int TRANSITION_AUTHORIZE_ACCESS = 2;
    static final int TRANSITION_DENY_ACCESS = 3;
    static final int TRANSITION_LOGOFF = 4;

    private static int identifier = -1;
    private byte challengeIdentifier;
    private byte[] challengeState;
    private byte[] username;
    private byte[] requestAuthenticator;

    // Supplicant connectivity info
    private ConnectPoint supplicantConnectpoint;
    private MacAddress supplicantAddress;
    private short vlanId;
    private byte priorityCode;
    private long sessionStartTime;
    private String eapolTypeVal;

    public enum EapolType {
        EAPOL_PACKET("EAPOL_PACKET"),
        EAPOL_START("EAPOL_START"),
        EAPOL_LOGOFF("EAPOL_LOGOFF"),
        EAPOL_KEY("EAPOL_KEY"),
        EAPOL_ASF("EAPOL_ASF");

        private final String eaptype;

        private EapolType(String value) {
            this.eaptype = value;
        }
    };

    private String sessionTerminateReason;

    public enum SessionTerminationReasons {
        SUPPLICANT_LOGOFF("SUPPLICANT_LOGOFF"),
        TIME_OUT("TIME_OUT"),
        PORT_REMOVED("PORT_REMOVED"),
        DEVICE_REMOVED("DEVICE_REMOVED");

        private final String reason;

        private SessionTerminationReasons(String value) {
            this.reason = value;
        }

        public String getReason() {
            return this.reason;
        }
    };

    // Supplicant packet count
    private int totalPacketsSent;
    private int totalPacketsReceived;
    private int totalOctetSent;
    private int totalOctetReceived;

    // Boolean flag indicating whether response is pending from AAA Server.
    // Used for counting timeout happening for AAA Sessions due to no response.
    private boolean waitingForRadiusResponse;

    private static int cleanupTimerTimeOutInMins;

    private String sessionId = null;

    private final Logger log = getLogger(getClass());

    private State[] states = {new Idle(), new Started(), new Pending(), new Authorized(), new Unauthorized() };

    // Cleanup Timer instance created for this session
    private ScheduledExecutorService executor;
    private java.util.concurrent.ScheduledFuture<?> cleanupTimer = null;

    // TimeStamp of last EAPOL or RADIUS message received.
    private long lastPacketReceivedTime = 0;

    // State transition table
    /*
     *
     * state IDLE | STARTED | PENDING | AUTHORIZED | UNAUTHORIZED //// input
     * -----------------------------------------------------------------------------
     * -----------------------
     *
     * START STARTED | _ | _ | STARTED | STARTED
     *
     * REQUEST_ACCESS _ | PENDING | _ | _ | _
     *
     * AUTHORIZE_ACCESS _ | _ | AUTHORIZED | _ | _
     *
     * DENY_ACCESS _ | - | UNAUTHORIZED | _ | _
     *
     * LOGOFF _ | _ | _ | IDLE | IDLE
     */

    private int[] idleTransition = {STATE_STARTED, STATE_IDLE, STATE_IDLE, STATE_IDLE, STATE_IDLE };
    private int[] startedTransition = {STATE_STARTED, STATE_PENDING, STATE_STARTED, STATE_STARTED, STATE_STARTED };
    private int[] pendingTransition = {STATE_PENDING, STATE_PENDING, STATE_AUTHORIZED, STATE_UNAUTHORIZED,
            STATE_PENDING };
    private int[] authorizedTransition = {STATE_STARTED, STATE_AUTHORIZED, STATE_AUTHORIZED, STATE_AUTHORIZED,
            STATE_IDLE };
    private int[] unauthorizedTransition = {STATE_STARTED, STATE_UNAUTHORIZED, STATE_UNAUTHORIZED, STATE_UNAUTHORIZED,
            STATE_IDLE };

    // THE TRANSITION TABLE
    private int[][] transition = {idleTransition, startedTransition, pendingTransition, authorizedTransition,
            unauthorizedTransition };

    private int currentState = STATE_IDLE;

    private static StateMachineDelegate delegate;

    public static void setDelegate(StateMachineDelegate delegate) {
        StateMachine.delegate = delegate;
    }

    public static void setcleanupTimerTimeOutInMins(int cleanupTimerTimeoutInMins) {
        cleanupTimerTimeOutInMins = cleanupTimerTimeoutInMins;
    }

    private void scheduleTimeout() {
        cleanupTimer = executor.schedule(this::timeout, cleanupTimerTimeOutInMins, TimeUnit.MINUTES);
    }

    public static void unsetDelegate(StateMachineDelegate delegate) {
        if (StateMachine.delegate == delegate) {
            StateMachine.delegate = null;
        }
    }

    public static void deleteStateMachineMapping(StateMachine machine) {
        if (machine.cleanupTimer != null) {
            machine.cleanupTimer.cancel(false);
            machine.cleanupTimer = null;
        }
    }

    public void stop() {
        if (cleanupTimer != null) {
            cleanupTimer.cancel(false);
        }
    }

    public boolean isWaitingForRadiusResponse() {
        return waitingForRadiusResponse;
    }

    public void setWaitingForRadiusResponse(boolean waitingForRadiusResponse) {
        this.waitingForRadiusResponse = waitingForRadiusResponse;
    }

    /**
     * Creates a new StateMachine with the given session ID.
     *
     * @param sessionId session Id represented by the switch dpid + port number
     * @param executor executor to run background tasks on
     */
    public StateMachine(String sessionId, ScheduledExecutorService executor) {
        log.info("Creating a new state machine for {}", sessionId);
        this.sessionId = sessionId;
        this.executor = executor;
    }

    /**
     * Gets the connect point for the supplicant side.
     *
     * @return supplicant connect point
     */
    public ConnectPoint supplicantConnectpoint() {
        return supplicantConnectpoint;
    }

    /**
     * Sets the supplicant side connect point.
     *
     * @param supplicantConnectpoint supplicant select point.
     */
    public void setSupplicantConnectpoint(ConnectPoint supplicantConnectpoint) {
        this.supplicantConnectpoint = supplicantConnectpoint;
    }

    /**
     * Gets the MAC address of the supplicant.
     *
     * @return supplicant MAC address
     */
    public MacAddress supplicantAddress() {
        return supplicantAddress;
    }

    /**
     * Sets the supplicant MAC address.
     *
     * @param supplicantAddress new supplicant MAC address
     */
    public void setSupplicantAddress(MacAddress supplicantAddress) {
        this.supplicantAddress = supplicantAddress;
    }

    /**
     * Sets the lastPacketReceivedTime.
     *
     * @param lastPacketReceivedTime timelastPacket was received
     */
    public void setLastPacketReceivedTime(long lastPacketReceivedTime) {
        this.lastPacketReceivedTime = lastPacketReceivedTime;
    }

    /**
     * Gets the lastPacketReceivedTime.
     *
     * @return lastPacketReceivedTime
     */
    public long getLastPacketReceivedTime() {
        return lastPacketReceivedTime;
    }

    /**
     * Gets the client's Vlan ID.
     *
     * @return client vlan ID
     */
    public short vlanId() {
        return vlanId;
    }

    /**
     * Sets the client's vlan ID.
     *
     * @param vlanId new client vlan ID
     */
    public void setVlanId(short vlanId) {
        this.vlanId = vlanId;
    }

    /**
     * Gets the client's priority Code.
     *
     * @return client Priority code
     */
    public byte priorityCode() {
        return priorityCode;
    }

    /**
     * Sets the client's priority Code.
     *
     * @param priorityCode new client priority Code
     */
    public void setPriorityCode(byte priorityCode) {
        this.priorityCode = priorityCode;
    }

    /**
     * Gets the session start time.
     *
     * @return session start time
     */
    public long sessionStartTime() {
        return sessionStartTime;
    }

    /**
     * Sets the session start time.
     *
     * @param sessionStartTime new session start time
     */
    public void setSessionStartTime(long sessionStartTime) {
        this.sessionStartTime = sessionStartTime;
    }

    /**
     * returns eapol Type.
     *
     * @return eapolTypeVal.
     */
    public String eapolType() {
        return this.eapolTypeVal;
    }

    /**
     * Sets eapol Type name from eapol value.
     *
     * @param value eapol type as byte.
     */
    public void setEapolTypeVal(byte value) {
        switch (value) {
            case (byte) 0: this.eapolTypeVal = EapolType.EAPOL_PACKET.eaptype;
                break;
            case (byte) 1: this.eapolTypeVal = EapolType.EAPOL_START.eaptype;
                break;
            case (byte) 2: this.eapolTypeVal = EapolType.EAPOL_LOGOFF.eaptype;
                break;
            case (byte) 3: this.eapolTypeVal = EapolType.EAPOL_KEY.eaptype;
                break;
            case (byte) 4: this.eapolTypeVal = EapolType.EAPOL_ASF.eaptype;
                break;
            default : this.eapolTypeVal = "INVALID TYPE";
        }
    }

    public String getSessionTerminateReason() {
        return sessionTerminateReason;
    }

    public void setSessionTerminateReason(String sessionTerminateReason) {
        this.sessionTerminateReason = sessionTerminateReason;
    }

    public int totalPacketsReceived() {
        return this.totalPacketsReceived;
    }

    public void incrementTotalPacketsReceived() {
        this.totalPacketsReceived = this.totalPacketsReceived + 1;
    }

    public int totalPacketsSent() {
        return this.totalPacketsSent;
    }

    public void incrementTotalPacketsSent() {
        this.totalPacketsSent = this.totalPacketsSent + 1;
    }

    public void incrementTotalOctetReceived(short packetLen) {
        this.totalOctetReceived = this.totalOctetReceived + packetLen;
    }

    public void incrementTotalOctetSent(short packetLen) {
        this.totalOctetSent = this.totalOctetSent + packetLen;
    }

    /**
     * Gets the client id that is requesting for access.
     *
     * @return The client id.
     */
    public String sessionId() {
        return this.sessionId;
    }

    /**
     * Set the challenge identifier and the state issued by the RADIUS.
     *
     * @param challengeIdentifier The challenge identifier set into the EAP packet
     *                            from the RADIUS message.
     * @param challengeState      The challenge state from the RADIUS.
     */
    protected void setChallengeInfo(byte challengeIdentifier, byte[] challengeState) {
        this.challengeIdentifier = challengeIdentifier;
        this.challengeState = challengeState;
    }

    /**
     * Set the challenge identifier issued by the RADIUS on the access challenge
     * request.
     *
     * @param challengeIdentifier The challenge identifier set into the EAP packet
     *                            from the RADIUS message.
     */
    protected void setChallengeIdentifier(byte challengeIdentifier) {
        log.info("Set Challenge Identifier to {}", challengeIdentifier);
        this.challengeIdentifier = challengeIdentifier;
    }

    /**
     * Gets the challenge EAP identifier set by the RADIUS.
     *
     * @return The challenge EAP identifier.
     */
    protected byte challengeIdentifier() {
        return this.challengeIdentifier;
    }

    /**
     * Set the challenge state info issued by the RADIUS.
     *
     * @param challengeState The challenge state from the RADIUS.
     */
    protected void setChallengeState(byte[] challengeState) {
        log.info("Set Challenge State");
        this.challengeState = challengeState;
    }

    /**
     * Gets the challenge state set by the RADIUS.
     *
     * @return The challenge state.
     */
    protected byte[] challengeState() {
        return this.challengeState;
    }

    /**
     * Set the username.
     *
     * @param username The username sent to the RADIUS upon access request.
     */
    protected void setUsername(byte[] username) {
        this.username = username;
    }

    /**
     * Gets the username.
     *
     * @return The requestAuthenticator.
     */
    protected byte[] requestAuthenticator() {
        return this.requestAuthenticator;
    }

    /**
     * Sets the authenticator.
     *
     * @param authenticator The username sent to the RADIUS upon access request.
     */
    protected void setRequestAuthenticator(byte[] authenticator) {
        this.requestAuthenticator = authenticator;
    }

    /**
     * Gets the username.
     *
     * @return The username.
     */
    public byte[] username() {
        return this.username;
    }

    /**
     * Return the identifier of the state machine.
     *
     * @return The state machine identifier.
     */
    public synchronized byte identifier() {
        identifier = (identifier + 1) % 255;
        return (byte) identifier;
    }

    /**
     * Move to the next state.
     *
     * @param msg message
     */
    private void next(int msg) {
        currentState = transition[currentState][msg];
        log.info("Current State " + currentState);
    }

    /**
     * Client has requested the start action to allow network access.
     */
    public void start() {
        this.scheduleTimeout();

        states[currentState].start();

        delegate.notify(new AuthenticationEvent(AuthenticationEvent.Type.STARTED,
                supplicantConnectpoint, toAuthRecord()));

        // move to the next state
        next(TRANSITION_START);
    }

    /**
     * An Identification information has been sent by the supplicant. Move to the
     * next state if possible.
     */
    public void requestAccess() {
        states[currentState].requestAccess();

        delegate.notify(new AuthenticationEvent(AuthenticationEvent.Type.REQUESTED,
                supplicantConnectpoint, toAuthRecord()));

        // move to the next state
        next(TRANSITION_REQUEST_ACCESS);
    }

    /**
     * RADIUS has accepted the identification. Move to the next state if possible.
     */
    public void authorizeAccess() {
        states[currentState].radiusAccepted();
        // move to the next state
        next(TRANSITION_AUTHORIZE_ACCESS);

        delegate.notify(new AuthenticationEvent(AuthenticationEvent.Type.APPROVED,
                supplicantConnectpoint, toAuthRecord()));

        // Clear mapping
        deleteStateMachineMapping(this);
    }

    /**
     * RADIUS has denied the identification. Move to the next state if possible.
     */
    public void denyAccess() {
        states[currentState].radiusDenied();
        // move to the next state
        next(TRANSITION_DENY_ACCESS);

        delegate.notify(new AuthenticationEvent(AuthenticationEvent.Type.DENIED,
                supplicantConnectpoint, toAuthRecord()));

        // Clear mappings
        deleteStateMachineMapping(this);
    }

    /**
     * Logoff request has been requested. Move to the next state if possible.
     */
    public void logoff() {
        states[currentState].logoff();

        // TODO event here?

        // move to the next state
        next(TRANSITION_LOGOFF);
    }

    private AuthenticationRecord toAuthRecord() {
        return new AuthenticationRecord(this.supplicantConnectpoint(),
                this.username(), this.supplicantAddress(), this.stateString(),
                this.getLastPacketReceivedTime());
    }

    /**
     * Gets the current state.
     *
     * @return The current state. Could be STATE_IDLE, STATE_STARTED, STATE_PENDING,
     *         STATE_AUTHORIZED, STATE_UNAUTHORIZED.
     */
    public int state() {
        return currentState;
    }

    public String stateString() {
        return states[currentState].name();
    }

    @Override
    public String toString() {
        return ("sessionId: " + this.sessionId) + "\t" + ("state: " + this.currentState);
    }

    abstract static class State {
        private final Logger log = getLogger(getClass());

        abstract String name();

        public void start() {
            log.warn("START transition from this state is not allowed.");
        }

        public void requestAccess() {
            log.warn("REQUEST ACCESS transition from this state is not allowed.");
        }

        public void radiusAccepted() {
            log.warn("AUTHORIZE ACCESS transition from this state is not allowed.");
        }

        public void radiusDenied() {
            log.warn("DENY ACCESS transition from this state is not allowed.");
        }

        public void logoff() {
            log.warn("LOGOFF transition from this state is not allowed.");
        }
    }

    /**
     * Idle state: supplicant is logged off from the network.
     */
    static class Idle extends State {
        private final Logger log = getLogger(getClass());
        private String name = "IDLE_STATE";

        @Override
        String name() {
            return this.name;
        }

        @Override
        public void start() {
            log.info("Moving from IDLE state to STARTED state.");
        }
    }

    /**
     * Started state: supplicant has entered the network and informed the
     * authenticator.
     */
    static class Started extends State {
        private final Logger log = getLogger(getClass());
        private String name = "STARTED_STATE";

        @Override
        String name() {
            return this.name;
        }

        @Override
        public void requestAccess() {
            log.info("Moving from STARTED state to PENDING state.");
        }
    }

    /**
     * Pending state: supplicant has been identified by the authenticator but has
     * not access yet.
     */
    static class Pending extends State {
        private final Logger log = getLogger(getClass());
        private String name = "PENDING_STATE";

        @Override
        String name() {
            return this.name;
        }

        @Override
        public void radiusAccepted() {
            log.info("Moving from PENDING state to AUTHORIZED state.");
        }

        @Override
        public void radiusDenied() {
            log.info("Moving from PENDING state to UNAUTHORIZED state.");
        }
    }

    /**
     * Authorized state: supplicant port has been accepted, access is granted.
     */
    static class Authorized extends State {
        private final Logger log = getLogger(getClass());
        private String name = "AUTHORIZED_STATE";

        @Override
        String name() {
            return this.name;
        }

        @Override
        public void start() {
            log.info("Moving from AUTHORIZED state to STARTED state.");
        }

        @Override
        public void logoff() {

            log.info("Moving from AUTHORIZED state to IDLE state.");
        }
    }

    /**
     * Unauthorized state: supplicant port has been rejected, access is denied.
     */
    static class Unauthorized extends State {
        private final Logger log = getLogger(getClass());
        private String name = "UNAUTHORIZED_STATE";

        @Override
        String name() {
            return this.name;
        }

        @Override
        public void start() {
            log.info("Moving from UNAUTHORIZED state to STARTED state.");
        }

        @Override
        public void logoff() {
            log.info("Moving from UNAUTHORIZED state to IDLE state.");
        }
    }

    private void timeout() {
        boolean noTrafficWithinThreshold =
                (System.currentTimeMillis() - lastPacketReceivedTime) > ((cleanupTimerTimeOutInMins * 60 * 1000) / 2);

        if (TIMEOUT_ELIGIBLE_STATES.contains(currentState) && noTrafficWithinThreshold) {
            this.setSessionTerminateReason(SessionTerminationReasons.TIME_OUT.reason);

            delegate.notify(new AuthenticationEvent(AuthenticationEvent.Type.TIMEOUT,
                    this.supplicantConnectpoint));
            // If StateMachine is not eligible for cleanup yet, reschedule cleanupTimer further.
        } else {
            this.scheduleTimeout();
        }
    }

}
