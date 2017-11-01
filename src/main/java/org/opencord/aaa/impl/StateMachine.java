/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.opencord.aaa.impl;

import com.google.common.collect.Maps;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.opencord.aaa.api.AaaAuthState;
import org.slf4j.Logger;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.opencord.aaa.api.AaaAuthState.AUTHORIZED;
import static org.opencord.aaa.api.AaaAuthState.IDLE;
import static org.opencord.aaa.api.AaaAuthState.PENDING;
import static org.opencord.aaa.api.AaaAuthState.STARTED;
import static org.opencord.aaa.api.AaaAuthState.UNAUTHORIZED;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * AAA Finite State Machine.
 */

/*
 * TODO: Review - rename this class?
 * A better name for this class might be something like AaaSessionState.
 * "StateMachine" is too generic and does not convey what instances of
 * this class represent, by its name alone.
 */
public class StateMachine {
    /*
                                    |
                                    v
                     logoff   +-----------+   logoff
                   +--------->|   IDLE    |<---------+
                   |          +-----------+          |
                   |                | start          |
                   |                v                |
                   |   start  +-----------+  start   |
                   |    +---->|  STARTED  |<----+    |
                   |    |     +-----------+     |    |
                   |    |           | request   |    |
                   |    |           v access    |    |
                   |    |     +-----------+     |    |
                   |    |     |  PENDING  |     |    |
                   |    |     +-----------+     |    |
                   |    |   auth |     | deny   |    |
                   |    | access |     | access |    |
            +------+----+--+     |     |     +--+----+------+
            |  AUTHORIZED  |<----+     +---->| UNAUTHORIZED |
            +--------------+                 +--------------+
     */

    private static final Set<AaaAuthState> TO_IDLE =
            new HashSet<>(Arrays.asList(AUTHORIZED, UNAUTHORIZED));

    private static final Set<AaaAuthState> TO_STARTED =
            new HashSet<>(Arrays.asList(IDLE, AUTHORIZED, UNAUTHORIZED));

    private static final Set<AaaAuthState> TO_PENDING =
            new HashSet<>(Arrays.asList(STARTED));

    private static final Set<AaaAuthState> TO_AUTHORIZED =
            new HashSet<>(Arrays.asList(PENDING));

    private static final Set<AaaAuthState> TO_UNAUTHORIZED =
            new HashSet<>(Arrays.asList(PENDING));

    private static final Logger log = getLogger(StateMachine.class);

    // state machines mapped by unique session ID (dpid + port#)
    private static Map<String, StateMachine> sessionIdMap;

    // state machines mapped by internal ID (RADIUS "conversation" id)
    private static Map<Integer, StateMachine> identifierMap;


    // internal "conversation" id, incremented and assigned for each new request
    private static int identifier = -1;

//    private byte challengeIdentifier;
//    private byte[] challengeState;
//    private byte[] username;
//    private byte[] requestAuthenticator;


    private final String sessionId;
    private final VlanId cTag;

    private AaaAuthState currentState = IDLE;

    // Supplicant connectivity info
//    private ConnectPoint supplicantConnectPoint;
    private MacAddress supplicantAddress;
//    private short vlanId;
//    private byte priorityCode;


    /**
     * Constructs an authentication session instance, and creates a mapping
     * from the session ID to this instance.
     *
     * @param sessionId the session identifier
     * @param cTag      the associated C-Tag, if any
     */
    public StateMachine(String sessionId, VlanId cTag) {
        log.info("Creating new state machine for {} C-TAG {}", sessionId, cTag);
        this.sessionId = sessionId;
        this.cTag = cTag;
        sessionIdMap.put(sessionId, this);
    }

    /**
     * Returns the session identifier for this authorization session.
     *
     * @return the session ID
     */
    public String sessionId() {
        return sessionId;
    }

    /**
     * Returns the C-Tag VLAN ID for this authorization session;
     * (null if not applicable).
     *
     * @return the C-Tag VLAN ID
     */
    public VlanId cTag() {
        return cTag;
    }

    /**
     * Returns the current state of this session.
     *
     * @return the current state
     */
    public AaaAuthState state() {
        return currentState;
    }

    @Override
    public String toString() {
        return "StateMachine{" +
                "sessionId=\"" + sessionId +
                "\", c-tag=" + cTag +
                ", state=" + currentState +
                "}";

        // TODO: consider adding other attributes
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

    // TODO: getter/setter for : vlanId, priorityCode, challenge stuff, username, etc.

    /*
     * TODO: review - although the transition methods declared they threw StateMachineException,
     *       none of them ever did (search for "throw new" in the original source).
     *       So (for now), such declarations have been removed in this updated implementation.
     */


    /**
     * Client has requested the start action to allow network access.
     */
    public void start() {
        if (TO_STARTED.contains(currentState)) {
            allowTransition(STARTED);
            assignMeTheNextIdentifier();
            // TODO: emit event
        } else {
            warnBadTransition("START");
        }
    }

    /**
     * An Identification information has been sent by the supplicant.
     * Move to the next state if possible.
     */
    public void requestAccess() {
        if (TO_PENDING.contains(currentState)) {
            allowTransition(PENDING);
            // TODO: emit event
        } else {
            warnBadTransition("REQUEST ACCESS");
        }
    }

    /**
     * RADIUS has accepted the identification.
     * Move to the next state if possible.
     */
    public void authorizeAccess() {
        if (TO_AUTHORIZED.contains(currentState)) {
            allowTransition(AUTHORIZED);

            deleteStateMachineMapping(this);

            // TODO: emit event
            //  event listener (OLT app) would provision subscriber keyed off
            //   this event -- params: supplicantConnectPoint, cTag
        } else {
            warnBadTransition("AUTHORIZE ACCESS");
        }
    }

    /**
     * RADIUS has denied the identification.
     * Move to the next state if possible.
     */
    public void denyAccess() {
        if (TO_UNAUTHORIZED.contains(currentState)) {
            allowTransition(UNAUTHORIZED);

            deleteStateMachineMapping(this);

            // TODO: emit event
        } else {
            warnBadTransition("DENY ACCESS");
        }
    }

    /**
     * Logoff request has been requested.
     * Move to the next state if possible.
     */
    public void logoff() {
        if (TO_IDLE.contains(currentState)) {
            allowTransition(IDLE);

            // TODO: emit event
        } else {
            warnBadTransition("LOGOFF");
        }
    }

    private void allowTransition(AaaAuthState toState) {
        log.info("sessionId {}: Moving from {} to {} state",
                 sessionId, currentState, toState);
        currentState = toState;
    }

    private void warnBadTransition(String transition) {
        log.warn("sessionID {}: {} transition from {} is not allowed!",
                 sessionId, transition, currentState);
    }

    /**
     * Assigns a new "RADIUS conversation" identifier to this session and
     * remembers the mapping.
     *
     * @return the assigned identifier
     */
    /*
     * Assumption: These are used to uniquely identify a request packet to
     *             the RADIUS server; the RADIUS response packet is tagged
     *             with the same ID so that the caller can reconcile
     *             response with request. It is normal for a session to use
     *             different identifiers for each request/response transaction.
     */
    synchronized byte assignMeTheNextIdentifier() {
        identifier = (identifier + 1) % 255;
        identifierMap.put(identifier, this);
        return (byte) identifier;
    }


    // ===

    /**
     * Initializes the session mappings.
     */
    static void initializeMaps() {
        sessionIdMap = Maps.newConcurrentMap();
        identifierMap = Maps.newConcurrentMap();
        identifier = -1;
    }

    /**
     * Destroys the session mappings.
     */
    static void destroyMaps() {
        sessionIdMap = null;
        identifierMap = null;
    }

    /**
     * Removes all internal identifier mappings which map to the given
     * state machine instance.
     *
     * @param sm the state machine to be removed from the mappings
     */
    private static void deleteStateMachineMapping(StateMachine sm) {
        identifierMap.entrySet().removeIf(e -> e.getValue().equals(sm));
    }

    /**
     * Returns the state machine bound to the given session ID. If there is
     * no such binding, null is returned.
     *
     * @param sessionId the session ID
     * @return the associated state machine
     */
    static StateMachine lookupStateMachineBySessionId(String sessionId) {
        return sessionIdMap.get(sessionId);
    }

    /**
     * Returns the state machine bound to the given "RADIUS conversation"
     * identifier. If there is no such binding, null is returned.
     *
     * @param id the identifier
     * @return the associated state machine
     */
    static StateMachine lookupStateMachineById(byte id) {
        return identifierMap.get((int) id);
    }

    /**
     * Deletes authentication state machine records for a given MAC address.
     *
     * @param mac MAC address of the suppliant who's state machine
     *            should be removed
     */
    static void deleteByMac(MacAddress mac) {
        // Walk the map from session IDs to state machines looking for a MAC match
        for (Map.Entry<String, StateMachine> e : sessionIdMap.entrySet()) {

            StateMachine sm = e.getValue();

            // If a MAC match is found then delete the entry from the session ID
            // and identifier map as well as call delete identifier to clean up
            // the identifier bit set.
            if (sm != null && sm.supplicantAddress != null &&
                    sm.supplicantAddress.equals(mac)) {
                sessionIdMap.remove(sm.sessionId);
                if (identifier != -1) {
                    deleteStateMachineMapping(sm);
                }
                break;
            }
        }
    }
}
