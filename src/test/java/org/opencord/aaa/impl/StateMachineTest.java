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

/*
 * TODO: As a first pass, this set of unit tests is re-implementing those
 * already defined in org.opencord.aaa.StateMachineTest
 */

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.opencord.aaa.PrintableTest;
import org.opencord.aaa.api.AaaAuthState;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.onlab.packet.VlanId.vlanId;
import static org.opencord.aaa.impl.StateMachine.deleteByMac;
import static org.opencord.aaa.impl.StateMachine.lookupStateMachineById;
import static org.opencord.aaa.impl.StateMachine.lookupStateMachineBySessionId;

/**
 * Unit tests for {@link StateMachine}.
 */
public class StateMachineTest extends PrintableTest {

    private static final String SESSION_ID = "session0";
    private static final VlanId C_TAG = vlanId((short) 2);
    private static final String FMT_MAC = "00:00:00:00:00:%02x";

    StateMachine sm = null;

    @Before
    public void setUp() {
        StateMachine.initializeMaps();
        sm = new StateMachine(SESSION_ID, C_TAG);
    }

    @After
    public void tearDown() {
        StateMachine.destroyMaps();
        sm = null;
    }

    /*
     * Test all the basic inputs from state to state:
     * IDLE -> STARTED -> PENDING -> AUTHORIZED -> IDLE
     */
    @Test
    public void basic() {
        print("=== BASIC ===");
        assertEquals(AaaAuthState.IDLE, sm.state());

        sm.start();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.authorizeAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());

        sm.logoff();
        assertEquals(AaaAuthState.IDLE, sm.state());
    }

    /*
     * Test all inputs from an IDLE state
     * (starting with the ones that are not
     * impacting the current state).
     */
    @Test
    public void testIdleState() {
        print("=== IDLE state test ===");
        assertEquals(AaaAuthState.IDLE, sm.state());

        sm.requestAccess();
        assertEquals(AaaAuthState.IDLE, sm.state());

        sm.authorizeAccess();
        assertEquals(AaaAuthState.IDLE, sm.state());

        sm.denyAccess();
        assertEquals(AaaAuthState.IDLE, sm.state());

        sm.logoff();
        assertEquals(AaaAuthState.IDLE, sm.state());

        sm.start();
        assertEquals(AaaAuthState.STARTED, sm.state());
    }

    /*
     * Test all inputs from an STARTED state
     * (starting with the ones that are not
     * impacting the current state).
     */
    @Test
    public void testStartedState() {
        print("=== STARTED state test ===");
        sm.start();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.authorizeAccess();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.denyAccess();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.logoff();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.start();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());
    }

    /*
     * Test all inputs from a PENDING state
     * (starting with the ones that are not
     * impacting the current state).
     * The next valid state for this test is AUTHORIZED.
     */
    @Test
    public void testPendingStateToAuthorized() {
        print("=== PENDING state test (AUTHORIZED) ===");
        sm.start();
        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.logoff();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.start();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.authorizeAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());

        // NOTE: once AUTHORIZED, denyAccess has no effect
        sm.denyAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());
    }

    /*
     * Test all inputs from a PENDING state
     * (starting with the ones that are not
     * impacting the current state).
     * The next valid state for this test is UNAUTHORIZED.
     */
    @Test
    public void testPendingStateToUnauthorized() {
        print("=== PENDING state test (UNAUTHORIZED) ===");
        sm.start();
        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.logoff();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.start();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.denyAccess();
        assertEquals(AaaAuthState.UNAUTHORIZED, sm.state());

        // NOTE: once UNAUTHORIZED, authorizeAccess has no effect
        sm.authorizeAccess();
        assertEquals(AaaAuthState.UNAUTHORIZED, sm.state());
    }

    /*
     * Test all inputs from an AUTHORIZED state
     * (starting with the ones that are not
     * impacting the current state).
     * FIXME: doesn't seem to test what the above description states
     */
    @Test
    public void testAuthorizedState() {
        print("=== AUTHORIZED state test ===");
        sm.start();
        sm.requestAccess();
        sm.authorizeAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());


        sm.start();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.authorizeAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());

        sm.denyAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());

        sm.logoff();
        assertEquals(AaaAuthState.IDLE, sm.state());
    }

    /*
     * Test all inputs from an UNAUTHORIZED state
     * (starting with the ones that are not
     * impacting the current state).
     * FIXME: doesn't seem to test what the above description states
     */
    @Test
    public void testUnauthorizedState() {
        print("=== UNAUTHORIZED state test ===");
        sm.start();
        sm.requestAccess();
        sm.denyAccess();
        assertEquals(AaaAuthState.UNAUTHORIZED, sm.state());


        sm.start();
        assertEquals(AaaAuthState.STARTED, sm.state());

        sm.requestAccess();
        assertEquals(AaaAuthState.PENDING, sm.state());

        sm.authorizeAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());

        sm.denyAccess();
        assertEquals(AaaAuthState.AUTHORIZED, sm.state());

        sm.logoff();
        assertEquals(AaaAuthState.IDLE, sm.state());
    }

    @Test
    public void testSessionIdLookups() {
        print("=== Session ID Lookups ===");

        final String sessionId1 = "session1";
        final String sessionId2 = "session2";
        final String sessionId3 = "session3";

        StateMachine sm1expNull = lookupStateMachineBySessionId(sessionId1);
        assertNull(sm1expNull);
        StateMachine sm2expNull = lookupStateMachineBySessionId(sessionId2);
        assertNull(sm2expNull);

        StateMachine sm1 = new StateMachine(sessionId1, C_TAG);
        StateMachine sm2 = new StateMachine(sessionId2, C_TAG);

        assertEquals(sm1, lookupStateMachineBySessionId(sessionId1));
        assertEquals(sm2, lookupStateMachineBySessionId(sessionId2));
        assertNull(lookupStateMachineBySessionId(sessionId3));
    }

    @Test
    public void testIdentifierLookups() {
        print("=== Identifier Lookups ===");

        final String sessionId1 = "session1";
        final String sessionId2 = "session2";

        StateMachine sm1expNull = lookupStateMachineById((byte) 1);
        assertNull(sm1expNull);
        StateMachine sm2expNull = lookupStateMachineById((byte) 2);
        assertNull(sm2expNull);

        StateMachine sm1 = new StateMachine(sessionId1, C_TAG);
        sm1.start();
        StateMachine sm2 = new StateMachine(sessionId2, C_TAG);
        sm2.start();

        assertEquals(sm1, lookupStateMachineById(sm1.assignMeTheNextIdentifier()));
        assertEquals(sm2, lookupStateMachineById(sm2.assignMeTheNextIdentifier()));
        print(sm1);
        print(sm2);
    }

    private String makeMac(int i) {
        return String.format(FMT_MAC, i);
    }

    @Test
    public void testStateMachineReset() {
        final int count = 256;

        // Instantiate a bunch of state machines
        for (int i = 0; i < count; i++) {
            String mac = makeMac(i);
            StateMachine sm = new StateMachine(mac, vlanId((short) i));
            sm.start();
            sm.setSupplicantAddress(MacAddress.valueOf(mac));
        }

        // Verify all state machines with an "even" MAC exist
        for (int i = 0; i < count; i += 2) {
            String mac = makeMac(i);
            assertNotNull(lookupStateMachineBySessionId(mac));
        }

        // Delete all state machines with an "even" MAC
        for (int i = 0; i < count; i += 2) {
            String mac = makeMac(i);
            deleteByMac(MacAddress.valueOf(mac));
        }

        // Verify all the deleted state machines no longer exist
        for (int i = 0; i < count; i += 2) {
            String mac = makeMac(i);
            assertNull(lookupStateMachineBySessionId(mac));
        }

        // (new) Verify all state machines with an "odd" MAC exist
        for (int i = 1; i < count; i += 2) {
            String mac = makeMac(i);
            assertNotNull(lookupStateMachineBySessionId(mac));
        }
    }
}
