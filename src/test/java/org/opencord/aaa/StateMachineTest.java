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
package org.opencord.aaa;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.packet.MacAddress;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class StateMachineTest {
    StateMachine stateMachine = null;

    @Before
    public void setUp() {
        System.out.println("Set Up.");
        StateMachine.initializeMaps();
        stateMachine = new StateMachine("session0");
    }

    @After
    public void tearDown() {
        System.out.println("Tear Down.");
        StateMachine.destroyMaps();
        stateMachine = null;
    }

    @Test
    /**
     * Test all the basic inputs from state to state: IDLE -> STARTED -> PENDING -> AUTHORIZED -> IDLE
     */
    public void basic() throws StateMachineException {
        System.out.println("======= BASIC =======.");
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);

        stateMachine.start();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);

        stateMachine.requestAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.authorizeAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_AUTHORIZED);

        stateMachine.logoff();
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);
    }

    @Test
    /**
     * Test all inputs from an IDLE state (starting with the ones that are not impacting the current state)
     */
    public void testIdleState() throws StateMachineException {
        System.out.println("======= IDLE STATE TEST =======.");
        stateMachine.requestAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);

        stateMachine.authorizeAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);

        stateMachine.denyAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);

        stateMachine.logoff();
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);

        stateMachine.start();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);
    }

    @Test
    /**
     * Test all inputs from an STARTED state (starting with the ones that are not impacting the current state)
     */
    public void testStartedState() throws StateMachineException {
        System.out.println("======= STARTED STATE TEST =======.");
        stateMachine.start();

        stateMachine.authorizeAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);

        stateMachine.denyAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);

        stateMachine.logoff();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);

        stateMachine.start();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);

        stateMachine.requestAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);
    }

    @Test
    /**
     * Test all inputs from a PENDING state (starting with the ones that are not impacting the current state).
     * The next valid state for this test is AUTHORIZED
     */
    public void testPendingStateToAuthorized() throws StateMachineException {
        System.out.println("======= PENDING STATE TEST (AUTHORIZED) =======.");
        stateMachine.start();
        stateMachine.requestAccess();

        stateMachine.logoff();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.start();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.requestAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.authorizeAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_AUTHORIZED);

        stateMachine.denyAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_AUTHORIZED);
    }

    @Test
    /**
     * Test all inputs from an PENDING state (starting with the ones that are not impacting the current state).
     * The next valid state for this test is UNAUTHORIZED
     */
    public void testPendingStateToUnauthorized() throws StateMachineException {
        System.out.println("======= PENDING STATE TEST (DENIED) =======.");
        stateMachine.start();
        stateMachine.requestAccess();

        stateMachine.logoff();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.start();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.requestAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.denyAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_UNAUTHORIZED);

        stateMachine.authorizeAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_UNAUTHORIZED);
    }

    @Test
    /**
     * Test all inputs from an AUTHORIZED state (starting with the ones that are not impacting the current state).
     */
    public void testAuthorizedState() throws StateMachineException {
        System.out.println("======= AUTHORIZED STATE TEST =======.");
        stateMachine.start();
        stateMachine.requestAccess();
        stateMachine.authorizeAccess();

        stateMachine.start();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);

        stateMachine.requestAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.authorizeAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_AUTHORIZED);

        stateMachine.denyAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_AUTHORIZED);

        stateMachine.logoff();
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);
    }

    @Test
    /**
     * Test all inputs from an UNAUTHORIZED state (starting with the ones that are not impacting the current state).
     */
    public void testUnauthorizedState() throws StateMachineException {
        System.out.println("======= UNAUTHORIZED STATE TEST =======.");
        stateMachine.start();
        stateMachine.requestAccess();
        stateMachine.denyAccess();

        stateMachine.start();
        assertEquals(stateMachine.state(), StateMachine.STATE_STARTED);

        stateMachine.requestAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_PENDING);

        stateMachine.authorizeAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_AUTHORIZED);

        stateMachine.denyAccess();
        assertEquals(stateMachine.state(), StateMachine.STATE_AUTHORIZED);

        stateMachine.logoff();
        assertEquals(stateMachine.state(), StateMachine.STATE_IDLE);
    }

    @Test
    public void testSessionIdLookups() {
        String sessionId1 = "session1";
        String sessionId2 = "session2";
        String sessionId3 = "session3";

        StateMachine machine1ShouldBeNull =
                StateMachine.lookupStateMachineBySessionId(sessionId1);
        assertNull(machine1ShouldBeNull);
        StateMachine machine2ShouldBeNull =
                StateMachine.lookupStateMachineBySessionId(sessionId2);
        assertNull(machine2ShouldBeNull);

        StateMachine stateMachine1 = new StateMachine(sessionId1);
        StateMachine stateMachine2 = new StateMachine(sessionId2);

        assertEquals(stateMachine1,
                     StateMachine.lookupStateMachineBySessionId(sessionId1));
        assertEquals(stateMachine2,
                     StateMachine.lookupStateMachineBySessionId(sessionId2));
        assertNull(StateMachine.lookupStateMachineBySessionId(sessionId3));
    }

    @Test
    public void testIdentifierLookups() throws StateMachineException {
        String sessionId1 = "session1";
        String sessionId2 = "session2";

        StateMachine machine1ShouldBeNull =
                StateMachine.lookupStateMachineById((byte) 1);
        assertNull(machine1ShouldBeNull);
        StateMachine machine2ShouldBeNull =
                StateMachine.lookupStateMachineById((byte) 2);
        assertNull(machine2ShouldBeNull);

        StateMachine stateMachine1 = new StateMachine(sessionId1);
        stateMachine1.start();
        StateMachine stateMachine2 = new StateMachine(sessionId2);
        stateMachine2.start();

        assertEquals(stateMachine1,
                     StateMachine.lookupStateMachineById(stateMachine1.identifier()));
        assertEquals(stateMachine2,
                     StateMachine.lookupStateMachineById(stateMachine2.identifier()));
    }

    @Test
    /**
     * Test state machine deletes
     */
    public void testStateMachineReset() throws StateMachineException {

        int count = 256;

        //StateMachine.initializeMaps();
        StateMachine.lookupStateMachineById((byte) 1);

        // Instantiate a bunch of state machines
        for (int i = 0; i < count; i += 1) {
            String mac = String.format("00:00:00:00:00:%02x", i);
            StateMachine sm = new StateMachine(mac);
            sm.start();
            sm.setSupplicantAddress(MacAddress.valueOf(mac));
        }

        // Verify all state machines with a "even" MAC exist
        for (int i = 0; i < count; i += 2) {
            String mac = String.format("00:00:00:00:00:%02x", i);
            assertNotNull(StateMachine.lookupStateMachineBySessionId(mac));
        }

        // Delete all state machines with a "even" MAC
        for (int i = 0; i < count; i += 2) {
            String mac = String.format("00:00:00:00:00:%02x", i);
            StateMachine.deleteByMac(MacAddress.valueOf(mac));
        }

        // Verify all the delete state machines no long exist
        for (int i = 0; i < count; i += 2) {
            String mac = String.format("00:00:00:00:00:%02x", i);
            assertNull(StateMachine.lookupStateMachineBySessionId(mac));
        }
    }
}
