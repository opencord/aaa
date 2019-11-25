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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.Executors;

import static org.junit.Assert.assertEquals;

public class StateMachineTest {
    StateMachine stateMachine = null;

    @Before
    public void setUp() {
        System.out.println("Set Up.");
        StateMachine.setDelegate(e -> { });
        stateMachine = new StateMachine("session0", Executors.newSingleThreadScheduledExecutor());
    }

    @After
    public void tearDown() {
        System.out.println("Tear Down.");
        stateMachine = null;
    }

    @Test
    /**
     * Test all the basic inputs from state to state: IDLE -> STARTED -> PENDING -> AUTHORIZED -> IDLE
     */
    public void basic() {
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
    public void testIdleState() {
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
    public void testStartedState() {
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
    public void testPendingStateToAuthorized() {
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
    public void testPendingStateToUnauthorized() {
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
    public void testAuthorizedState() {
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
    public void testUnauthorizedState() {
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

}
