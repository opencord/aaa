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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.Logger;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;
import static org.slf4j.LoggerFactory.getLogger;

@RunWith(Parameterized.class)
public class IdentifierManagerTest {

    // Change this to have more run with mvn
    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[1][0];
    }

    IdentifierManager idManager = null;
    private final Logger log = getLogger(getClass());

    @Before
    public void setUp() {
        System.out.print("Set up");
        idManager.timeout = 1500;
        idManager.pruningInterval = 1;
        idManager.pollTimeout = 1;
        idManager = new IdentifierManager();
    }

    @After
    public void tearDown() {
        System.out.print("Tear down");
        idManager = null;
    }

    @Test
    /**
     * Make sure that we never get ID 1 or 0 as they are reserved for RadiusOperationalStatusManager
     */
    public void testIdSequence() {
        for (int i = 1; i <= 300; i++) {
            RequestIdentifier id = idManager.getNewIdentifier(Integer.toString(i));
            log.trace("Id: {}", id.getReadableIdentifier());
            assertNotEquals(id.identifier(), 0);
            assertNotEquals(id.identifier(), 1);
            idManager.releaseIdentifier(id);
        }
    }

    @Test(timeout = 3800)
    public void testIdRelease() {
        assertEquals(254, idManager.getAvailableIdentifiers());
        for (int i = 0; i <= 253; i++) {
            idManager.getNewIdentifier(Integer.toString(i));
        }

        assertEquals(0, idManager.getAvailableIdentifiers());

        try {
            TimeUnit.MILLISECONDS.sleep(3500);
        } catch (InterruptedException e) {
            log.error("Can't sleep");
        }

        // check that the queue has been emptied after the timeout occurred
        assertEquals(254, idManager.getAvailableIdentifiers());

        // check that I can get a new ID immediately (note the timeout in the test declaration)
        idManager.getNewIdentifier(Integer.toString(254));
    }

    @Test(timeout = 5000)
    public void unavailableIds() {

        ExecutorService executor = Executors.newSingleThreadExecutor();

        Callable<Object> acquireId = () -> idManager.getNewIdentifier(Integer.toString(2));

        // fill the queue
        for (int i = 2; i <= 255; i++) {
            idManager.getNewIdentifier(Integer.toString(i));
        }

        // try to acquire an id
        Future<Object> futureAcquire = executor.submit(acquireId);

        // wait for the threads to complete
        RequestIdentifier id = null;
        try {
            id = (RequestIdentifier) futureAcquire.get();

            // if we can't get the ID within 2
            // seconds we'll drop the packet and we'll retry
            assertNull(id);
        } catch (InterruptedException | ExecutionException ex) {
            log.error("Something failed");
            assertNull(id);
        }
    }

    @Test(timeout = 5000)
    public void availableIds() {

        ExecutorService executor = Executors.newSingleThreadExecutor();

        Callable<Object> acquireId = () -> idManager.getNewIdentifier(Integer.toString(2));

        // fill the queue
        for (int i = 2; i <= 255; i++) {
            idManager.getNewIdentifier(Integer.toString(i));
        }

        // try to release an id
        final RequestIdentifier id = new RequestIdentifier((byte) 2);
        executor.submit(() -> idManager.releaseIdentifier(id));
        // try to acquire an id
        Future<Object> futureAcquire = executor.submit(acquireId);

        // wait for the threads to complete
        RequestIdentifier idGet = null;
        try {
            idGet = (RequestIdentifier) futureAcquire.get();
            assertNotNull(idGet);
        } catch (InterruptedException | ExecutionException ex) {
            log.error("Something failed");
            assertNull(idGet);
        }
    }
}
