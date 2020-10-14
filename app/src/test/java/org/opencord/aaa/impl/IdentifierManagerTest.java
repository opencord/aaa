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
import org.slf4j.Logger;

import static org.junit.Assert.assertNotEquals;
import static org.slf4j.LoggerFactory.getLogger;

public class IdentifierManagerTest {

    IdentifierManager idManager = null;
    private final Logger log = getLogger(getClass());

    @Before
    public void setUp() {
        System.out.print("Set up");
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
            log.trace("Id: {}", id.identifier() & 0xff);
            assertNotEquals(id.identifier(), 0);
            assertNotEquals(id.identifier(), 1);
            idManager.releaseIdentifier(id);
        }
    }
}
