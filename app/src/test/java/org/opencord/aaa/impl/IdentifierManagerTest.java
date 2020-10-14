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
