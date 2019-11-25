/*
 * Copyright 2020-present Open Networking Foundation
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

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Manages allocating request identifiers and mapping them to sessions.
 */
public class IdentifierManager {

    private static final int MAX_IDENTIFIER = 256;

    private BlockingQueue<Integer> freeIdNumbers;

    private ConcurrentMap<RequestIdentifier, String> idToSession;

    /**
     * Creates and initializes a new identifier manager.
     */
    public IdentifierManager() {
        idToSession = Maps.newConcurrentMap();
        freeIdNumbers = new LinkedBlockingQueue<>();

        // Starts at 2 because ids 0 and 1 are reserved for RADIUS server status requests.
        for (int i = 2; i < MAX_IDENTIFIER; i++) {
            freeIdNumbers.add(i);
        }
    }

    /**
     * Gets a new identifier and maps it to the given session ID.
     *
     * @param sessionId session this identifier is associated with
     * @return identifier
     */
    public synchronized RequestIdentifier getNewIdentifier(String sessionId) {
        int idNum;
        try {
            idNum = freeIdNumbers.take();
        } catch (InterruptedException e) {
            return null;
        }

        RequestIdentifier id = RequestIdentifier.of((byte) idNum);

        idToSession.put(id, sessionId);

        return id;
    }

    /**
     * Gets the session ID associated with a given request ID.
     *
     * @param id request ID
     * @return session ID
     */
    public String getSessionId(RequestIdentifier id) {
        return idToSession.get(id);
    }

    /**
     * Releases a request identifier and removes session mapping.
     *
     * @param id request identifier to release
     */
    public synchronized void releaseIdentifier(RequestIdentifier id) {
        String session = idToSession.remove(id);
        if (session == null) {
            // this id wasn't mapped to a session so is still free
            return;
        }

        // add id number back to set of free ids
        freeIdNumbers.add((int) id.identifier());
    }
}
