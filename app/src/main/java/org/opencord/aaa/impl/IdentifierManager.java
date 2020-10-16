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
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Manages allocating request identifiers and mapping them to sessions.
 */
public class IdentifierManager {

    private final Logger log = getLogger(getClass());

    private static final int MAX_IDENTIFIER = 256;

    private BlockingQueue<Integer> freeIdNumbers;

    private ConcurrentMap<RequestIdentifier, Pair<String, Long>> idToSession;

    ScheduledFuture<?> scheduledidentifierPruner;

    // TODO read from component config
    public static int timeout = 10000;
    //TODO make this configurable
    public static int pruningInterval = 3;

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

        ScheduledExecutorService identifierPruner = Executors.newSingleThreadScheduledExecutor(
                groupedThreads("onos/aaa", "aaa-idpruner-%d", log));

        scheduledidentifierPruner = identifierPruner.scheduleAtFixedRate(
                new IdentifierPruner(), 0,
                pruningInterval, TimeUnit.SECONDS);
    }

    /**
     * Gets a new identifier and maps it to the given session ID.
     *
     * @param sessionId session this identifier is associated with
     * @return identifier
     */
    public RequestIdentifier getNewIdentifier(String sessionId) {

        int idNum;

        try {
            idNum = freeIdNumbers.take();
        } catch (InterruptedException ex) {
            log.error("Caught interrupted exception", ex);
            return null;
        }

        if (log.isTraceEnabled()) {
            log.trace("Got identifier {} for session {}", idNum, sessionId);
        }

        RequestIdentifier id = RequestIdentifier.of((byte) idNum);
        idToSession.put(id, Pair.of(sessionId, System.currentTimeMillis()));

        return id;
    }

    /**
     * Gets the session ID associated with a given request ID.
     *
     * @param id request ID
     * @return session ID
     */
    public String getSessionId(RequestIdentifier id) {
        Pair<String, Long> info = idToSession.get(id);
        return info == null ? null : info.getKey();
    }

    /**
     * Releases a request identifier and removes session mapping.
     *
     * @param id request identifier to release
     */
    public void releaseIdentifier(RequestIdentifier id) {
        if (log.isTraceEnabled()) {
            log.trace("Releasing identifier {}", id.identifier() & 0xff);
        }
        if (freeIdNumbers.contains(id.identifier() & 0xff)) {
            if (log.isTraceEnabled()) {
                log.trace("Identifier was already released {}", id.identifier() & 0xff);
            }
            // this id wasn't mapped to a session so is still free
        } else {
            freeIdNumbers.add(id.identifier() & 0xff);
        }

        if (!idToSession.containsKey(id)) {
            if (log.isTraceEnabled()) {
                log.trace("Session for Identifier was already removed {}", id.identifier() & 0xff);
            }
            // this id wasn't mapped to a session so is still free
            return;
        }

        Pair<String, Long> session = idToSession.remove(id);
        if (log.isTraceEnabled()) {
            log.info("Removed identifier {} for session {}", id.identifier() & 0xff, session.getKey());
        }
    }

    /**
     * Returns true if this ID is currently taken.
     *
     * @param id request identifier to check
     * @return boolean
     */
    private boolean isIdentifierTaken(Integer id) {
        return !freeIdNumbers.contains(id);
    }

    /**
     * Returns the count of available identifiers in a given moment.
     *
     * @return boolean
     */
    public int getAvailableIdentifiers() {
        return freeIdNumbers.size();
    }

    private void pruneIfNeeded() {
        if (log.isTraceEnabled()) {
            log.trace("Starting pruning cycle");
        }
        Iterator<Map.Entry<RequestIdentifier, Pair<String, Long>>> itr =
                idToSession.entrySet().iterator();
        itr.forEachRemaining((entry) -> {
            RequestIdentifier id = entry.getKey();
            Pair<String, Long> info = entry.getValue();
            if (System.currentTimeMillis() - info.getValue() >= timeout) {
                log.info("Identifier {} for session {} has " +
                                 "exceeded timeout {}, releasing",
                         id.identifier() & 0xff, info.getKey(), timeout);
                releaseIdentifier(id);
            }
        });
    }

    private class IdentifierPruner implements Runnable {
        @Override
        public void run() {
            pruneIfNeeded();
        }

    }
}
