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

import com.google.common.collect.ImmutableMap;
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
    protected static int timeout = 10000;
    protected static int pollTimeout = 2;
    protected static int pruningInterval = 3;

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
                groupedThreads("onos/aaa", "idpruner-%d", log));

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
        // Run this part without the lock.
        Integer idNum;
        try {
            idNum = freeIdNumbers.poll(pollTimeout, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            // Interrupted case
            if (log.isTraceEnabled()) {
                log.trace("Interrupted while waiting for an id");
            }
            return null;
        }
        // Timeout let's exit
        if (idNum == null) {
            if (log.isTraceEnabled()) {
                log.trace("Timedout there are no available ids");
            }
            return null;
        }
        // Start of the synchronized zone. Real contention happens here.
        // This thread wants to update the session map. The release thread
        // wants to update the session map first and then free the id. Same
        // for the pruner. If this thread is interrupted here is not a big issue
        // its update is not yet visible for the remaining threads: i) the
        // release thread cannot release an id not yet taken; ii) the pruning
        // thread cannot prune for the same reason.
        synchronized (this) {
            if (log.isTraceEnabled()) {
                log.trace("Got identifier {} for session {}", idNum, sessionId);
            }

            RequestIdentifier id = RequestIdentifier.of((byte) idNum.intValue());

            idToSession.put(id, Pair.of(sessionId, System.currentTimeMillis()));

            return id;
        }
    }

    /**
     * Gets the session ID associated with a given request ID.
     *
     * @param id request ID
     * @return session ID
     */
    public synchronized String getSessionId(RequestIdentifier id) {
        //TODO this has multiple accesses
        return idToSession.get(id) == null ? null : idToSession.get(id).getKey();
    }

    /**
     * Releases a request identifier and removes session mapping.
     *
     * @param id request identifier to release
     */
    public synchronized void releaseIdentifier(RequestIdentifier id) {
        if (log.isTraceEnabled()) {
            log.trace("Releasing identifier {}", id.getReadableIdentifier());
        }

        Pair<String, Long> session = idToSession.remove(id);
        if (session == null) {
            if (log.isTraceEnabled()) {
                log.trace("Unable to released identifier {} for session null", id.getReadableIdentifier());
            }
            // this id wasn't mapped to a session so is still free
            return;
        }

        // add id number back to set of free ids
        freeIdNumbers.add(id.getReadableIdentifier());

        if (log.isTraceEnabled()) {
            log.trace("Released identifier {} for session {}", id.getReadableIdentifier(), session.getKey());
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

    private synchronized void pruneIfNeeded() {
        if (log.isTraceEnabled()) {
            log.trace("Starting pruning cycle");
        }
        // Gets an immutable copy of the ids and release the ones that exceed the timeout
        Map<RequestIdentifier, Pair<String, Long>> idsToCheck = ImmutableMap.copyOf(idToSession);
        // We should not modify while iterating - this is why we get a copy
        Iterator<Map.Entry<RequestIdentifier, Pair<String, Long>>> itr = idsToCheck.entrySet().iterator();
        itr.forEachRemaining((entry) -> {
            RequestIdentifier id = entry.getKey();
            Pair<String, Long> info = entry.getValue();
            long diff = System.currentTimeMillis() - info.getValue();
            if (diff >= timeout) {
                if (log.isTraceEnabled()) {
                    log.trace("Identifier {} for session {} has exceeded timeout {}, releasing",
                            id.getReadableIdentifier(), info.getKey(), timeout);
                }
                releaseIdentifier(id);
            }
        });
        if (log.isTraceEnabled()) {
            log.trace("End pruning cycle");
        }
    }

    private class IdentifierPruner implements Runnable {
        @Override
        public void run() {
            pruneIfNeeded();
        }

    }
}
