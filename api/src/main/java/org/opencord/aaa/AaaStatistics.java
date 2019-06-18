/*
 * Copyright 2018-present Open Networking Foundation
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

package org.opencord.aaa;

import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicLong;

public class AaaStatistics {
    // Number of access accept packets sent to the server
    private AtomicLong acceptResponsesRx = new AtomicLong();
    // Number of access reject packets sent to the server
    private AtomicLong rejectResponsesRx = new AtomicLong();
    // Number of access challenge packets sent to the server
    private AtomicLong challengeResponsesRx = new AtomicLong();
    // Number of access request packets sent to the server
    private AtomicLong accessRequestsTx = new AtomicLong();
    // Number of access request packets pending a response from the server
    private AtomicLong pendingRequests = new AtomicLong();
    // Number of packets of an unknown RADIUS type received from the accounting
    // server
    private AtomicLong unknownTypeRx = new AtomicLong();
    // Number of access response packets received from the server with an invalid
    // validator
    private AtomicLong invalidValidatorsRx = new AtomicLong();
    // Number of dropped packets received from the accounting server
    private AtomicLong droppedResponsesRx = new AtomicLong();
    // Number of malformed access response packets received from the server
    private AtomicLong malformedResponsesRx = new AtomicLong();
    // Number of packets received from an unknown server
    private AtomicLong unknownServerRx = new AtomicLong();
    // Roundtrip packet time to the accounting server
    private AtomicLong requestRttMilis = new AtomicLong();
    // Number of access request packets retransmitted to the server
    private AtomicLong requestReTx = new AtomicLong();
    // Number of sessions expired
    private AtomicLong numberOfSessionsExpired = new AtomicLong();

    private LinkedList<Long> packetRoundTripTimeList = new LinkedList<Long>();

    public LinkedList<Long> getPacketRoundTripTimeList() {
        return packetRoundTripTimeList;
    }

    public int getPacketRoundTripTimeListSize() {
        return packetRoundTripTimeList.size();
    }

    public void clearPacketRoundTripTimeList() {
        packetRoundTripTimeList.clear();
    }

    public void getPacketRoundTripTimeListRemoveFirst() {
        packetRoundTripTimeList.removeFirst();
    }

    public void getPacketRoundTripTimeListAdd(long time) {
        packetRoundTripTimeList.add(time);
    }

    public Long getRequestReTx() {
        return requestReTx.get();
    }

    public void setRequestRttMilis(AtomicLong requestRttMilis) {
        this.requestRttMilis = requestRttMilis;
    }

    public Long getUnknownServerRx() {
        return unknownServerRx.get();
    }

    public Long getRequestRttMilis() {
        return requestRttMilis.get();
    }

    public Long getMalformedResponsesRx() {
        return malformedResponsesRx.get();
    }

    public Long getDroppedResponsesRx() {
        return droppedResponsesRx.get();
    }

    public Long getInvalidValidatorsRx() {
        return invalidValidatorsRx.get();
    }

    public Long getAcceptResponsesRx() {
        return acceptResponsesRx.get();
    }

    public Long getRejectResponsesRx() {
        return rejectResponsesRx.get();
    }

    public Long getChallengeResponsesRx() {
        return challengeResponsesRx.get();
    }

    public Long getAccessRequestsTx() {
        return accessRequestsTx.get();
    }

    public Long getPendingRequests() {
        return pendingRequests.get();
    }

    public Long getUnknownTypeRx() {
        return unknownTypeRx.get();
    }

    public void increaseAcceptResponsesRx() {
        acceptResponsesRx.incrementAndGet();
    }

    public void increaseRejectResponsesRx() {
        rejectResponsesRx.incrementAndGet();
    }

    public void increaseChallengeResponsesRx() {
        challengeResponsesRx.incrementAndGet();
    }

    public void increaseAccessRequestsTx() {
        accessRequestsTx.incrementAndGet();
    }

    public void increaseRequestReTx() {
        requestReTx.incrementAndGet();
    }

    public void increaseOrDecreasePendingRequests(boolean isIncrement) {
        if (isIncrement) {
            pendingRequests.incrementAndGet();
        } else {
            pendingRequests.decrementAndGet();
        }
    }

    public void increaseUnknownTypeRx() {
        unknownTypeRx.incrementAndGet();
    }

    public void increaseMalformedResponsesRx() {
        malformedResponsesRx.incrementAndGet();
    }

    public void increaseInvalidValidatorsRx() {
        invalidValidatorsRx.incrementAndGet();
    }

    public void incrementUnknownServerRx() {
        unknownServerRx.incrementAndGet();
    }

    public void incrementNumberOfSessionsExpired() {
        numberOfSessionsExpired.incrementAndGet();
    }

    public void countDroppedResponsesRx() {
        long numberOfDroppedPackets = invalidValidatorsRx.get();
        numberOfDroppedPackets += unknownTypeRx.get();
        numberOfDroppedPackets += malformedResponsesRx.get();
        numberOfDroppedPackets += numberOfSessionsExpired.get();
        this.droppedResponsesRx = new AtomicLong(numberOfDroppedPackets);
    }

    public void resetAllCounters() {
        clearPacketRoundTripTimeList();

        accessRequestsTx.set(0);
        acceptResponsesRx.set(0);
        challengeResponsesRx.set(0);
        droppedResponsesRx.set(0);
        invalidValidatorsRx.set(0);
        malformedResponsesRx.set(0);
        pendingRequests.set(0);
        rejectResponsesRx.set(0);
        requestReTx.set(0);
        requestRttMilis.set(0);
        unknownServerRx.set(0);
        unknownTypeRx.set(0);
    }
}
