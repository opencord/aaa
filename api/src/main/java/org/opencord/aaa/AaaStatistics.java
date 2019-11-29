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
    // Number of packets send to the server which timed out.
    private AtomicLong timedOutPackets = new AtomicLong();
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
    //Number of EAPOL logoff messages received resulting in disconnected state
    private AtomicLong eapolLogoffRx = new AtomicLong();
    //Number of authenticated transitions due to successful authentication
    private AtomicLong eapolAuthSuccessTrans = new AtomicLong();
    //Number of transitions to held due to authentication failure
    private AtomicLong eapolAuthFailureTrans = new AtomicLong();
    //Number of transitions to connecting due to start request
    private AtomicLong eapolStartReqTrans = new AtomicLong();
    //MD5 Response Challenge
    private AtomicLong eapolMd5RspChall = new AtomicLong();
    //Tls Response Challenge
    private AtomicLong eapolTlsRespChall = new AtomicLong();
    //Number of transitions to response (received response other that NAK)
    private AtomicLong eapolTransRespNotNak = new AtomicLong();
    //Number of EAP request packets sent due to the authenticator choosing the EAP method
    private AtomicLong eapPktTxauthChooseEap = new AtomicLong();
    //Attr Identity
    private AtomicLong eapolAttrIdentity = new AtomicLong();
    //Number of authenticating transitions due to EAP response or identity message
    private AtomicLong eapolResIdentityMsgTrans = new AtomicLong();
    //Current number of EAPOL frames transmitted
    private AtomicLong eapolFramesTx = new AtomicLong();
    //Authenticator state when idle
    private AtomicLong authStateIdle = new AtomicLong();
    //Number of request ID EAP frames transmitted
    private AtomicLong requestIdFramesTx = new AtomicLong();
    //Current number of request EAP frames transmitted
    private AtomicLong reqEapFramesTx = new AtomicLong();
    //Number of EAPOL frames received with invalid packet type
    private AtomicLong invalidPktType = new AtomicLong();
    //Number of EAPOL frames received with invalid body length
    private AtomicLong invalidBodyLength = new AtomicLong();
    //number of valid EAPOL frames received
    private AtomicLong validEapolFramesRx = new AtomicLong();
    //Number of request pending response from supplicant
    private AtomicLong pendingResSupp = new AtomicLong();

    public Long getEapolResIdentityMsgTrans() {
        return eapolResIdentityMsgTrans.get();
    }

    public Long getEapolattrIdentity() {
        return eapolAttrIdentity.get();
    }

    public Long getEapPktTxauthChooseEap() {
        return eapPktTxauthChooseEap.get();
    }

    public Long getEapolTransRespNotNak() {
        return eapolTransRespNotNak.get();
    }

    public Long getEapolMd5RspChall() {
        return eapolMd5RspChall.get();
    }

    public Long getEapolTlsRespChall() {
        return eapolTlsRespChall.get();
    }

    public Long getEapolLogoffRx() {
        return eapolLogoffRx.get();
    }

    public Long getEapolAuthSuccessTrans() {
        return eapolAuthSuccessTrans.get();
    }

    public Long getEapolAuthFailureTrans() {
        return eapolAuthFailureTrans.get();
    }

    public Long getEapolStartReqTrans() {
        return eapolStartReqTrans.get();
    }

    private LinkedList<Long> packetRoundTripTimeList = new LinkedList<Long>();

    public Long getPendingResSupp() {
        return pendingResSupp.get();
    }

    public Long getValidEapolFramesRx() {
        return validEapolFramesRx.get();
    }

    public Long getInvalidBodyLength() {
        return invalidBodyLength.get();
    }

    public Long getInvalidPktType() {
        return invalidPktType.get();
    }

    public Long getRequestIdFramesTx() {
        return requestIdFramesTx.get();
    }

    public Long getReqEapFramesTx() {
        return reqEapFramesTx.get();
    }

    public Long getAuthStateIdle() {
        return authStateIdle.get();
    }

    public Long getEapolFramesTx() {
        return eapolFramesTx.get();
    }

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

    public void incrementInvalidPktType() {
        invalidPktType.incrementAndGet();
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

    public void incrementEapolLogoffRx() {
        eapolLogoffRx.incrementAndGet();
    }

    public void incrementEapolAuthSuccessTrans() {
        eapolAuthSuccessTrans.incrementAndGet();
    }

    public void incrementEapolauthFailureTrans() {
        eapolAuthFailureTrans.incrementAndGet();
    }

    public void incrementEapolStartReqTrans() {
        eapolStartReqTrans.incrementAndGet();
    }

    public void incrementEapolMd5RspChall() {
        eapolMd5RspChall.incrementAndGet();
    }

    public void incrementEapolAtrrIdentity() {
        eapolAttrIdentity.incrementAndGet();
    }

    public void incrementEapolTlsRespChall() {
        eapolTlsRespChall.incrementAndGet();
    }

    public void incrementEapolFramesTx() {
        eapolFramesTx.incrementAndGet();
    }

    public void incrementAuthStateIdle() {
        authStateIdle.incrementAndGet();
    }

    public void incrementRequestIdFramesTx() {
        requestIdFramesTx.incrementAndGet();
    }

    public void incrementInvalidBodyLength() {
        invalidBodyLength.incrementAndGet();
    }

    public void incrementValidEapolFramesRx() {
        validEapolFramesRx.incrementAndGet();
    }

    public void incrementPendingResSupp() {
        pendingResSupp.incrementAndGet();
    }

    public void decrementPendingResSupp() {
        pendingResSupp.decrementAndGet();
    }

    public void countDroppedResponsesRx() {
        long numberOfDroppedPackets = invalidValidatorsRx.get();
        numberOfDroppedPackets += unknownTypeRx.get();
        numberOfDroppedPackets += malformedResponsesRx.get();
        numberOfDroppedPackets += numberOfSessionsExpired.get();
        this.droppedResponsesRx = new AtomicLong(numberOfDroppedPackets);
    }

    public void countReqEapFramesTx() {
        long noReqEapFramesTx = requestIdFramesTx.get();
        noReqEapFramesTx += challengeResponsesRx.get();
        this.reqEapFramesTx = new AtomicLong(noReqEapFramesTx);
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
        eapolLogoffRx.set(0);
        eapolAuthSuccessTrans.set(0);
        eapolAuthFailureTrans.set(0);
        eapolStartReqTrans.set(0);
        eapolTransRespNotNak.set(0);
        eapPktTxauthChooseEap.set(0);
        eapolResIdentityMsgTrans.set(0);
        eapolFramesTx.set(0);
        authStateIdle.set(0);
        requestIdFramesTx.set(0);
        reqEapFramesTx.set(0);
        invalidPktType.set(0);
        invalidBodyLength.set(0);
        validEapolFramesRx.set(0);
        pendingResSupp.set(0);
        timedOutPackets.set(0);

    }
    public void countTransRespNotNak() {
        long eapolTransactionNotNak = eapolMd5RspChall.get();
        eapolTransactionNotNak += eapolTlsRespChall.get();
        this.eapolTransRespNotNak = new AtomicLong(eapolTransactionNotNak);
    }

    public void countEapolResIdentityMsgTrans() {
        long authTransaction = eapolMd5RspChall.get();
        authTransaction += eapolTlsRespChall.get();
        authTransaction += eapolAttrIdentity.get();
        this.eapolResIdentityMsgTrans = new AtomicLong(authTransaction);
    }

    public void incrementEapPktTxauthEap() {
        eapPktTxauthChooseEap.incrementAndGet();
    }

    public long getTimedOutPackets() {
        return timedOutPackets.get();
    }

    public void increaseTimedOutPackets() {
        timedOutPackets.incrementAndGet();
    }

}
