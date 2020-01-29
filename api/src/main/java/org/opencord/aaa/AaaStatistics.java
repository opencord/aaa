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

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Records metrics for the AAA application.
 */
public class AaaStatistics {
    public static final String ACCEPT_RESPONSES_RX = "acceptResponsesRx";
    public static final String REJECT_RESPONSES_RX = "rejectResponsesRx";
    public static final String CHALLENGE_RESPONSES_RX = "challengeResponsesRx";
    public static final String ACCESS_REQUESTS_TX = "accessRequestsTx";
    public static final String PENDING_REQUESTS = "pendingRequests";
    public static final String TIMED_OUT_PACKETS = "timedOutPackets";
    public static final String UNKNOWN_TYPE_RX = "unknownTypeRx";
    public static final String INVALID_VALIDATORS_RX = "invalidValidatorsRx";
    public static final String DROPPED_RESPONSES_RX = "droppedResponsesRx";
    public static final String MALFORMED_RESPONSES_RX = "malformedResponsesRx";
    public static final String UNKNOWN_SERVER_RX = "unknownServerRx";
    public static final String REQUEST_RTT_MILLIS = "requestRttMillis";
    public static final String REQUEST_RE_TX = "requestReTx";
    public static final String NUM_SESSIONS_EXPIRED = "numSessionsExpired";
    public static final String EAPOL_LOGOFF_RX = "eapolLogoffRx";
    public static final String EAPOL_AUTH_SUCCESS_TRANS = "eapolAuthSuccessTrans";
    public static final String EAPOL_AUTH_FAILURE_TRANS = "eapolAuthFailureTrans";
    public static final String EAPOL_START_REQ_TRANS = "eapolStartReqTrans";
    public static final String EAPOL_MD5_RESP_CHALLENGE = "eapolMd5RespChallenge";
    public static final String EAPOL_TLS_RESP_CHALLENGE = "eapolTlsRespChallenge";
    public static final String EAPOL_TRANS_RESP_NOT_NAK = "eapolTransRespNotNak";
    public static final String EAP_PKT_TX_AUTH_CHOOSE_EAP = "eapPktTxauthChooseEap";
    public static final String RES_ID_EAP_FRAMES_RX = "resIdEapFramesRx";
    public static final String EAPOL_RES_IDENTITY_MSG_TRANS = "eapolResIdentityMsgTrans";
    public static final String EAPOL_FRAMES_TX = "eapolFramesTx";
    public static final String AUTH_STATE_IDLE = "authStateIdle";
    public static final String REQUEST_ID_FRAMES_TX = "requestIdFramesTx";
    public static final String REQUEST_EAP_FRAMES_TX = "requestEapFramesTx";
    public static final String INVALID_PKT_TYPE = "invalidPktType";
    public static final String INVALID_BODY_LENGTH = "invalidBodyLength";
    public static final String VALID_EAPOL_FRAMES_RX = "validEapolFramesRx";
    public static final String PENDING_RES_SUPPLICANT = "pendingResSupplicant";

    public static final String[] COUNTER_NAMES = new String[]{
            ACCEPT_RESPONSES_RX,
            REJECT_RESPONSES_RX,
            CHALLENGE_RESPONSES_RX,
            ACCESS_REQUESTS_TX,
            PENDING_REQUESTS,
            TIMED_OUT_PACKETS,
            UNKNOWN_TYPE_RX,
            INVALID_VALIDATORS_RX,
            DROPPED_RESPONSES_RX,
            MALFORMED_RESPONSES_RX,
            UNKNOWN_SERVER_RX,
            REQUEST_RTT_MILLIS,
            REQUEST_RE_TX,
            NUM_SESSIONS_EXPIRED,
            EAPOL_LOGOFF_RX,
            EAPOL_AUTH_SUCCESS_TRANS,
            EAPOL_AUTH_FAILURE_TRANS,
            EAPOL_START_REQ_TRANS,
            EAPOL_MD5_RESP_CHALLENGE,
            EAPOL_TLS_RESP_CHALLENGE,
            EAPOL_TRANS_RESP_NOT_NAK,
            EAP_PKT_TX_AUTH_CHOOSE_EAP,
            RES_ID_EAP_FRAMES_RX,
            EAPOL_RES_IDENTITY_MSG_TRANS,
            EAPOL_FRAMES_TX,
            AUTH_STATE_IDLE,
            REQUEST_ID_FRAMES_TX,
            REQUEST_EAP_FRAMES_TX,
            INVALID_PKT_TYPE,
            INVALID_BODY_LENGTH,
            VALID_EAPOL_FRAMES_RX,
            PENDING_RES_SUPPLICANT,
    };

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
        eapolMd5RspChall.set(0);
        eapolTlsRespChall.set(0);
        eapolAttrIdentity.set(0);
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

    /**
     * Creates a snapshot of the current values of the counters.
     *
     * @return statistics snapshot
     */
    public AaaStatisticsSnapshot snapshot() {
        ImmutableMap.Builder<String, Long> builder = ImmutableMap.builder();
        builder.put(ACCEPT_RESPONSES_RX, acceptResponsesRx.get())
                .put(REJECT_RESPONSES_RX, rejectResponsesRx.get())
                .put(CHALLENGE_RESPONSES_RX, challengeResponsesRx.get())
                .put(ACCESS_REQUESTS_TX, accessRequestsTx.get())
                .put(PENDING_REQUESTS, pendingRequests.get())
                .put(TIMED_OUT_PACKETS, timedOutPackets.get())
                .put(UNKNOWN_TYPE_RX, unknownTypeRx.get())
                .put(INVALID_VALIDATORS_RX, invalidValidatorsRx.get())
                .put(DROPPED_RESPONSES_RX, droppedResponsesRx.get())
                .put(MALFORMED_RESPONSES_RX, malformedResponsesRx.get())
                .put(UNKNOWN_SERVER_RX, unknownServerRx.get())
                .put(REQUEST_RTT_MILLIS, requestRttMilis.get())
                .put(REQUEST_RE_TX, requestReTx.get())
                .put(NUM_SESSIONS_EXPIRED, numberOfSessionsExpired.get())
                .put(EAPOL_LOGOFF_RX, eapolLogoffRx.get())
                .put(EAPOL_AUTH_SUCCESS_TRANS, eapolAuthSuccessTrans.get())
                .put(EAPOL_AUTH_FAILURE_TRANS, eapolAuthFailureTrans.get())
                .put(EAPOL_START_REQ_TRANS, eapolStartReqTrans.get())
                .put(EAPOL_MD5_RESP_CHALLENGE, eapolMd5RspChall.get())
                .put(EAPOL_TLS_RESP_CHALLENGE, eapolTlsRespChall.get())
                .put(EAPOL_TRANS_RESP_NOT_NAK, eapolTransRespNotNak.get())
                .put(EAP_PKT_TX_AUTH_CHOOSE_EAP, eapPktTxauthChooseEap.get())
                .put(RES_ID_EAP_FRAMES_RX, eapolAttrIdentity.get())
                .put(EAPOL_RES_IDENTITY_MSG_TRANS, eapolResIdentityMsgTrans.get())
                .put(EAPOL_FRAMES_TX, eapolFramesTx.get())
                .put(AUTH_STATE_IDLE, authStateIdle.get())
                .put(REQUEST_ID_FRAMES_TX, requestIdFramesTx.get())
                .put(REQUEST_EAP_FRAMES_TX, reqEapFramesTx.get())
                .put(INVALID_PKT_TYPE, invalidPktType.get())
                .put(INVALID_BODY_LENGTH, invalidBodyLength.get())
                .put(VALID_EAPOL_FRAMES_RX, validEapolFramesRx.get())
                .put(PENDING_RES_SUPPLICANT, pendingResSupp.get());

        return new AaaStatisticsSnapshot(builder.build());
    }

    public static AaaStatistics fromSnapshot(AaaStatisticsSnapshot snapshot) {
        AaaStatistics stats = new AaaStatistics();

        stats.acceptResponsesRx.set(snapshot.get(ACCEPT_RESPONSES_RX));
        stats.rejectResponsesRx.set(snapshot.get(REJECT_RESPONSES_RX));
        stats.challengeResponsesRx.set(snapshot.get(CHALLENGE_RESPONSES_RX));
        stats.accessRequestsTx.set(snapshot.get(ACCESS_REQUESTS_TX));
        stats.pendingRequests.set(snapshot.get(PENDING_REQUESTS));
        stats.timedOutPackets.set(snapshot.get(TIMED_OUT_PACKETS));
        stats.unknownTypeRx.set(snapshot.get(UNKNOWN_TYPE_RX));
        stats.invalidValidatorsRx.set(snapshot.get(INVALID_VALIDATORS_RX));
        stats.droppedResponsesRx.set(snapshot.get(DROPPED_RESPONSES_RX));
        stats.malformedResponsesRx.set(snapshot.get(MALFORMED_RESPONSES_RX));
        stats.unknownServerRx.set(snapshot.get(UNKNOWN_SERVER_RX));
        stats.requestRttMilis.set(snapshot.get(REQUEST_RTT_MILLIS));
        stats.requestReTx.set(snapshot.get(REQUEST_RE_TX));
        stats.numberOfSessionsExpired.set(snapshot.get(NUM_SESSIONS_EXPIRED));
        stats.eapolLogoffRx.set(snapshot.get(EAPOL_LOGOFF_RX));
        stats.eapolAuthSuccessTrans.set(snapshot.get(EAPOL_AUTH_SUCCESS_TRANS));
        stats.eapolAuthFailureTrans.set(snapshot.get(EAPOL_AUTH_FAILURE_TRANS));
        stats.eapolStartReqTrans.set(snapshot.get(EAPOL_START_REQ_TRANS));
        stats.eapolMd5RspChall.set(snapshot.get(EAPOL_MD5_RESP_CHALLENGE));
        stats.eapolTlsRespChall.set(snapshot.get(EAPOL_TLS_RESP_CHALLENGE));
        stats.eapolTransRespNotNak.set(snapshot.get(EAPOL_TRANS_RESP_NOT_NAK));
        stats.eapPktTxauthChooseEap.set(snapshot.get(EAP_PKT_TX_AUTH_CHOOSE_EAP));
        stats.eapolAttrIdentity.set(snapshot.get(RES_ID_EAP_FRAMES_RX));
        stats.eapolResIdentityMsgTrans.set(snapshot.get(EAPOL_RES_IDENTITY_MSG_TRANS));
        stats.eapolFramesTx.set(snapshot.get(EAPOL_FRAMES_TX));
        stats.authStateIdle.set(snapshot.get(AUTH_STATE_IDLE));
        stats.requestIdFramesTx.set(snapshot.get(REQUEST_ID_FRAMES_TX));
        stats.reqEapFramesTx.set(snapshot.get(REQUEST_EAP_FRAMES_TX));
        stats.invalidPktType.set(snapshot.get(INVALID_PKT_TYPE));
        stats.invalidBodyLength.set(snapshot.get(INVALID_BODY_LENGTH));
        stats.validEapolFramesRx.set(snapshot.get(VALID_EAPOL_FRAMES_RX));
        stats.pendingResSupp.set(snapshot.get(PENDING_RES_SUPPLICANT));

        return stats;
    }

    public String toString() {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this.getClass());
        helper.add(ACCEPT_RESPONSES_RX, acceptResponsesRx.get())
                .add(REJECT_RESPONSES_RX, rejectResponsesRx.get())
                .add(CHALLENGE_RESPONSES_RX, challengeResponsesRx.get())
                .add(ACCESS_REQUESTS_TX, accessRequestsTx.get())
                .add(PENDING_REQUESTS, pendingRequests.get())
                .add(TIMED_OUT_PACKETS, timedOutPackets.get())
                .add(UNKNOWN_TYPE_RX, unknownTypeRx.get())
                .add(INVALID_VALIDATORS_RX, invalidValidatorsRx.get())
                .add(DROPPED_RESPONSES_RX, droppedResponsesRx.get())
                .add(MALFORMED_RESPONSES_RX, malformedResponsesRx.get())
                .add(UNKNOWN_SERVER_RX, unknownServerRx.get())
                .add(REQUEST_RTT_MILLIS, requestRttMilis.get())
                .add(REQUEST_RE_TX, requestReTx.get())
                .add(NUM_SESSIONS_EXPIRED, numberOfSessionsExpired.get())
                .add(EAPOL_LOGOFF_RX, eapolLogoffRx.get())
                .add(EAPOL_AUTH_SUCCESS_TRANS, eapolAuthSuccessTrans.get())
                .add(EAPOL_AUTH_FAILURE_TRANS, eapolAuthFailureTrans.get())
                .add(EAPOL_START_REQ_TRANS, eapolStartReqTrans.get())
                .add(EAPOL_MD5_RESP_CHALLENGE, eapolMd5RspChall.get())
                .add(EAPOL_TLS_RESP_CHALLENGE, eapolTlsRespChall.get())
                .add(EAPOL_TRANS_RESP_NOT_NAK, eapolTransRespNotNak.get())
                .add(EAP_PKT_TX_AUTH_CHOOSE_EAP, eapPktTxauthChooseEap.get())
                .add(RES_ID_EAP_FRAMES_RX, eapolAttrIdentity.get())
                .add(EAPOL_RES_IDENTITY_MSG_TRANS, eapolResIdentityMsgTrans.get())
                .add(EAPOL_FRAMES_TX, eapolFramesTx.get())
                .add(AUTH_STATE_IDLE, authStateIdle.get())
                .add(REQUEST_ID_FRAMES_TX, requestIdFramesTx.get())
                .add(REQUEST_EAP_FRAMES_TX, reqEapFramesTx.get())
                .add(INVALID_PKT_TYPE, invalidPktType.get())
                .add(INVALID_BODY_LENGTH, invalidBodyLength.get())
                .add(VALID_EAPOL_FRAMES_RX, validEapolFramesRx.get())
                .add(PENDING_RES_SUPPLICANT, pendingResSupp.get());
        return helper.toString();
    }

}
