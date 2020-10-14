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

import java.util.Arrays;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

/**
 * Records metrics for the AAA application.
 */
public class AaaStatistics {
    public static final String RADIUS_ACCEPT_RESPONSES_RX = "radiusAccessAcceptRx";
    public static final String RADIUS_REJECT_RESPONSES_RX = "radiusRejectResponsesRx";
    public static final String RADIUS_CHALLENGE_RESPONSES_RX = "radiusAccessChallengeRx";
    public static final String RADIUS_ACCESS_REQUESTS_TX = "radiusAccessRequestTx";
    public static final String RADIUS_ACCESS_REQUESTS_IDENTITY_TX = "radiusAccessRequestIdentityTx";
    public static final String RADIUS_ACCESS_REQUESTS_CHALLENGE_TX = "radiusAccessRequestChallengeTx";
    public static final String RADIUS_PENDING_REQUESTS = "radiusPendingRequests";
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
    public static final String EAPOL_AUTH_SUCCESS_TX = "eapolAuthSuccessTx";
    public static final String EAPOL_AUTH_FAILURE_TX = "eapolAuthFailureTrans";
    public static final String EAPOL_START_REQ_RX = "eapolStartRequestRx";
    public static final String EAPOL_MD5_CHALLENGE_RESP_RX = "eapolMd5ChallengeResponseRx";
    public static final String EAPOL_TLS_CHALLENGE_RESP = "eapolTlsRespChallenge";
    public static final String EAPOL_TRANS_RESP_NOT_NAK = "eapolTransRespNotNak";
    public static final String EAPOL_CHALLENGE_REQ_TX = "eapolChallengeRequestTx";
    public static final String EAPOL_ID_RESP_FRAMES_RX = "eapolIdentityResponseRx";
    public static final String EAPOL_ID_MSG_RESP_TX = "eapolIdentityMsgResponseTx";
    public static final String EAPOL_FRAMES_TX = "eapolFramesTx";
    public static final String AUTH_STATE_IDLE = "authStateIdle";
    public static final String EAPOL_ID_REQUEST_FRAMES_TX = "eapolIdentityRequestTx";
    public static final String EAPOL_REQUEST_FRAMES_TX = "eapolRequestAuthTx";
    public static final String INVALID_PKT_TYPE = "invalidPktType";
    public static final String INVALID_BODY_LENGTH = "invalidBodyLength";
    public static final String EAPOL_VALID_FRAMES_RX = "eapolValidFramesRx";
    public static final String EAPOL_PENDING_REQUESTS = "eapolPendingRequests";

    // this are the stats that represent a successful EAPOL exchange
    public static final String[] EAPOL_SM_NAMES = new String[]{
            EAPOL_START_REQ_RX,

            EAPOL_ID_REQUEST_FRAMES_TX,
            EAPOL_ID_RESP_FRAMES_RX,

            RADIUS_ACCESS_REQUESTS_IDENTITY_TX,
            RADIUS_CHALLENGE_RESPONSES_RX,

            EAPOL_CHALLENGE_REQ_TX,
            EAPOL_MD5_CHALLENGE_RESP_RX,

            RADIUS_ACCESS_REQUESTS_CHALLENGE_TX,
            RADIUS_ACCEPT_RESPONSES_RX,

            EAPOL_AUTH_SUCCESS_TX,
    };

    // all other EAPOL Stats
    public static final String[] EAPOL_STATS_NAMES = new String[]{
            EAPOL_REQUEST_FRAMES_TX,
            RADIUS_ACCESS_REQUESTS_TX,
            RADIUS_REJECT_RESPONSES_RX,
            RADIUS_PENDING_REQUESTS,
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
            EAPOL_AUTH_FAILURE_TX,
            EAPOL_TLS_CHALLENGE_RESP,
            EAPOL_TRANS_RESP_NOT_NAK,
            EAPOL_ID_MSG_RESP_TX,
            EAPOL_FRAMES_TX,
            AUTH_STATE_IDLE,
            INVALID_PKT_TYPE,
            INVALID_BODY_LENGTH,
            EAPOL_VALID_FRAMES_RX,
            EAPOL_PENDING_REQUESTS,
    };

    public static final String[] COUNTER_NAMES =
            Stream.concat(Arrays.stream(EAPOL_SM_NAMES), Arrays.stream(EAPOL_STATS_NAMES))
            .toArray(String[]::new);

    // Number of access accept packets sent to the server
    private AtomicLong radiusAcceptResponsesRx = new AtomicLong();
    // Number of access reject packets sent to the server
    private AtomicLong radiusRejectResponsesRx = new AtomicLong();
    // Number of access challenge packets sent to the server
    private AtomicLong radiusChallengeResponsesRx = new AtomicLong();
    // Number of access request packets sent to the server
    private AtomicLong radiusAccessRequestsTx = new AtomicLong();
    // Number of identity request packets sent to the server
    private AtomicLong radiusAccessRequestsIdentityTx = new AtomicLong();
    // Number of challenge request packets sent to the server
    private AtomicLong radiusAccessRequestsChallengeTx = new AtomicLong();
    // Number of access request packets pending a response from the server
    private AtomicLong radiusPendingRequests = new AtomicLong();
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
    private AtomicLong eapolAuthSuccessTx = new AtomicLong();
    //Number of transitions to held due to authentication failure
    private AtomicLong eapolAuthFailureTx = new AtomicLong();
    //Number of transitions to connecting due to start request
    private AtomicLong eapolStartReqRx = new AtomicLong();
    //MD5 Response Challenge
    private AtomicLong eapolMd5ChallRespRx = new AtomicLong();
    //Tls Response Challenge
    private AtomicLong eapolTlsChallResp = new AtomicLong();
    //Number of transitions to response (received response other that NAK)
    private AtomicLong eapolTransRespNotNak = new AtomicLong();
    //Number of EAP request packets sent due to the authenticator choosing the EAP method
    private AtomicLong eapolChallengeReqTx = new AtomicLong();
    //Attr Identity
    private AtomicLong eapolAttrIdentity = new AtomicLong();
    //Number of authenticating transitions due to EAP response or identity message
    private AtomicLong eapolResIdentityMsgTrans = new AtomicLong();
    //Current number of EAPOL frames transmitted
    private AtomicLong eapolFramesTx = new AtomicLong();
    //Authenticator state when idle
    private AtomicLong authStateIdle = new AtomicLong();
    //Number of request ID EAP frames transmitted
    private AtomicLong eapolIdRequestFramesTx = new AtomicLong();
    //Current number of request EAP frames transmitted
    private AtomicLong eapolReqFramesTx = new AtomicLong();
    //Number of EAPOL frames received with invalid packet type
    private AtomicLong invalidPktType = new AtomicLong();
    //Number of EAPOL frames received with invalid body length
    private AtomicLong invalidBodyLength = new AtomicLong();
    //number of valid EAPOL frames received
    private AtomicLong eapolValidFramesRx = new AtomicLong();
    //Number of request pending response from supplicant
    private AtomicLong eapolPendingReq = new AtomicLong();

    public Long getEapolResIdentityMsgTrans() {
        return eapolResIdentityMsgTrans.get();
    }

    public Long getEapolattrIdentity() {
        return eapolAttrIdentity.get();
    }

    public Long getEapolChallengeReqTx() {
        return eapolChallengeReqTx.get();
    }

    public Long getEapolTransRespNotNak() {
        return eapolTransRespNotNak.get();
    }

    public Long getEapolMd5ChallRespRx() {
        return eapolMd5ChallRespRx.get();
    }

    public Long getEapolTlsChallResp() {
        return eapolTlsChallResp.get();
    }

    public Long getEapolLogoffRx() {
        return eapolLogoffRx.get();
    }

    public Long getEapolAuthSuccessTx() {
        return eapolAuthSuccessTx.get();
    }

    public Long getEapolAuthFailureTx() {
        return eapolAuthFailureTx.get();
    }

    public Long getEapolStartReqRx() {
        return eapolStartReqRx.get();
    }

    private LinkedList<Long> packetRoundTripTimeList = new LinkedList<Long>();

    public Long getEapolPendingReq() {
        return eapolPendingReq.get();
    }

    public Long getEapolValidFramesRx() {
        return eapolValidFramesRx.get();
    }

    public Long getInvalidBodyLength() {
        return invalidBodyLength.get();
    }

    public Long getInvalidPktType() {
        return invalidPktType.get();
    }

    public Long getEapolIdRequestFramesTx() {
        return eapolIdRequestFramesTx.get();
    }

    public Long getEapolReqFramesTx() {
        return eapolReqFramesTx.get();
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

    public Long getRadiusAcceptResponsesRx() {
        return radiusAcceptResponsesRx.get();
    }

    public Long getRadiusRejectResponsesRx() {
        return radiusRejectResponsesRx.get();
    }

    public Long getRadiusChallengeResponsesRx() {
        return radiusChallengeResponsesRx.get();
    }

    public Long getRadiusAccessRequestsTx() {
        return radiusAccessRequestsTx.get();
    }

    public Long getRadiusPendingRequests() {
        return radiusPendingRequests.get();
    }

    public Long getUnknownTypeRx() {
        return unknownTypeRx.get();
    }

    public void increaseAcceptResponsesRx() {
        radiusAcceptResponsesRx.incrementAndGet();
    }

    public void increaseRejectResponsesRx() {
        radiusRejectResponsesRx.incrementAndGet();
    }

    public void increaseChallengeResponsesRx() {
        radiusChallengeResponsesRx.incrementAndGet();
    }

    public void increaseAccessRequestsTx() {
        radiusAccessRequestsTx.incrementAndGet();
    }

    public void increaseRequestReTx() {
        requestReTx.incrementAndGet();
    }

    public void incrementInvalidPktType() {
        invalidPktType.incrementAndGet();
    }

    public void increaseOrDecreasePendingRequests(boolean isIncrement) {
        if (isIncrement) {
            radiusPendingRequests.incrementAndGet();
        } else {
            radiusPendingRequests.decrementAndGet();
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
        eapolAuthSuccessTx.incrementAndGet();
    }

    public void incrementEapolauthFailureTrans() {
        eapolAuthFailureTx.incrementAndGet();
    }

    public void incrementEapolStartReqRx() {
        eapolStartReqRx.incrementAndGet();
    }

    public void incrementEapolMd5RspChall() {
        eapolMd5ChallRespRx.incrementAndGet();
    }

    public void incrementEapolAtrrIdentity() {
        eapolAttrIdentity.incrementAndGet();
    }

    public void incrementEapolTlsRespChall() {
        eapolTlsChallResp.incrementAndGet();
    }

    public void incrementEapolFramesTx() {
        eapolFramesTx.incrementAndGet();
    }

    public void incrementAuthStateIdle() {
        authStateIdle.incrementAndGet();
    }

    public void incrementRequestIdFramesTx() {
        eapolIdRequestFramesTx.incrementAndGet();
    }

    public void incrementInvalidBodyLength() {
        invalidBodyLength.incrementAndGet();
    }

    public void incrementValidEapolFramesRx() {
        eapolValidFramesRx.incrementAndGet();
    }

    public void incrementPendingReqSupp() {
        eapolPendingReq.incrementAndGet();
    }

    public void decrementPendingReqSupp() {
        eapolPendingReq.decrementAndGet();
    }

    public void countDroppedResponsesRx() {
        long numberOfDroppedPackets = invalidValidatorsRx.get();
        numberOfDroppedPackets += unknownTypeRx.get();
        numberOfDroppedPackets += malformedResponsesRx.get();
        numberOfDroppedPackets += numberOfSessionsExpired.get();
        this.droppedResponsesRx = new AtomicLong(numberOfDroppedPackets);
    }

    public void countReqEapFramesTx() {
        long noReqEapFramesTx = eapolIdRequestFramesTx.get();
        noReqEapFramesTx += radiusChallengeResponsesRx.get();
        this.eapolReqFramesTx = new AtomicLong(noReqEapFramesTx);
    }

    public void resetAllCounters() {
        clearPacketRoundTripTimeList();

        radiusAccessRequestsTx.set(0);
        radiusAccessRequestsIdentityTx.set(0);
        radiusAccessRequestsChallengeTx.set(0);
        radiusAcceptResponsesRx.set(0);
        radiusChallengeResponsesRx.set(0);
        droppedResponsesRx.set(0);
        invalidValidatorsRx.set(0);
        malformedResponsesRx.set(0);
        radiusPendingRequests.set(0);
        radiusRejectResponsesRx.set(0);
        requestReTx.set(0);
        requestRttMilis.set(0);
        unknownServerRx.set(0);
        unknownTypeRx.set(0);
        eapolLogoffRx.set(0);
        eapolAuthSuccessTx.set(0);
        eapolAuthFailureTx.set(0);
        eapolStartReqRx.set(0);
        eapolTransRespNotNak.set(0);
        eapolChallengeReqTx.set(0);
        eapolResIdentityMsgTrans.set(0);
        eapolFramesTx.set(0);
        authStateIdle.set(0);
        eapolIdRequestFramesTx.set(0);
        eapolReqFramesTx.set(0);
        invalidPktType.set(0);
        invalidBodyLength.set(0);
        eapolValidFramesRx.set(0);
        eapolPendingReq.set(0);
        timedOutPackets.set(0);
        eapolMd5ChallRespRx.set(0);
        eapolTlsChallResp.set(0);
        eapolAttrIdentity.set(0);
    }

    public void countTransRespNotNak() {
        long eapolTransactionNotNak = eapolMd5ChallRespRx.get();
        eapolTransactionNotNak += eapolTlsChallResp.get();
        this.eapolTransRespNotNak = new AtomicLong(eapolTransactionNotNak);
    }

    public void countEapolResIdentityMsgTrans() {
        long authTransaction = eapolMd5ChallRespRx.get();
        authTransaction += eapolTlsChallResp.get();
        authTransaction += eapolAttrIdentity.get();
        this.eapolResIdentityMsgTrans = new AtomicLong(authTransaction);
    }

    public void incrementEapPktTxauthEap() {
        eapolChallengeReqTx.incrementAndGet();
    }

    public void incrementRadiusReqIdTx() {
        radiusAccessRequestsIdentityTx.incrementAndGet();
    }

    public void incrementRadiusReqChallengeTx() {
        radiusAccessRequestsChallengeTx.incrementAndGet();
    }

    public Long getRadiusReqIdTx() {
        return radiusAccessRequestsIdentityTx.get();
    }

    public Long getRadiusReqChallengeTx() {
        return radiusAccessRequestsChallengeTx.get();
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
        builder.put(RADIUS_ACCEPT_RESPONSES_RX, radiusAcceptResponsesRx.get())
                .put(RADIUS_REJECT_RESPONSES_RX, radiusRejectResponsesRx.get())
                .put(RADIUS_CHALLENGE_RESPONSES_RX, radiusChallengeResponsesRx.get())
                .put(RADIUS_ACCESS_REQUESTS_TX, radiusAccessRequestsTx.get())
                .put(RADIUS_ACCESS_REQUESTS_IDENTITY_TX, radiusAccessRequestsIdentityTx.get())
                .put(RADIUS_ACCESS_REQUESTS_CHALLENGE_TX, radiusAccessRequestsChallengeTx.get())
                .put(RADIUS_PENDING_REQUESTS, radiusPendingRequests.get())
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
                .put(EAPOL_AUTH_SUCCESS_TX, eapolAuthSuccessTx.get())
                .put(EAPOL_AUTH_FAILURE_TX, eapolAuthFailureTx.get())
                .put(EAPOL_START_REQ_RX, eapolStartReqRx.get())
                .put(EAPOL_MD5_CHALLENGE_RESP_RX, eapolMd5ChallRespRx.get())
                .put(EAPOL_TLS_CHALLENGE_RESP, eapolTlsChallResp.get())
                .put(EAPOL_TRANS_RESP_NOT_NAK, eapolTransRespNotNak.get())
                .put(EAPOL_CHALLENGE_REQ_TX, eapolChallengeReqTx.get())
                .put(EAPOL_ID_RESP_FRAMES_RX, eapolAttrIdentity.get())
                .put(EAPOL_ID_MSG_RESP_TX, eapolResIdentityMsgTrans.get())
                .put(EAPOL_FRAMES_TX, eapolFramesTx.get())
                .put(AUTH_STATE_IDLE, authStateIdle.get())
                .put(EAPOL_ID_REQUEST_FRAMES_TX, eapolIdRequestFramesTx.get())
                .put(EAPOL_REQUEST_FRAMES_TX, eapolReqFramesTx.get())
                .put(INVALID_PKT_TYPE, invalidPktType.get())
                .put(INVALID_BODY_LENGTH, invalidBodyLength.get())
                .put(EAPOL_VALID_FRAMES_RX, eapolValidFramesRx.get())
                .put(EAPOL_PENDING_REQUESTS, eapolPendingReq.get());

        return new AaaStatisticsSnapshot(builder.build());
    }

    public static AaaStatistics fromSnapshot(AaaStatisticsSnapshot snapshot) {
        AaaStatistics stats = new AaaStatistics();

        stats.radiusAcceptResponsesRx.set(snapshot.get(RADIUS_ACCEPT_RESPONSES_RX));
        stats.radiusRejectResponsesRx.set(snapshot.get(RADIUS_REJECT_RESPONSES_RX));
        stats.radiusChallengeResponsesRx.set(snapshot.get(RADIUS_CHALLENGE_RESPONSES_RX));
        stats.radiusAccessRequestsTx.set(snapshot.get(RADIUS_ACCESS_REQUESTS_TX));
        stats.radiusAccessRequestsIdentityTx.set(snapshot.get(RADIUS_ACCESS_REQUESTS_IDENTITY_TX));
        stats.radiusAccessRequestsChallengeTx.set(snapshot.get(RADIUS_ACCESS_REQUESTS_CHALLENGE_TX));
        stats.radiusPendingRequests.set(snapshot.get(RADIUS_PENDING_REQUESTS));
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
        stats.eapolAuthSuccessTx.set(snapshot.get(EAPOL_AUTH_SUCCESS_TX));
        stats.eapolAuthFailureTx.set(snapshot.get(EAPOL_AUTH_FAILURE_TX));
        stats.eapolStartReqRx.set(snapshot.get(EAPOL_START_REQ_RX));
        stats.eapolMd5ChallRespRx.set(snapshot.get(EAPOL_MD5_CHALLENGE_RESP_RX));
        stats.eapolTlsChallResp.set(snapshot.get(EAPOL_TLS_CHALLENGE_RESP));
        stats.eapolTransRespNotNak.set(snapshot.get(EAPOL_TRANS_RESP_NOT_NAK));
        stats.eapolChallengeReqTx.set(snapshot.get(EAPOL_CHALLENGE_REQ_TX));
        stats.eapolAttrIdentity.set(snapshot.get(EAPOL_ID_RESP_FRAMES_RX));
        stats.eapolResIdentityMsgTrans.set(snapshot.get(EAPOL_ID_MSG_RESP_TX));
        stats.eapolFramesTx.set(snapshot.get(EAPOL_FRAMES_TX));
        stats.authStateIdle.set(snapshot.get(AUTH_STATE_IDLE));
        stats.eapolIdRequestFramesTx.set(snapshot.get(EAPOL_ID_REQUEST_FRAMES_TX));
        stats.eapolReqFramesTx.set(snapshot.get(EAPOL_REQUEST_FRAMES_TX));
        stats.invalidPktType.set(snapshot.get(INVALID_PKT_TYPE));
        stats.invalidBodyLength.set(snapshot.get(INVALID_BODY_LENGTH));
        stats.eapolValidFramesRx.set(snapshot.get(EAPOL_VALID_FRAMES_RX));
        stats.eapolPendingReq.set(snapshot.get(EAPOL_PENDING_REQUESTS));

        return stats;
    }

    public String toString() {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this.getClass());
        helper.add(RADIUS_ACCEPT_RESPONSES_RX, radiusAcceptResponsesRx.get())
                .add(RADIUS_REJECT_RESPONSES_RX, radiusRejectResponsesRx.get())
                .add(RADIUS_CHALLENGE_RESPONSES_RX, radiusChallengeResponsesRx.get())
                .add(RADIUS_ACCESS_REQUESTS_TX, radiusAccessRequestsTx.get())
                .add(RADIUS_ACCESS_REQUESTS_IDENTITY_TX, radiusAccessRequestsIdentityTx.get())
                .add(RADIUS_ACCESS_REQUESTS_CHALLENGE_TX, radiusAccessRequestsChallengeTx.get())
                .add(RADIUS_PENDING_REQUESTS, radiusPendingRequests.get())
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
                .add(EAPOL_AUTH_SUCCESS_TX, eapolAuthSuccessTx.get())
                .add(EAPOL_AUTH_FAILURE_TX, eapolAuthFailureTx.get())
                .add(EAPOL_START_REQ_RX, eapolStartReqRx.get())
                .add(EAPOL_MD5_CHALLENGE_RESP_RX, eapolMd5ChallRespRx.get())
                .add(EAPOL_TLS_CHALLENGE_RESP, eapolTlsChallResp.get())
                .add(EAPOL_TRANS_RESP_NOT_NAK, eapolTransRespNotNak.get())
                .add(EAPOL_CHALLENGE_REQ_TX, eapolChallengeReqTx.get())
                .add(EAPOL_ID_RESP_FRAMES_RX, eapolAttrIdentity.get())
                .add(EAPOL_ID_MSG_RESP_TX, eapolResIdentityMsgTrans.get())
                .add(EAPOL_FRAMES_TX, eapolFramesTx.get())
                .add(AUTH_STATE_IDLE, authStateIdle.get())
                .add(EAPOL_ID_REQUEST_FRAMES_TX, eapolIdRequestFramesTx.get())
                .add(EAPOL_REQUEST_FRAMES_TX, eapolReqFramesTx.get())
                .add(INVALID_PKT_TYPE, invalidPktType.get())
                .add(INVALID_BODY_LENGTH, invalidBodyLength.get())
                .add(EAPOL_VALID_FRAMES_RX, eapolValidFramesRx.get())
                .add(EAPOL_PENDING_REQUESTS, eapolPendingReq.get());
        return helper.toString();
    }
}
