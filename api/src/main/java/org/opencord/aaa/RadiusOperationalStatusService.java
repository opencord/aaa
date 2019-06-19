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

import org.onlab.packet.RADIUS;
import org.onosproject.event.ListenerService;

/**
 * Service for interacting with operational status module.
 */

public interface RadiusOperationalStatusService extends
             ListenerService<RadiusOperationalStatusEvent, RadiusOperationalStatusEventListener> {
   /**
     * Return RadiusOperationalStatusEventDelegate object.
     *
     * @return RadiusOperationalStatusEventDelegate
    */
    RadiusOperationalStatusEventDelegate getRadiusOprStDelegate();

    /**
     * Return String object.
     *
     * @return String
    */
    String getRadiusServerOperationalStatus();

    /**
     * Set the value of statusServerReqSent flag.
     *
     * @param statusServerReqSent statusServerReqSent flag
    */
    void setStatusServerReqSent(boolean statusServerReqSent);

    /**
     * Set the value of radiusOperationalStatus Evaluation Mode.
     *
     * @param radiusOperationalStatusEvaluationMode radiusOperationalStatusEvaluationMode value
    */
    void setRadiusOperationalStatusEvaluationMode(
            RadiusOperationalStatusEvaluationMode radiusOperationalStatusEvaluationMode);

    /**
     * Set the value of Operational Status Server Timeout In Milliseconds.
     *
     * @param operationalStatusServerTimeoutInMillis operationalStatusServerTimeoutInMillis
    */
    void setOperationalStatusServerTimeoutInMillis(long operationalStatusServerTimeoutInMillis);

    /**
     * Determine the operational status of server.
    */
    void checkServerOperationalStatus();

    /**
     * Check if radius response is for operational status.
     *
     * @param identifier identifier value of radius packet
     * @return boolean
    */
    boolean isRadiusResponseForOperationalStatus(byte identifier);

    /**
     * handle incoming radius packet for operational status.
     *
     * @param radiusPacket radiusPacket of incoming operational status
    */
    void handleRadiusPacketForOperationalStatus(RADIUS radiusPacket);

    /**
     * initialize radiusOperationalStatusService.
     *
     * @param address address of radius server
     * @param secret secret key for radius server
     * @param impl impl of RadiusCommunicator
    */
    void initialize(byte[] address, String secret, RadiusCommunicator impl);

    /**
     * set packet outgoing time in milliseconds.
     *
     * @param identifier identifier of outgoing packet
    */
    void setOutTimeInMillis(byte identifier);

    enum OperationalStatus {
        UNAVAILABLE,
        UNKNOWN,
        IN_USE,
    }

    enum RadiusOperationalStatusEvaluationMode {

        STATUS_REQUEST, ACCESS_REQUEST, AUTO;

        public static RadiusOperationalStatusEvaluationMode getValue(String value) {

            for (RadiusOperationalStatusEvaluationMode mode: RadiusOperationalStatusEvaluationMode.values()) {
                if (mode.toString().equalsIgnoreCase(value)) {
                   return mode;
                }
            }
            return null;
        }
    }

}
