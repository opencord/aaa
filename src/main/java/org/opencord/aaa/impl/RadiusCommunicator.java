/*
 * Copyright 2017-present Open Networking Foundation
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

import org.onlab.packet.RADIUS;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.opencord.aaa.api.AaaConfig;

/**
 * Interface to the implementations for RADIUS server side communication.
 */
public interface RadiusCommunicator {

    /**
     * Initializes the local state of the communicator, using the relevant
     * parameters from the supplied configuration.
     *
     * @param newCfg new configuration to be applied
     */
    void initializeLocalState(AaaConfig newCfg);

    /**
     * Clears local state.
     */
    void clearLocalState();

    /**
     * Callback invoked when the AAA application is deactivated.
     */
    void deactivate();

    /**
     * Provisions intercepts on the switches (if needed).
     */
    void requestIntercepts();

    /**
     * Clears intercepts from the switches (if needed).
     */
    void withdrawIntercepts();

    /**
     * Sends the given RADIUS packet to the RADIUS server. The incoming
     * EAPOL packet (from the switch to ONOS) is provided as reference.
     *
     * @param radiusPacket RADIUS packet to be sent to server
     * @param inPkt        incoming EAPOL packet
     */
    void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt);

    /**
     * Handles the packet from RADIUS server.
     *
     * @param context incoming packet context
     */
    void handlePacketFromServer(PacketContext context);
}
