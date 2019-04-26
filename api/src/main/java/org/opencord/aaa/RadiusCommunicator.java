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
package org.opencord.aaa;

import org.onlab.packet.RADIUS;

import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;

/**
 * Interface to the implementations for RADIUS server side communication.
 */
public interface RadiusCommunicator {

    /**
     * Does initialization required for the implementation to work and applies the
     * relevant part of the passed configuration.
     *
     * @param newCfg : New configuration to be applied
     */
    void initializeLocalState(AaaConfig newCfg);
    /**
     * Clears up all local state.
     */
    void clearLocalState();
    /**
     * Shutdown, called when AAA app is deactivated.
     */
    void deactivate();
    /**
     * Provision intercepts on the switches if needed.
     */
    void requestIntercepts();
    /**
     * Clear intercepts from the switches if needed.
     */
    void withdrawIntercepts();
    /**
     * Send RADIUS packet to the RADIUS server.
     *
     * @param radiusPacket RADIUS packet to be sent to server.
     * @param inPkt        Incoming EAPOL packet
     */
    void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt);
    /**
     * Handle packet from RADIUS server.
     *
     * @param context Incoming packet context.
     */
    void handlePacketFromServer(PacketContext context);
}
