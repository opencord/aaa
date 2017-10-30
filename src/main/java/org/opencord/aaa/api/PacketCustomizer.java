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
package org.opencord.aaa.api;

import org.onlab.packet.Ethernet;
import org.onlab.packet.RADIUS;
import org.onosproject.net.packet.InboundPacket;

/**
 * Facilitates the customization of RADIUS packets.
 * <p>
 * This default implementation does no customization.
 * <p>
 * Subclasses should override the appropriate methods to fill in attributes
 * according to the specifics of the RADIUS server set up.
 */
public class PacketCustomizer {

    /**
     * Customize the packet as per specific setup or RADIUS server requirements.
     * <p>
     * This default implementation returns the packet unaltered.
     *
     * @param inPkt     RADIUS packet to be customized
     * @param eapPacket Incoming packet containing EAP for which this RADIUS
     *                  message is being created
     * @return customized RADIUS packet
     */
    public RADIUS customizePacket(RADIUS inPkt, InboundPacket eapPacket) {
        return inPkt;
    }

    /**
     * Customize the Ethernet header as per specific setup or RADIUS
     * server requirements.
     * <p>
     * This default implementation returns the packet unaltered.
     *
     * @param inPkt     Ethernet packet to be changed
     * @param eapPacket Incoming packet containing EAP for which this RADIUS
     *                  message is being created
     * @return customized Ethernet packet
     */
    public Ethernet customizeEthernetIPHeaders(Ethernet inPkt,
                                               InboundPacket eapPacket) {
        return inPkt;
    }
}