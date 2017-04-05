/*
 * Copyright 2015-present Open Networking Laboratory
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

import org.onosproject.net.device.DeviceService;
import org.onosproject.net.packet.InboundPacket;


/**
 * Default RADIUS Packet Customization.
 * Does not change the packet
 *
 * Subclasses should implement filling of attributes depending on specifics ofsetup/RADIUS server
 */
public class  RadiusPayloadCustomizer {

    DeviceService deviceService;

    public RadiusPayloadCustomizer(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    /**
     * Customize the packet as per specific Setup or RADIUS server requirements.
     *
     * @param inPkt RADIUS packet to be customized
     * @param eapPacket Incoming packet containing EAP for which this the RADIUS message is being created
     * @return Customized RADIUS packet
     */
    public RADIUS customizePacket(RADIUS inPkt, InboundPacket eapPacket) {
        return inPkt;
    }
}
