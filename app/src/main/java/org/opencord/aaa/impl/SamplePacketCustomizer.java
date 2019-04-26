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

import static org.slf4j.LoggerFactory.getLogger;

import java.nio.ByteBuffer;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.Port;
import org.onosproject.net.packet.InboundPacket;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.slf4j.Logger;


/**
 * Sample RADIUS Packet Customization.
 *
 */
public class  SamplePacketCustomizer extends PacketCustomizer {

    private final Logger log = getLogger(getClass());

    public SamplePacketCustomizer(CustomizationInfo customInfo) {
        super(customInfo);
    }

    /**
     * Determines if NAS IP Attribute should be updated or not.
     *
     * @return true if updating NAS IP is desired
     */
    protected boolean updateNasIp() {
        return true;
    }

    /**
     * Customize the packet as per specific Setup or RADIUS
     * server requirements.
     *
     * @param inPkt RADIUS packet to be customized
     * @param eapPacket Incoming packet containing EAP for which this the
     *                  RADIUS message is being created
     * @return Customized RADIUS packet
     */
    @Override
    public RADIUS customizePacket(RADIUS inPkt, InboundPacket eapPacket) {
        Port p = customInfo.deviceService().getPort(eapPacket.receivedFrom());

        String id = p.annotations().value(AnnotationKeys.PORT_NAME);

        log.info("Customizing packet Port received for {}", id);

        SubscriberAndDeviceInformation subscriber = customInfo.
                subscriberService().get(id);

        if (subscriber == null) {
            log.warn("No subscriber found with id {}", id);
            return inPkt;
        }

        String nasPortId = subscriber.nasPortId();

        Ethernet ethPkt = eapPacket.parsed();
        MacAddress srcMac = ethPkt.getSourceMAC();

        // Get the nasId from subscriber service using the Serial Number
        String serialNo = customInfo.deviceService().getDevice(eapPacket.
                receivedFrom().deviceId()).serialNumber();

        log.info("SampleRadiusCustomizer serial = {}", serialNo);
        SubscriberAndDeviceInformation deviceInfo = customInfo.
                subscriberService().get(serialNo);

        if (deviceInfo == null) {
            log.warn("No Device found with SN {}", serialNo);
            return inPkt;
        }
        String nodeName = deviceInfo.nasId();

        log.info("Setting nasId={} nasPortId{}", nodeName, nasPortId);

        if (updateNasIp()) {
            inPkt.updateAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_IP,
                                  deviceInfo.ipAddress().toOctets());
        }

        inPkt.setAttribute(RADIUSAttribute.RADIUS_ATTR_CALLING_STATION_ID,
                srcMac.toBytes());

        // Check value - 16 was used in PoC2, as per PoC3 TS value should be 15
        inPkt.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_PORT_TYPE,
                ByteBuffer.allocate(4).putInt(15).array());

        inPkt.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_PORT,
                ByteBuffer.allocate(4).putInt((int) p.number().toLong()).array());
        // Check - If this is needed, worked with this value in PoC2
        inPkt.setAttribute(RADIUSAttribute.RADIUS_ATTR_ACCT_SESSION_ID,
                "023:27:46:00000".getBytes());

        inPkt.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_ID,
                nodeName.getBytes());
        inPkt.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_PORT_ID,
                nasPortId.getBytes());

        return inPkt;
    }

    /**
     * Customize the Ethernet header as per specific Setup or RADIUS
     * server requirements.
     *
     * @param inPkt Ethernet packet to be changed
     * @param eapPacket Incoming packet containing EAP for which this the
     *                  RADIUS message is being created
     * @return Changed Ethernet packet
     */
    @Override
    public Ethernet customizeEthernetIPHeaders(Ethernet inPkt,
                                               InboundPacket eapPacket) {

        String serialNo = customInfo.deviceService().getDevice(eapPacket.
                receivedFrom().deviceId()).serialNumber();

        log.info("SampleRadiusCustomzer customizer serial = {}", serialNo);
        SubscriberAndDeviceInformation deviceInfo = customInfo.
                subscriberService().get(serialNo);

        if (deviceInfo == null) {
            log.warn("No Device found with SN {}", serialNo);
            return inPkt;
        }

        inPkt.setSourceMACAddress(deviceInfo.hardwareIdentifier());

        IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
        ipv4Packet.setSourceAddress(deviceInfo.ipAddress().toString());
        inPkt.setPayload(ipv4Packet);

        return inPkt;
    }
}
