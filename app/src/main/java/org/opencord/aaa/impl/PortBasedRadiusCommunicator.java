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

import com.google.common.collect.Maps;
import org.onlab.packet.ARP;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipEvent;
import org.onosproject.mastership.MastershipListener;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketService;
import org.opencord.aaa.AaaConfig;
import org.opencord.aaa.RadiusCommunicator;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Set;

import static org.onosproject.net.packet.PacketPriority.CONTROL;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Handles communication with the RADIUS server through ports
 * of the SDN switches.
 */
public class PortBasedRadiusCommunicator implements RadiusCommunicator {

    // for verbose output
    private final Logger log = getLogger(getClass());

    // our unique identifier
    private ApplicationId appId;

    // to receive Packet-in events that we'll respond to
    PacketService packetService;

    DeviceService deviceService;

    MastershipService mastershipService;

    BaseInformationService<SubscriberAndDeviceInformation> subsService;

    // to store local mapping of IP Address and Serial No of Device
    private Map<Ip4Address, String> ipToSnMap;

    // connect points to the RADIUS server
    Set<ConnectPoint> radiusConnectPoints;

    // Parsed RADIUS server addresses
    protected InetAddress radiusIpAddress;

    // RADIUS server TCP port number
    protected short radiusServerPort;

    protected String radiusMacAddress;

    // NAS IP address
    protected InetAddress nasIpAddress;

    protected String nasMacAddress;

    // RADIUS server Vlan ID
    private short radiusVlanID;

    // RADIUS p-bit
    private byte radiusPBit;

    PacketCustomizer pktCustomizer;
    AaaManager aaaManager;
    ConnectPoint radiusServerConnectPoint = null;

    InnerMastershipListener changeListener = new InnerMastershipListener();
    InnerDeviceListener deviceListener = new InnerDeviceListener();

    PortBasedRadiusCommunicator(ApplicationId appId, PacketService pktService,
                                MastershipService masService, DeviceService devService,
                                BaseInformationService<SubscriberAndDeviceInformation> subsService,
                                PacketCustomizer pktCustomizer, AaaManager aaaManager) {
        this.appId = appId;
        this.packetService = pktService;
        this.mastershipService = masService;
        this.deviceService = devService;
        this.subsService = subsService;
        this.pktCustomizer = pktCustomizer;
        this.aaaManager = aaaManager;

        ipToSnMap = Maps.newConcurrentMap();
        mastershipService.addListener(changeListener);
        deviceService.addListener(deviceListener);

        log.info("Created PortBased");
    }

    private void initializeLocalState() {
        synchronized (this) {
            radiusServerConnectPoint = null;
            if (radiusConnectPoints != null) {
                // find a connect point through a device for which we are master
                for (ConnectPoint cp: radiusConnectPoints) {
                    if (mastershipService.isLocalMaster(cp.deviceId())) {
                        if (deviceService.isAvailable(cp.deviceId())) {
                            radiusServerConnectPoint = cp;
                        }
                        break;
                    }
                }
            }

            log.info("RADIUS connectPoint in initializeLocalState is {}", radiusServerConnectPoint);

            if (radiusServerConnectPoint == null) {
                log.error("Master of none, can't send radius Message to server");
            }
        }
    }

    @Override
    public void initializeLocalState(AaaConfig newCfg) {
        if (newCfg.nasIp() != null) {
            nasIpAddress = newCfg.nasIp();
        }
        if (newCfg.radiusIp() != null) {
            radiusIpAddress = newCfg.radiusIp();
        }
        if (newCfg.radiusMac() != null) {
            radiusMacAddress = newCfg.radiusMac();
        }
        if (newCfg.nasMac() != null) {
            nasMacAddress = newCfg.nasMac();
        }

        radiusServerPort = newCfg.radiusServerUdpPort();
        radiusVlanID = newCfg.radiusServerVlanId();
        radiusPBit = newCfg.radiusServerPBit();

        radiusConnectPoints = newCfg.radiusServerConnectPoints();

        initializeLocalState();
    }

    @Override
    public void clearLocalState() {
        mastershipService.removeListener(changeListener);
        deviceService.removeListener(deviceListener);
    }

    @Override
    public void deactivate() {
        mastershipService.removeListener(changeListener);
        deviceService.removeListener(deviceListener);
    }

    @Override
    public void requestIntercepts() {
        TrafficSelector.Builder selectorArpServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selectorArpServer.build(), CONTROL, appId);

        TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(radiusServerPort));
        packetService.requestPackets(selectorServer.build(), CONTROL, appId);

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
               selector.matchEthType(EthType.EtherType.EAPOL.ethType().toShort());
               packetService.requestPackets(selector.build(), CONTROL, appId);
    }

    @Override
    public void withdrawIntercepts() {
        TrafficSelector.Builder selectorArpServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selectorArpServer.build(), CONTROL, appId);

        TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(radiusServerPort));
        packetService.cancelPackets(selectorServer.build(), CONTROL, appId);

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(EthType.EtherType.EAPOL.ethType().toShort());
        packetService.cancelPackets(selector.build(), CONTROL, appId);
    }

    @Override
    public void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
        // create the packet
        Ethernet ethReply = new Ethernet();
        ethReply.setSourceMACAddress(nasMacAddress);
        ethReply.setDestinationMACAddress(radiusMacAddress);
        ethReply.setEtherType(Ethernet.TYPE_IPV4);
        ethReply.setVlanID(radiusVlanID);
        ethReply.setPriorityCode(radiusPBit);

        IPv4 ipv4Packet = new IPv4();
        ipv4Packet.setTtl((byte) 64);
        ipv4Packet.setSourceAddress(Ip4Address.
                valueOf(nasIpAddress).toInt());
        ipv4Packet.setDestinationAddress(Ip4Address.
                valueOf(radiusIpAddress).toInt());

        UDP udpPacket = new UDP();
        udpPacket.setSourcePort(radiusServerPort);
        udpPacket.setDestinationPort(radiusServerPort);

        udpPacket.setPayload(radiusPacket);
        ipv4Packet.setPayload(udpPacket);
        ethReply.setPayload(ipv4Packet);

        // store the IP address and SN of the device, later to be used
        // for ARP responses
        String serialNo = deviceService.getDevice(inPkt.
                receivedFrom().deviceId()).serialNumber();

        SubscriberAndDeviceInformation deviceInfo = subsService.get(serialNo);

        if (deviceInfo == null) {
            log.warn("No Device found with SN {}", serialNo);
            aaaManager.radiusOperationalStatusService.setStatusServerReqSent(false);
            return;
        }
        ipToSnMap.put(deviceInfo.ipAddress(), serialNo);
        if (radiusPacket.getIdentifier() == RadiusOperationalStatusManager.AAA_REQUEST_ID_STATUS_REQUEST ||
                radiusPacket.getIdentifier() == RadiusOperationalStatusManager.AAA_REQUEST_ID_FAKE_ACCESS_REQUEST) {
            aaaManager.radiusOperationalStatusService.setOutTimeInMillis(radiusPacket.getIdentifier());
        } else {
            aaaManager.aaaStatisticsManager.putOutgoingIdentifierToMap(radiusPacket.getIdentifier());
        }
        // send the message out
        sendFromRadiusServerPort(pktCustomizer.
                customizeEthernetIPHeaders(ethReply, inPkt));
        aaaManager.radiusOperationalStatusService.setStatusServerReqSent(true);
    }

    /**
     * Sends packet to the RADIUS server using one of the switch ports.
     *
     * @param packet Ethernet packet to be sent
     */
    private void sendFromRadiusServerPort(Ethernet packet) {
        if (radiusServerConnectPoint != null) {
            log.trace("AAA Manager sending Ethernet packet = {}", packet);
            TrafficTreatment t = DefaultTrafficTreatment.builder()
                    .setOutput(radiusServerConnectPoint.port()).build();
            OutboundPacket o = new DefaultOutboundPacket(
                    radiusServerConnectPoint.deviceId(), t, ByteBuffer.wrap(packet.serialize()));
            packetService.emit(o);
        } else {
            log.error("Unable to send RADIUS packet, connectPoint is null");
        }
    }

    @Override
    public void handlePacketFromServer(PacketContext context) {
        // Extract the original Ethernet frame from the packet information
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        if (ethPkt == null) {
            return;
        }

        // identify if incoming packet
        switch (EthType.EtherType.lookup(ethPkt.getEtherType())) {
            case ARP:
                handleArpPacketFromServer(context);
                break;
            case IPV4:
                handleIPv4PacketFromServer(context);
                break;
            default:
                log.debug("Skipping Ethernet packet type {}",
                        EthType.EtherType.lookup(ethPkt.getEtherType()));
        }
    }

    /**
     * Handles ARP packets from RADIUS server.
     *
     * @param context Context for the packet
     */
    private void handleArpPacketFromServer(PacketContext context) {
        // Extract the original Ethernet frame from the packet information
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        if (ethPkt == null) {
            return;
        }

        ARP arpPacket = (ARP) ethPkt.getPayload();

        Ip4Address targetAddress = Ip4Address.valueOf(arpPacket.
                getTargetProtocolAddress());

        String serialNo = ipToSnMap.get(targetAddress);
        if (serialNo == null) {
            log.info("No mapping found for ARP reply, target address {}",
                    targetAddress);
            return;
        }
        MacAddress senderMac = subsService.get(serialNo).hardwareIdentifier();
        if (senderMac == null) {
            log.warn("ARP resolution, MAC address not found for SN {}", serialNo);
            return;
        }

        ARP arpReply = (ARP) arpPacket.clone();
        arpReply.setOpCode(ARP.OP_REPLY);
        arpReply.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
        arpReply.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
        arpReply.setSenderProtocolAddress(arpPacket.getTargetProtocolAddress());
        arpReply.setSenderHardwareAddress(senderMac.toBytes());

        log.debug("AAA Manager: Query for ARP of IP : {}", arpPacket.getTargetProtocolAddress());

        // Ethernet Frame.
        Ethernet ethReply = new Ethernet();
        ethReply.setSourceMACAddress(senderMac);
        ethReply.setDestinationMACAddress(ethPkt.getSourceMAC());
        ethReply.setEtherType(Ethernet.TYPE_ARP);
        ethReply.setVlanID(radiusVlanID);
        ethReply.setPriorityCode(ethPkt.getPriorityCode());

        ethReply.setPayload(arpReply);
        sendFromRadiusServerPort(ethReply);
    }

    /**
     * Handles IP packets from RADIUS server.
     *
     * @param context Context for the packet
     */
    private void handleIPv4PacketFromServer(PacketContext context) {
        // Extract the original Ethernet frame from the packet information
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        if (ethPkt == null) {
            return;
        }

        IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();

        if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
            UDP udpPacket = (UDP) ipv4Packet.getPayload();

            if (udpPacket.getSourcePort() == radiusServerPort) {
                //This packet is RADIUS packet from the server.
                RADIUS radiusMsg;
                try {
                    radiusMsg =
                            RADIUS.deserializer()
                                    .deserialize(udpPacket.serialize(),
                                            8,
                                            udpPacket.getLength() - 8);
                    aaaManager.aaaStatisticsManager.handleRoundtripTime(radiusMsg.getIdentifier());
                    aaaManager.handleRadiusPacket(radiusMsg);
                } catch (DeserializationException dex) {
                    log.error("Cannot deserialize packet", dex);
                }
            }
        }
    }

    /**
     * Handles Mastership changes for the devices which connect
     * to the RADIUS server.
     */
    private class InnerMastershipListener implements MastershipListener {
        @Override
        public void event(MastershipEvent event) {
            if (radiusServerConnectPoint != null &&
                    radiusServerConnectPoint.deviceId().
                            equals(event.subject())) {
                log.trace("Mastership Event recevived for {}", event.subject());
                // mastership of the device for our connect point has changed
                // reselect
                initializeLocalState();
            }
        }
    }

    /**
     * Handles Device status change for the devices which connect
     * to the RADIUS server.
     */
    private class InnerDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            log.trace("Device Event recevived for {} event {}", event.subject(), event.type());
            if (radiusServerConnectPoint == null) {
                switch (event.type()) {
                    case DEVICE_ADDED:
                    case DEVICE_AVAILABILITY_CHANGED:
                        // some device is available check if we can get one
                        initializeLocalState();
                        break;
                    default:
                        break;
                }
                return;
            }
            if (radiusServerConnectPoint.deviceId().
                    equals(event.subject().id())) {
                switch (event.type()) {
                    case DEVICE_AVAILABILITY_CHANGED:
                    case DEVICE_REMOVED:
                    case DEVICE_SUSPENDED:
                        // state of our device has changed, check if we need
                        // to re-select
                        initializeLocalState();
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
