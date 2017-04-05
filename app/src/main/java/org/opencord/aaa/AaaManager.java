/*
 * Copyright 2015 AT&T Foundry
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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.ARP;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EAP;
import org.onlab.packet.EAPOL;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.Ip4Address;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;

import com.google.common.util.concurrent.ThreadFactoryBuilder;

import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.onosproject.net.packet.PacketPriority.CONTROL;
import static org.slf4j.LoggerFactory.getLogger;

import java.lang.reflect.Constructor;
import java.util.Optional;

/**
 * AAA application for ONOS.
 */
@Service
@Component(immediate = true)
public class AaaManager implements AaaManagerService {
    private static final String APP_NAME = "org.opencord.aaa";

    // for verbose output
    private final Logger log = getLogger(getClass());

    // a list of our dependencies :
    // to register with ONOS as an application - described next
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    // to receive Packet-in events that we'll respond to
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry netCfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    // Parsed RADIUS server addresses
    protected InetAddress radiusIpAddress;
    protected String radiusMacAddress;

    // NAS IP address
    protected InetAddress nasIpAddress;
    protected String nasMacAddress;

    // RADIUS server secret
    protected String radiusSecret;

    // ID of RADIUS switch
    protected String radiusSwitch;

    // RADIUS port number
    protected long radiusPort;

    // RADIUS server TCP port number
    protected short radiusServerPort;

    // RADIUS server ConnectPoint
    protected ConnectPoint radiusServerConnectPoint;

    // our application-specific event handler
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    // our unique identifier
    private ApplicationId appId;

    // Socket used for UDP communications with RADIUS server
    private DatagramSocket radiusSocket;

    // Executor for RADIUS communication thread
    private ExecutorService executor;

    // Whether to use the UDP socket or leaf switch for communication with RADIUS server
    private boolean useSocket;

    // Setup specific customization/attributes on the RADIUS packets
    RadiusPayloadCustomizer pktCustomizer;

    // packet customizer to use
    private String pktCustomizerClassName;

    // RADIUS server Vlan ID
    private short radiusVlanID;

    // Configuration properties factory
    private final ConfigFactory factory =
            new ConfigFactory<ApplicationId, AaaConfig>(APP_SUBJECT_FACTORY,
                                                         AaaConfig.class,
                                                         "AAA") {
                @Override
                public AaaConfig createConfig() {
                    return new AaaConfig();
                }
            };

    // Listener for config changes
    private final InternalConfigListener cfgListener = new InternalConfigListener();

    /**
     * Builds an EAPOL packet based on the given parameters.
     *
     * @param dstMac    destination MAC address
     * @param srcMac    source MAC address
     * @param vlan      vlan identifier
     * @param eapolType EAPOL type
     * @param eap       EAP payload
     * @return Ethernet frame
     */
    private static Ethernet buildEapolResponse(MacAddress dstMac, MacAddress srcMac,
                                               short vlan, byte eapolType, EAP eap, byte priorityCode) {

        Ethernet eth = new Ethernet();
        eth.setDestinationMACAddress(dstMac.toBytes());
        eth.setSourceMACAddress(srcMac.toBytes());
        eth.setEtherType(EthType.EtherType.EAPOL.ethType().toShort());
        if (vlan != Ethernet.VLAN_UNTAGGED) {
            eth.setVlanID(vlan);
            eth.setPriorityCode(priorityCode);
        }
        //eapol header
        EAPOL eapol = new EAPOL();
        eapol.setEapolType(eapolType);
        eapol.setPacketLength(eap.getLength());

        //eap part
        eapol.setPayload(eap);

        eth.setPayload(eapol);
        eth.setPad(true);
        return eth;
    }

    private void initializeLocalState() {
        if (useSocket) {
            try {
                radiusSocket = new DatagramSocket(null);
                radiusSocket.setReuseAddress(true);
                radiusSocket.bind(new InetSocketAddress(radiusServerPort));
            } catch (Exception ex) {
                log.error("Can't open RADIUS socket", ex);
            }

            executor = Executors.newSingleThreadExecutor(
                    new ThreadFactoryBuilder()
                            .setNameFormat("AAA-radius-%d").build());
            executor.execute(radiusListener);
        }
    }

    @Activate
    public void activate() {
        netCfgService.registerConfigFactory(factory);
        // "org.onosproject.aaa" is the FQDN of our app
        appId = coreService.registerApplication(APP_NAME);

        cfgListener.reconfigureNetwork(netCfgService.getConfig(appId, AaaConfig.class));

        // register our event handler
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();

        StateMachine.initializeMaps();


        if (pktCustomizerClassName == null) {
            pktCustomizer = new RadiusPayloadCustomizer(deviceService);
        } else {
            try {
                Class c = Class.forName(APP_NAME + "." + pktCustomizerClassName);
                Constructor constructor = c.getConstructor(new Class[] {DeviceService.class});
                pktCustomizer = (RadiusPayloadCustomizer) constructor.newInstance(new Object[] {deviceService});
            } catch (Exception e) {
                log.error("AaaManager: {}.{} not found. Using Default", APP_NAME, pktCustomizerClassName);
                pktCustomizer = new RadiusPayloadCustomizer(deviceService);
            }

        }

        initializeLocalState();
        netCfgService.addListener(cfgListener);

        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        withdrawIntercepts();
        // de-register and null our handler
        packetService.removeProcessor(processor);
        processor = null;
        StateMachine.destroyMaps();
        if (useSocket) {
            radiusSocket.close();
            executor.shutdownNow();
        }

        log.info("Stopped");
    }

    /**
     * Get the port of authenticated subscriber.
     *
     * @param mac  MAC address of subscriber
     * @return The connect port of subscriber
     */
    @Override
    public ConnectPoint getConnectPointIfAuthenticated(String mac) {
        ConnectPoint cp = StateMachine.getConnectPointIfAuthenticated(mac);
        log.info("AAA App: found ConnectPoint ({})", cp);
        return cp;
    }

    protected void sendRadiusPacket(RADIUS radiusPacket) {

        if (useSocket) {
            try {
                final byte[] data = radiusPacket.serialize();
                final DatagramSocket socket = radiusSocket;

                DatagramPacket packet =
                        new DatagramPacket(data, data.length,
                                radiusIpAddress, radiusServerPort);

                socket.send(packet);
            } catch (IOException e) {
                log.info("Cannot send packet to RADIUS server", e);
            }
        } else {
            // create the packet
            Ethernet ethReply = new Ethernet();
            ethReply.setSourceMACAddress(nasMacAddress);
            ethReply.setDestinationMACAddress(radiusMacAddress);
            ethReply.setEtherType(Ethernet.TYPE_IPV4);
            ethReply.setVlanID(radiusVlanID);

            IPv4 ipv4Packet = new IPv4();
            ipv4Packet.setTtl((byte) 64);
            ipv4Packet.setSourceAddress(Ip4Address.valueOf(nasIpAddress).toInt());
            ipv4Packet.setDestinationAddress(Ip4Address.valueOf(radiusIpAddress).toInt());

            UDP udpPacket = new UDP();
            udpPacket.setSourcePort(radiusServerPort);
            udpPacket.setDestinationPort(radiusServerPort);

            udpPacket.setPayload(radiusPacket);
            ipv4Packet.setPayload(udpPacket);
            ethReply.setPayload(ipv4Packet);

            sendFromRadiusServerPort(ethReply);
        }
    }

    private void sendFromRadiusServerPort(Ethernet packet) {
        //send Packetout to radius server connectpoint.
        if (radiusServerConnectPoint != null) {
            TrafficTreatment t = DefaultTrafficTreatment.builder()
                    .setOutput(radiusServerConnectPoint.port()).build();
            OutboundPacket o = new DefaultOutboundPacket(
                    radiusServerConnectPoint.deviceId(), t, ByteBuffer.wrap(packet.serialize()));
            packetService.emit(o);
        }
    }

    /**
     * Request packet in via PacketService.
     */
    private void requestIntercepts() {
        if (!useSocket) {
            TrafficSelector.Builder selectorArpServer = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_ARP);
            packetService.requestPackets(selectorArpServer.build(), CONTROL, appId,
                    Optional.of(radiusServerConnectPoint.deviceId()));

            TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_UDP)
                    .matchUdpSrc(TpPort.tpPort(radiusServerPort));
            packetService.requestPackets(selectorServer.build(), CONTROL, appId,
                    Optional.of(radiusServerConnectPoint.deviceId()));
        }
    }

    /**
     * Cancel request for packet in via PacketService.
     */
    private void withdrawIntercepts() {
        if (!useSocket) {
            TrafficSelector.Builder selectorArpServer = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_ARP);
            packetService.cancelPackets(selectorArpServer.build(), CONTROL, appId,
                    Optional.of(radiusServerConnectPoint.deviceId()));

            TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_UDP)
                    .matchUdpSrc(TpPort.tpPort(radiusServerPort));
            packetService.cancelPackets(selectorServer.build(), CONTROL, appId,
                    Optional.of(radiusServerConnectPoint.deviceId()));
        }
    }

    /**
     * Handles RADIUS packets.
     *
     * @param radiusPacket RADIUS packet coming from the RADIUS server.
     * @throws StateMachineException if an illegal state transition is triggered
     */
    protected void handleRadiusPacket(RADIUS radiusPacket) throws StateMachineException {
        StateMachine stateMachine = StateMachine.lookupStateMachineById(radiusPacket.getIdentifier());
        if (stateMachine == null) {
            log.error("Invalid session identifier, exiting...");
            return;
        }

        EAP eapPayload;
        Ethernet eth;
        log.debug("Recieved Radius Packet of type {}", radiusPacket.getCode());
        switch (radiusPacket.getCode()) {
            case RADIUS.RADIUS_CODE_ACCESS_CHALLENGE:
                RADIUSAttribute radiusAttrState = radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_STATE);
                byte[] challengeState = null;
                if (radiusAttrState != null) {
                    challengeState = radiusAttrState.getValue();
                }
                eapPayload = radiusPacket.decapsulateMessage();
                stateMachine.setChallengeInfo(eapPayload.getIdentifier(), challengeState);
                eth = buildEapolResponse(stateMachine.supplicantAddress(),
                        MacAddress.valueOf(nasMacAddress),
                        stateMachine.vlanId(),
                        EAPOL.EAPOL_PACKET,
                        eapPayload, stateMachine.priorityCode());
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());
                break;
            case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                //send an EAPOL - Success to the supplicant.
                byte[] eapMessageSuccess =
                        radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_EAP_MESSAGE).getValue();
                eapPayload = new EAP();
                eapPayload = (EAP) eapPayload.deserialize(eapMessageSuccess, 0, eapMessageSuccess.length);
                eth = buildEapolResponse(stateMachine.supplicantAddress(),
                        MacAddress.valueOf(nasMacAddress),
                        stateMachine.vlanId(),
                        EAPOL.EAPOL_PACKET,
                        eapPayload, stateMachine.priorityCode());
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());

                stateMachine.authorizeAccess();
                break;
            case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                //send an EAPOL - Failure to the supplicant.
                byte[] eapMessageFailure;
                eapPayload = new EAP();
                RADIUSAttribute radiusAttrEap = radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_EAP_MESSAGE);
                if (radiusAttrEap == null) {
                    eapPayload.setCode(EAP.FAILURE);
                    eapPayload.setIdentifier(stateMachine.challengeIdentifier());
                    eapPayload.setLength(EAP.EAP_HDR_LEN_SUC_FAIL);
                } else {
                    eapMessageFailure = radiusAttrEap.getValue();
                    eapPayload = (EAP) eapPayload.deserialize(eapMessageFailure, 0, eapMessageFailure.length);
                }
                eth = buildEapolResponse(stateMachine.supplicantAddress(),
                        MacAddress.valueOf(nasMacAddress),
                        stateMachine.vlanId(),
                        EAPOL.EAPOL_PACKET,
                        eapPayload, stateMachine.priorityCode());
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());
                stateMachine.denyAccess();
                break;
            default:
                log.warn("Unknown RADIUS message received with code: {}", radiusPacket.getCode());
        }
    }

    /**
     * Send the ethernet packet to the supplicant.
     *
     * @param ethernetPkt  the ethernet packet
     * @param connectPoint the connect point to send out
     */
    private void sendPacketToSupplicant(Ethernet ethernetPkt, ConnectPoint connectPoint) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(connectPoint.port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(connectPoint.deviceId(),
                                                          treatment, ByteBuffer.wrap(ethernetPkt.serialize()));
        packetService.emit(packet);
    }

    // our handler defined as a private inner class

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {

            // Extract the original Ethernet frame from the packet information
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }
            try {
                // identify if incoming packet comes from supplicant (EAP) or RADIUS
                switch (EthType.EtherType.lookup(ethPkt.getEtherType())) {
                    case EAPOL:
                        handleSupplicantPacket(context.inPacket());
                        break;
                    case ARP:
                        handleArpPacketFromServer(context);
                        break;
                    case IPV4:
                        handleIPv4PacketFromServer(context);
                        break;
                    default:
                        log.trace("Skipping Ethernet packet type {}",
                                  EthType.EtherType.lookup(ethPkt.getEtherType()));
                }
            } catch (StateMachineException e) {
                log.warn("Unable to process RADIUS packet:", e);
            }
        }

        /**
         * Creates and initializes common fields of a RADIUS packet.
         *
         * @param stateMachine state machine for the request
         * @param eapPacket  EAP packet
         * @return RADIUS packet
         */
        private RADIUS getRadiusPayload(StateMachine stateMachine, byte identifier, EAP eapPacket) {
            RADIUS radiusPayload =
                    new RADIUS(RADIUS.RADIUS_CODE_ACCESS_REQUEST,
                               eapPacket.getIdentifier());

            // set Request Authenticator in StateMachine
            stateMachine.setRequestAuthenticator(radiusPayload.generateAuthCode());

            radiusPayload.setIdentifier(identifier);
            radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME,
                                       stateMachine.username());

            radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_IP,
                    AaaManager.this.nasIpAddress.getAddress());

            radiusPayload.encapsulateMessage(eapPacket);

            return radiusPayload;
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

            if (Ip4Address.valueOf(arpPacket.getTargetProtocolAddress()).equals(Ip4Address.valueOf(nasIpAddress))) {
                ARP arpReply = (ARP) arpPacket.clone();
                arpReply.setOpCode(ARP.OP_REPLY);
                arpReply.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
                arpReply.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
                arpReply.setSenderProtocolAddress(arpPacket.getTargetProtocolAddress());
                arpReply.setSenderHardwareAddress(MacAddress.valueOf(nasMacAddress).toBytes());

                log.debug("AAA Manager: Query for ARP of IP : {}", arpPacket.getTargetProtocolAddress());

                // Ethernet Frame.
                Ethernet ethReply = new Ethernet();
                ethReply.setSourceMACAddress(nasMacAddress);
                ethReply.setDestinationMACAddress(ethPkt.getSourceMAC());
                ethReply.setEtherType(Ethernet.TYPE_ARP);
                ethReply.setVlanID(radiusVlanID);
                log.debug("AAA Manager set VID in ARP = {}", ethReply.getVlanID());

                ethReply.setPayload(arpReply);
                sendFromRadiusServerPort(ethReply);
            } else {
                log.debug("AAA Manager: ARP received for {}", arpPacket.getTargetProtocolAddress());
            }
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
                        try {
                            handleRadiusPacket(radiusMsg);
                        }  catch (StateMachineException sme) {
                            log.error("Illegal state machine operation", sme);
                        }
                    } catch (DeserializationException dex) {
                        log.error("Cannot deserialize packet", dex);
                    }
                }
            }
        }

        /**
         * Handles PAE packets (supplicant).
         *
         * @param inPacket Ethernet packet coming from the supplicant
         */
        private void handleSupplicantPacket(InboundPacket inPacket) throws StateMachineException {
            Ethernet ethPkt = inPacket.parsed();
            // Where does it come from?
            MacAddress srcMac = ethPkt.getSourceMAC();

            DeviceId deviceId = inPacket.receivedFrom().deviceId();
            PortNumber portNumber = inPacket.receivedFrom().port();
            String sessionId = deviceId.toString() + portNumber.toString();
            StateMachine stateMachine = StateMachine.lookupStateMachineBySessionId(sessionId);
            if (stateMachine == null) {
                stateMachine = new StateMachine(sessionId);
            }


            EAPOL eapol = (EAPOL) ethPkt.getPayload();

            switch (eapol.getEapolType()) {
                case EAPOL.EAPOL_START:
                    stateMachine.start();
                    stateMachine.setSupplicantConnectpoint(inPacket.receivedFrom());

                    //send an EAP Request/Identify to the supplicant
                    EAP eapPayload = new EAP(EAP.REQUEST, stateMachine.identifier(), EAP.ATTR_IDENTITY, null);
                    if (ethPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                       stateMachine.setPriorityCode(ethPkt.getPriorityCode());
                    }
                    Ethernet eth = buildEapolResponse(srcMac, MacAddress.valueOf(nasMacAddress),
                                                      ethPkt.getVlanID(), EAPOL.EAPOL_PACKET,
                                                      eapPayload, stateMachine.priorityCode());
                    stateMachine.setSupplicantAddress(srcMac);
                    stateMachine.setVlanId(ethPkt.getVlanID());

                    sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());

                    break;
                case EAPOL.EAPOL_LOGOFF:
                    if (stateMachine.state() == StateMachine.STATE_AUTHORIZED) {
                        stateMachine.logoff();
                    }

                    break;
                case EAPOL.EAPOL_PACKET:
                    RADIUS radiusPayload;
                    // check if this is a Response/Identify or  a Response/TLS
                    EAP eapPacket = (EAP) eapol.getPayload();

                    byte dataType = eapPacket.getDataType();
                    switch (dataType) {

                        case EAP.ATTR_IDENTITY:
                            // request id access to RADIUS
                            stateMachine.setUsername(eapPacket.getData());

                            radiusPayload = getRadiusPayload(stateMachine, stateMachine.identifier(), eapPacket);
                            radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);
                            radiusPayload.addMessageAuthenticator(AaaManager.this.radiusSecret);

                            sendRadiusPacket(radiusPayload);

                            // change the state to "PENDING"
                            stateMachine.requestAccess();
                            break;
                        case EAP.ATTR_MD5:
                            // verify if the EAP identifier corresponds to the
                            // challenge identifier from the client state
                            // machine.
                            if (eapPacket.getIdentifier() == stateMachine.challengeIdentifier()) {
                                //send the RADIUS challenge response
                                radiusPayload =
                                        getRadiusPayload(stateMachine,
                                                         stateMachine.identifier(),
                                                         eapPacket);
                                radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);

                                if (stateMachine.challengeState() != null) {
                                    radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                            stateMachine.challengeState());
                                }
                                radiusPayload.addMessageAuthenticator(AaaManager.this.radiusSecret);
                                sendRadiusPacket(radiusPayload);
                            }
                            break;
                        case EAP.ATTR_TLS:
                            // request id access to RADIUS
                            radiusPayload = getRadiusPayload(stateMachine, stateMachine.identifier(), eapPacket);
                            radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);

                            if (stateMachine.challengeState() != null) {
                                radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                        stateMachine.challengeState());
                            }
                            stateMachine.setRequestAuthenticator(radiusPayload.generateAuthCode());

                            radiusPayload.addMessageAuthenticator(AaaManager.this.radiusSecret);
                            sendRadiusPacket(radiusPayload);

                            if (stateMachine.state() != StateMachine.STATE_PENDING) {
                                stateMachine.requestAccess();
                            }

                            break;
                        default:
                            return;
                    }
                    break;
                default:
                    log.trace("Skipping EAPOL message {}", eapol.getEapolType());
            }

        }
    }

    class RadiusListener implements Runnable {

        @Override
        public void run() {
            boolean done = false;
            int packetNumber = 1;

            log.info("UDP listener thread starting up");
            RADIUS inboundRadiusPacket;
            while (!done) {
                try {
                    byte[] packetBuffer = new byte[RADIUS.RADIUS_MAX_LENGTH];
                    DatagramPacket inboundBasePacket =
                            new DatagramPacket(packetBuffer, packetBuffer.length);
                    DatagramSocket socket = radiusSocket;
                    socket.receive(inboundBasePacket);
                    log.info("Packet #{} received", packetNumber++);
                    try {
                        inboundRadiusPacket =
                                RADIUS.deserializer()
                                        .deserialize(inboundBasePacket.getData(),
                                                     0,
                                                     inboundBasePacket.getLength());
                        handleRadiusPacket(inboundRadiusPacket);
                    } catch (DeserializationException dex) {
                        log.error("Cannot deserialize packet", dex);
                    } catch (StateMachineException sme) {
                        log.error("Illegal state machine operation", sme);
                    }

                } catch (IOException e) {
                    log.info("Socket was closed, exiting listener thread");
                    done = true;
                }
            }
        }
    }

    RadiusListener radiusListener = new RadiusListener();

    private class InternalConfigListener implements NetworkConfigListener {

        /**
         * Reconfigures the AAA application according to the
         * configuration parameters passed.
         *
         * @param cfg configuration object
         */
        private void reconfigureNetwork(AaaConfig cfg) {
            AaaConfig newCfg;
            if (cfg == null) {
                newCfg = new AaaConfig();
            } else {
                newCfg = cfg;
            }
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
            if (newCfg.radiusSecret() != null) {
                radiusSecret = newCfg.radiusSecret();
            }
            if (newCfg.radiusSwitch() != null) {
                radiusSwitch = newCfg.radiusSwitch();
            }
            if (newCfg.radiusPort() != -1) {
                radiusPort = newCfg.radiusPort();
            }
            if (newCfg.radiusServerUdpPort() != -1) {
                radiusServerPort = newCfg.radiusServerUdpPort();
            }
            if (newCfg.radiusServerVlanId() != -1) {
                radiusVlanID = newCfg.radiusServerVlanId();
            }
            useSocket = newCfg.radiusUseSocket();

            radiusServerConnectPoint = new ConnectPoint(DeviceId.deviceId(radiusSwitch),
                                                  PortNumber.portNumber(radiusPort));
            pktCustomizerClassName = newCfg.radiusPktCustomizerClassName();
        }

        @Override
        public void event(NetworkConfigEvent event) {

            if ((event.type() == NetworkConfigEvent.Type.CONFIG_ADDED ||
                    event.type() == NetworkConfigEvent.Type.CONFIG_UPDATED) &&
                    event.configClass().equals(AaaConfig.class)) {

                AaaConfig cfg = netCfgService.getConfig(appId, AaaConfig.class);
                reconfigureNetwork(cfg);
                radiusSocket.close();
                executor.shutdownNow();
                initializeLocalState();
                log.info("Reconfigured");
            }
        }
    }


}
