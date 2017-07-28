/*
 * Copyright 2017-present Open Networking Laboratory
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

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;

import org.onlab.packet.ARP;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EAP;
import org.onlab.packet.EAPOL;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipEvent;
import org.onosproject.mastership.MastershipListener;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
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
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import org.opencord.olt.AccessDeviceService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.SubscriberAndDeviceInformationService;

import org.slf4j.Logger;

import com.google.common.collect.Maps;
import com.google.common.util.concurrent.ThreadFactoryBuilder;

import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.onosproject.net.packet.PacketPriority.CONTROL;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


/**
 * AAA application for ONOS.
 */
@Component(immediate = true)
public class AaaManager {
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

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected SubscriberAndDeviceInformationService subsService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected AccessDeviceService accessDeviceService;

    // Parsed RADIUS server addresses
    protected InetAddress radiusIpAddress;
    protected String radiusMacAddress;

    // NAS IP address
    protected InetAddress nasIpAddress;
    protected String nasMacAddress;

    // RADIUS server secret
    protected String radiusSecret;

    // RADIUS server TCP port number
    protected short radiusServerPort;

    // connect points to the RADIUS server
    Set<ConnectPoint> radiusConnectPoints;

    // NAS Identifier
    protected String nasId;

    // bindings
    protected CustomizationInfo customInfo;

    // our application-specific event handler
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    // our unique identifier
    private ApplicationId appId;

    // Whether to use the UDP socket or leaf switch for communication with RADIUS server
    private boolean useSocket;

    // Setup specific customization/attributes on the RADIUS packets
    PacketCustomizer pktCustomizer;

    // packet customizer to use
    private String customizer;

    // RADIUS server Vlan ID
    private short radiusVlanID;

    // RADIUS p-bit
    private byte radiusPBit;

    RadiusCommunication impl = null;

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

    @Activate
    public void activate() {
        netCfgService.registerConfigFactory(factory);
        appId = coreService.registerApplication(APP_NAME);

        cfgListener.reconfigureNetwork(netCfgService.getConfig(appId, AaaConfig.class));

        // register our event handler
        packetService.addProcessor(processor, PacketProcessor.director(2));

        if (useSocket) {
            impl = new SocketBasedRadiusCommunication();
        } else {
            impl = new PortBasedRadiusCommunication();
        }

        impl.requestIntercepts();

        StateMachine.initializeMaps();
        StateMachine.setAccessDeviceService(accessDeviceService);

        customInfo = new CustomizationInfo(subsService, deviceService);

        switch (customizer) {
            case "sample":
                pktCustomizer = new SamplePacketCustomizer(customInfo);
                log.info("Created SamplePacketCustomizer");
                break;
            default:
                pktCustomizer = new PacketCustomizer(customInfo);
                log.info("Created default PacketCustomizer");
                break;
        }

        impl.initializeLocalState();
        netCfgService.addListener(cfgListener);

        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        impl.withdrawIntercepts();
        // de-register and null our handler
        packetService.removeProcessor(processor);
        processor = null;
        StateMachine.destroyMaps();

        impl.deactivate();

        log.info("Stopped");
    }

    /**
     * Send RADIUS packet to the RADIUS server.
     *
     * @param radiusPacket RADIUS packet to be sent to server.
     * @param inPkt        Incoming EAPOL packet
     */
    protected void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
        impl.sendRadiusPacket(radiusPacket, inPkt);
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
            log.error("Invalid session identifier {}, exiting...", radiusPacket.getIdentifier());
            return;
        }

        EAP eapPayload;
        Ethernet eth;

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
                    default:
                        // any other packets let the specific implementation handle
                        impl.handlePacketFromServer(context);
                }
            } catch (StateMachineException e) {
                log.warn("Unable to process packet:", e);
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
                if (deviceService != null) {
                    String nasPortId = deviceService.getPort(inPacket.receivedFrom()).
                            annotations().value(AnnotationKeys.PORT_NAME);

                    SubscriberAndDeviceInformation subscriber =
                            subsService.get(nasPortId);
                    if (subscriber != null) {
                        stateMachine = new StateMachine(sessionId, subscriber.cTag());
                    }
                } else {
                    stateMachine = new StateMachine(sessionId, VlanId.vlanId((short) 0));
                }
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

                            sendRadiusPacket(radiusPayload, inPacket);

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
                                sendRadiusPacket(radiusPayload, inPacket);
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
                            sendRadiusPacket(radiusPayload, inPacket);

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

    /**
     * Configuration Listener, handles change in configuration.
     */
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

            radiusServerPort = newCfg.radiusServerUdpPort();
            radiusVlanID = newCfg.radiusServerVlanId();
            radiusPBit = newCfg.radiusServerPBit();
            useSocket = newCfg.radiusUseSocket();
            radiusConnectPoints = newCfg.radiusServerConnectPoints();
            customizer = newCfg.radiusPktCustomizer();

            if (impl != null) {
                impl.clearLocalState();
                impl.initializeLocalState();
            }
        }

        @Override
        public void event(NetworkConfigEvent event) {

            if ((event.type() == NetworkConfigEvent.Type.CONFIG_ADDED ||
                    event.type() == NetworkConfigEvent.Type.CONFIG_UPDATED) &&
                    event.configClass().equals(AaaConfig.class)) {

                AaaConfig cfg = netCfgService.getConfig(appId, AaaConfig.class);
                reconfigureNetwork(cfg);

                log.info("Reconfigured");
            }
        }
    }

    /**
     * Interface to the implementations for RADIUS server side communication.
     */
    private interface RadiusCommunication {

        /**
         * Does initialization required for the implementation to work.
         */
        void initializeLocalState();
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

    /**
     * Handles Socket based communication with the RADIUS server.
     */
    private class SocketBasedRadiusCommunication implements RadiusCommunication {

        // Socket used for UDP communications with RADIUS server
        private DatagramSocket radiusSocket;

        // Executor for RADIUS communication thread
        private ExecutorService executor;

        @Override
        public void initializeLocalState() {
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

        @Override
        public void clearLocalState() {
            radiusSocket.close();
            executor.shutdownNow();
        }

        @Override
        public void deactivate() { }

        @Override
        public void requestIntercepts() {
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType(EthType.EtherType.EAPOL.ethType().toShort());
            packetService.requestPackets(selector.build(), CONTROL, appId);
        }

        @Override
        public void withdrawIntercepts() {
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType(EthType.EtherType.EAPOL.ethType().toShort());
            packetService.cancelPackets(selector.build(), CONTROL, appId);
        }

        @Override
        public void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
            try {
                final byte[] data = radiusPacket.serialize();
                final DatagramSocket socket = radiusSocket;

                DatagramPacket packet =
                        new DatagramPacket(data, data.length,
                                radiusIpAddress, radiusServerPort);

                socket.send(packet);
                log.warn("Packet sent to Radius Server using socket packet = {}", packet);
            } catch (IOException e) {
                log.info("Cannot send packet to RADIUS server", e);
            }
        }

        @Override
        public void handlePacketFromServer(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            log.trace("Skipping Ethernet packet type {}",
                    EthType.EtherType.lookup(ethPkt.getEtherType()));
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
    }

    /**
     * Handles communication with the RADIUS server through ports
     * of the SDN switches.
     */
    private class PortBasedRadiusCommunication implements  RadiusCommunication {

        // to store local mapping of IP Address and Serial No of Device
        private Map<Ip4Address, String> ipToSnMap;

        ConnectPoint radiusServerConnectPoint = null;

        InnerMastershipListener changeListener = new InnerMastershipListener();
        InnerDeviceListener deviceListener = new InnerDeviceListener();

        PortBasedRadiusCommunication() {
            ipToSnMap = Maps.newConcurrentMap();
            mastershipService.addListener(changeListener);
            deviceService.addListener(deviceListener);
        }
        @Override
        public void initializeLocalState() {
            synchronized (this) {
                radiusServerConnectPoint = null;
                // find a connect point through a device for which we are master
                for (ConnectPoint cp: radiusConnectPoints) {
                    if (mastershipService.isLocalMaster(cp.deviceId())) {
                        if (deviceService.isAvailable(cp.deviceId())) {
                            radiusServerConnectPoint = cp;
                        }
                        log.warn("RADIUS connectPoint selected is {}", cp);
                        break;
                    }
                }
                log.warn("RADIUS connectPoint in initializeLocalState is {}", radiusServerConnectPoint);

                if (radiusServerConnectPoint == null) {
                    log.error("Master of none, can't send radius Message to server");
                }
            }
        }

        @Override
        public void clearLocalState() {}

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
            String serialNo = customInfo.deviceService().getDevice(inPkt.
                    receivedFrom().deviceId()).serialNumber();

            SubscriberAndDeviceInformation deviceInfo = customInfo.
                    subscriberService().get(serialNo);

            if (deviceInfo == null) {
                log.error("No Device found with SN {}", serialNo);
                return;
            }
            ipToSnMap.put(deviceInfo.ipAddress(), serialNo);

            // send the message out
            sendFromRadiusServerPort(pktCustomizer.
                    customizeEthernetIPHeaders(ethReply, inPkt));
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
                log.error("ARP resolution, MAC address not found for SN {}", serialNo);
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
    }
}
