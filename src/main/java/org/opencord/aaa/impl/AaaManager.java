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

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EAP;
import org.onlab.packet.EAPOL;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onlab.packet.VlanId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.AbstractListenerManager;
import org.onosproject.mastership.MastershipService;
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
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.opencord.aaa.api.AaaAuthState;
import org.opencord.aaa.api.AaaConfig;
import org.opencord.aaa.api.AaaEvent;
import org.opencord.aaa.api.AaaListener;
import org.opencord.aaa.api.AaaService;
import org.opencord.aaa.api.AaaSession;
import org.opencord.aaa.api.PacketCustomizer;
import org.opencord.sadis.SubscriberAndDeviceInformationService;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static jersey.repackaged.com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.opencord.aaa.impl.StateMachine.lookupStateMachineById;
import static org.opencord.aaa.impl.StateMachine.lookupStateMachineBySessionId;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * AAA application: interacts with a RADIUS server and, if available,
 * Subscriber And Device Information Service (SADIS).
 */
@Service
@Component(immediate = true)
public class AaaManager
        extends AbstractListenerManager<AaaEvent, AaaListener>
        implements AaaService {

    private static final String APP_NAME = "org.opencord.aaa";
    private static final String CFGKEY_RADIUS = "radius";
    private static final String SOCKET = "socket";

    private static final VlanId VLAN_0 = VlanId.vlanId((short) 0);

    private final Logger log = getLogger(getClass());


    // === Service Dependencies

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry netCfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MastershipService mastershipService;


    @Reference(cardinality = ReferenceCardinality.OPTIONAL_UNARY,
            bind = "bindSadis",
            unbind = "unbindSadis",
            policy = ReferencePolicy.DYNAMIC)
    protected SubscriberAndDeviceInformationService subsService;


    // DTO holding refs to device service and SADIS
    private CustomizationInfo customInfo;


    // === Radius Configuration

    // NAS IP address
    private InetAddress nasIpAddress;

    // NAS MAC address
    private String nasMacAddress;

    // Parsed RADIUS server address
    private InetAddress radiusIpAddress;

    // MAC address of RADIUS server or next-hop router
    private String radiusMacAddress;

    // RADIUS server secret
    private String radiusSecret;

    // Type of connection to use to communicate with Radius server;
    // options are "socket" (default) or "packet_out"
    private String radiusConnectionType;

    // === Internal State

    // our unique identifier
    private ApplicationId appId;

    // latest configuration
    private AaaConfig newCfg;

    // Configuration properties factory
    private final ConfigFactory radiusConfigfactory =
            new ConfigFactory<ApplicationId, AaaConfig>(APP_SUBJECT_FACTORY,
                                                        AaaConfig.class,
                                                        CFGKEY_RADIUS) {
                @Override
                public AaaConfig createConfig() {
                    return new AaaConfig();
                }
            };

    // Listener for config changes
    private final InternalConfigListener cfgListener = new InternalConfigListener();

    // Listener for port-removed events
    private final DeviceListener deviceListener = new InternalDeviceListener();

    // Processor for handling packet-ins
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();


    // Communicator implementation to communicate with the RADIUS server
    // (socket-based or packet_out-based)
    private RadiusCommunicator radComm = null;

    // Optional packet customizer for customizing the packets to and from the
    //  RADUIS server, based on specific customization/attributes of the setup
    private PacketCustomizer pktCustomizer;


    // ===

    /**
     * Hook for wiring up optional reference to SADIS.
     *
     * @param service service being announced
     */
    protected void bindSadis(SubscriberAndDeviceInformationService service) {
        if (subsService == null) {
            subsService = service;
            updateSadisConsumers();
            log.info("bound to SADIS service");
        }
    }

    /**
     * Hook for unwiring optional reference to SADIS.
     *
     * @param service service being withdrawn
     */
    protected void unbindSadis(SubscriberAndDeviceInformationService service) {
        if (subsService == service) {
            subsService = null;
            updateSadisConsumers();
            log.info("unbound from SADIS service");
        }
    }

    @Activate
    public void activate() {
        registration();
        configureRadiusComms();
        configureBindings();
        initializeStateMachine();
        initializeRadiusComms();
        registerListeners();
        installPacketIntercepts();
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        withdrawPacketIntercepts();
        unregisterListeners();
        deactivateRadiusComms();
        deactivateStateMachine();
        deregistration();
        log.info("Stopped");
    }


    // ===== set up methods

    private void registration() {
        appId = coreService.registerApplication(APP_NAME);
        netCfgService.registerConfigFactory(radiusConfigfactory);
        packetService.addProcessor(processor, PacketProcessor.director(2));
    }

    private void configureRadiusComms() {
        AaaConfig cfg = netCfgService.getConfig(appId, AaaConfig.class);
        cfgListener.reconfigureRadiusSettings(cfg);
    }

    private void configureBindings() {
        customInfo = new CustomizationInfo(subsService, deviceService);
        radComm = createCommunicator(radiusConnectionType);
        pktCustomizer = new PacketCustomizer(); // default no-op customizer
    }

    private RadiusCommunicator createCommunicator(String type) {
        RadiusCommunicator rc;
        if (type.toLowerCase().equals(SOCKET)) {
            rc = new SocketBasedRadiusCommunicator(appId, packetService, this);
        } else {
            rc = new PortBasedRadiusCommunicator(appId, packetService,
                                                 mastershipService, deviceService,
                                                 subsService, pktCustomizer, this);
        }
        return rc;
    }


    private void initializeStateMachine() {
        StateMachine.initializeMaps();
    }

    private void initializeRadiusComms() {
        radComm.initializeLocalState(newCfg);
    }

    private void registerListeners() {
        netCfgService.addListener(cfgListener);
        deviceService.addListener(deviceListener);
    }

    private void installPacketIntercepts() {
        radComm.requestIntercepts();
    }


    // ===== update methods

    private void updateSadisConsumers() {
        customInfo = new CustomizationInfo(subsService, deviceService);

        // pass the SADIS service ref (or null) on to the RADIUS communicator
        if (radComm != null) {
            radComm.sadisServiceChanged(subsService);
        }
    }


    // ===== tear down methods

    private void withdrawPacketIntercepts() {
        radComm.withdrawIntercepts();
    }

    private void unregisterListeners() {
        netCfgService.removeListener(cfgListener);
        deviceService.removeListener(deviceListener);
    }

    private void deactivateRadiusComms() {
        radComm.deactivate();
    }

    private void deactivateStateMachine() {
        StateMachine.destroyMaps();
    }

    private void deregistration() {
        packetService.removeProcessor(processor);
        processor = null;
    }


    // === Helper Methods

    /**
     * Builds an EAPOL packet based on the given parameters.
     *
     * @param dstMac       destination MAC address
     * @param srcMac       source MAC address
     * @param vlan         vlan identifier
     * @param priorityCode the priority code
     * @param eapolType    EAPOL type
     * @param eap          EAP payload
     * @return Ethernet frame
     */
    private Ethernet buildEapolResponse(MacAddress dstMac, MacAddress srcMac,
                                        short vlan, byte priorityCode,
                                        byte eapolType, EAP eap) {
        Ethernet eth = new Ethernet();
        eth.setDestinationMACAddress(dstMac.toBytes());
        eth.setSourceMACAddress(srcMac.toBytes());
        if (vlan != Ethernet.VLAN_UNTAGGED) {
            eth.setVlanID(vlan);
            eth.setPriorityCode(priorityCode);
        }
        eth.setEtherType(EthType.EtherType.EAPOL.ethType().toShort());

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

    /**
     * Sends the given ethernet packet to the supplicant.
     *
     * @param ethernetPkt  the ethernet packet
     * @param connectPoint the connect point to send out from
     */
    private void sendPacketToSupplicant(Ethernet ethernetPkt,
                                        ConnectPoint connectPoint) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(connectPoint.port())
                .build();

        OutboundPacket packet = new DefaultOutboundPacket(
                connectPoint.deviceId(),
                treatment,
                ByteBuffer.wrap(ethernetPkt.serialize())
        );

        packetService.emit(packet);
    }

    /**
     * Send RADIUS packet to the RADIUS server.
     *
     * @param radiusPacket RADIUS packet to be sent to server
     * @param inPkt        Incoming EAPOL packet
     */
    private void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
        radComm.sendRadiusPacket(radiusPacket, inPkt);
    }

    @Override
    public List<AaaSession> currentSessions() {
        List<AaaSession> sessions = new ArrayList<>();
        for (StateMachine sm : StateMachine.listSessions()) {
            sessions.add(new AaaSession(
                    sm.supplicantConnectpoint(),
                    new String(sm.username()),
                    sm.supplicantAddress(),
                    sm.vlanId(),
                    sm.state()
            ));
        }
        return sessions;
    }

    @Override
    public void resetAuthenticationSessionsByDeviceMac(String... macs) {
        for (String mac : macs) {
            StateMachine.deleteByMac(MacAddress.valueOf(mac));
        }
    }

    @Override
    public void registerPacketCustomizer(PacketCustomizer customizer) {
        checkNotNull(customizer, "must supply a customizer");
        pktCustomizer = customizer;
        log.info("New packet customizer installed: {}",
                 customizer.getClass().getName());
        radComm.setPacketCustomizer(pktCustomizer);
    }

    @Override
    public void unregisterPacketCustomizer(PacketCustomizer customizer) {
        pktCustomizer = new PacketCustomizer();
        log.info("Reverting to default packet customizer: {}",
                 pktCustomizer.getClass().getName());
        radComm.setPacketCustomizer(pktCustomizer);
    }

    /**
     * Posts an authentication event for the given session.
     *
     * @param type the event type
     * @param sm   the session state machine
     */
    void postEvent(AaaEvent.Type type, StateMachine sm) {
        AaaEvent event = new AaaEvent(type, sm.supplicantConnectpoint(),
                                      VlanId.vlanId(sm.vlanId()),
                                      sm.supplicantAddress());
        post(event);
    }

    /**
     * Handles a packet received from the RADUIS server.
     *
     * @param radiusPacket the inbound packet from the RADIUS server
     * @throws DeserializationException if the EAP packet deserialization fails
     */
    void handleRadiusPacket(RADIUS radiusPacket) throws DeserializationException {
        byte id = radiusPacket.getIdentifier();
        StateMachine sm = lookupStateMachineById(id);
        if (sm == null) {
            log.error("Invalid session identifier {}, ignoring packet...", id);
            return;
        }

        byte code = radiusPacket.getCode();
        switch (code) {
            case RADIUS.RADIUS_CODE_ACCESS_CHALLENGE:
                handleAccessChallenge(radiusPacket, sm);
                break;

            case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                handleAccessAccept(radiusPacket, sm);
                break;

            case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                handleAccessReject(radiusPacket, sm);
                break;

            default:
                log.warn("RADIUS message with unknown code: {}", code);
                break;
        }
    }

    private void handleAccessChallenge(RADIUS radiusPacket, StateMachine sm) {
        RADIUSAttribute radiusAttrState =
                radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_STATE);
        byte[] challengeState = (radiusAttrState == null) ? null : radiusAttrState.getValue();
        EAP eapPayload = radiusPacket.decapsulateMessage();
        sm.setChallengeInfo(eapPayload.getIdentifier(), challengeState);
        Ethernet eth = buildEapolResponse(sm.supplicantAddress(),
                                          MacAddress.valueOf(nasMacAddress),
                                          sm.vlanId(),
                                          sm.priorityCode(),
                                          EAPOL.EAPOL_PACKET,
                                          eapPayload);
        sendPacketToSupplicant(eth, sm.supplicantConnectpoint());
    }

    private void handleAccessAccept(RADIUS radiusPacket, StateMachine sm)
            throws DeserializationException {
        // send an EAPOL_Success to the supplicant
        byte[] eapMessageSuccess =
                radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_EAP_MESSAGE).getValue();

        EAP eapPayload = EAP.deserializer()
                .deserialize(eapMessageSuccess, 0, eapMessageSuccess.length);

        Ethernet eth = buildEapolResponse(sm.supplicantAddress(),
                                          MacAddress.valueOf(nasMacAddress),
                                          sm.vlanId(),
                                          sm.priorityCode(),
                                          EAPOL.EAPOL_PACKET,
                                          eapPayload);
        sendPacketToSupplicant(eth, sm.supplicantConnectpoint());

        sm.authorizeAccess();
    }

    private void handleAccessReject(RADIUS radiusPacket, StateMachine sm)
            throws DeserializationException {
        //send an EAPOL_Failure to the supplicant.
        byte[] eapMessageFailure;
        EAP eapPayload = new EAP();
        RADIUSAttribute radiusAttrEap =
                radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_EAP_MESSAGE);

        if (radiusAttrEap == null) {
            eapPayload.setCode(EAP.FAILURE);
            eapPayload.setIdentifier(sm.challengeIdentifier());
            eapPayload.setLength(EAP.EAP_HDR_LEN_SUC_FAIL);
        } else {
            eapMessageFailure = radiusAttrEap.getValue();
            eapPayload = EAP.deserializer()
                    .deserialize(eapMessageFailure, 0, eapMessageFailure.length);
        }

        Ethernet eth = buildEapolResponse(sm.supplicantAddress(),
                                          MacAddress.valueOf(nasMacAddress),
                                          sm.vlanId(),
                                          sm.priorityCode(),
                                          EAPOL.EAPOL_PACKET,
                                          eapPayload);
        sendPacketToSupplicant(eth, sm.supplicantConnectpoint());

        sm.denyAccess();
    }

    // === INNER CLASSES

    /**
     * Configuration change listener, responsible for reacting to changes in
     * the AAA network configuration.
     */
    private class InternalConfigListener implements NetworkConfigListener {

        /**
         * Reconfigures the AAA application (RADIUS settings) according to the
         * specified configuration parameters.
         *
         * @param cfg configuration object
         */
        private void reconfigureRadiusSettings(AaaConfig cfg) {

            // create default config if none was provided
            newCfg = cfg == null ? new AaaConfig() : cfg;

            // update internal state from non-null values
            if (newCfg.nasIp() != null) {
                nasIpAddress = newCfg.nasIp();
            }
            if (newCfg.nasMac() != null) {
                nasMacAddress = newCfg.nasMac();
            }

            if (newCfg.radiusIp() != null) {
                radiusIpAddress = newCfg.radiusIp();
            }
            if (newCfg.radiusMac() != null) {
                radiusMacAddress = newCfg.radiusMac();
            }

            if (newCfg.radiusSecret() != null) {
                radiusSecret = newCfg.radiusSecret();
            }

            // update connection and customizer types
            radiusConnectionType = newCfg.radiusConnectionType();

            // NOTE: packet customizer now set by call to AaaService
//            packetCustomizerType = newCfg.radiusPktCustomizer();

            if (radComm != null) {
                radComm.clearLocalState();
                radComm.initializeLocalState(newCfg);
            }

            log.info("RADIUS communication settings reconfigured");
        }


        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            return (event.type() == NetworkConfigEvent.Type.CONFIG_ADDED ||
                    event.type() == NetworkConfigEvent.Type.CONFIG_UPDATED) &&
                    event.configClass().equals(AaaConfig.class);
        }

        @Override
        public void event(NetworkConfigEvent event) {
            AaaConfig cfg = netCfgService.getConfig(appId, AaaConfig.class);
            reconfigureRadiusSettings(cfg);
        }
    }

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

            // identify if incoming packet is from supplicant (EAP) or RADIUS
            switch (EthType.EtherType.lookup(ethPkt.getEtherType())) {
                // Supplicant ---> [AAA] ---> RADIUS
                case EAPOL:
                    handleSupplicantPacket(pkt);
                    break;

                // allow RadiusCommunicator implementation to handle others
                //    (from RADIUS, in Port-Based scenario)
                default:
                    radComm.handlePacketFromServer(context);
                    break;
            }
        }

        /**
         * Handles PAE packets (supplicant).
         *
         * @param inPacket Ethernet packet coming from the supplicant
         */
        private void handleSupplicantPacket(InboundPacket inPacket) {
            // retrieve authentication session state machine
            StateMachine sm = getStateMachine(inPacket.receivedFrom());
            if (sm == null) {
                // SADIS not available, OR ...
                // SADIS available, but no registered 'nasPortId' subscriber
                return;
            }

            // the received packet
            Ethernet ethPkt = inPacket.parsed();
            MacAddress srcMac = ethPkt.getSourceMAC();

            // the EAPOL request
            EAPOL eapol = (EAPOL) ethPkt.getPayload();

            // now, decide how to handle the request...
            switch (eapol.getEapolType()) {
                case EAPOL.EAPOL_START:
                    handleEapolStart(inPacket, sm, ethPkt, srcMac);
                    break;

                case EAPOL.EAPOL_LOGOFF:
                    handleEapolLogoff(sm);
                    break;

                case EAPOL.EAPOL_PACKET:
                    handleEapolPacket(inPacket, sm, eapol);
                    break;

                default:
                    log.trace("Skipping EAPOL message {}", eapol.getEapolType());
            }
        }

        private void handleEapolStart(InboundPacket inPacket, StateMachine sm,
                                      Ethernet ethPkt, MacAddress srcMac) {
            sm.start();
            sm.setSupplicantConnectPoint(inPacket.receivedFrom());

            //send an EAP Request/Identify to the supplicant
            EAP eapPayload = new EAP(EAP.REQUEST,
                                     sm.assignMeTheNextIdentifier(),
                                     EAP.ATTR_IDENTITY, null);

            if (ethPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                sm.setPriorityCode(ethPkt.getPriorityCode());
            }

            Ethernet eth = buildEapolResponse(srcMac,
                                              MacAddress.valueOf(nasMacAddress),
                                              ethPkt.getVlanID(),
                                              sm.priorityCode(),
                                              EAPOL.EAPOL_PACKET,
                                              eapPayload);

            sm.setSupplicantAddress(srcMac);
            sm.setVlanId(ethPkt.getVlanID());

            sendPacketToSupplicant(eth, sm.supplicantConnectpoint());
        }

        private void handleEapolLogoff(StateMachine sm) {
            if (sm.state() == AaaAuthState.AUTHORIZED) {
                sm.logoff();
            }
        }

        private void handleEapolPacket(InboundPacket inPacket, StateMachine sm,
                                       EAPOL eapol) {
            // check if this is a Response/Identify or a Response/TLS
            EAP eapPacket = (EAP) eapol.getPayload();

            byte dataType = eapPacket.getDataType();
            switch (dataType) {

                case EAP.ATTR_IDENTITY:
                    handleEapolPktIdentity(inPacket, sm, eapPacket);
                    break;

                case EAP.ATTR_MD5:
                    handleEapolPktMd5(inPacket, sm, eapPacket);
                    break;

                case EAP.ATTR_TLS:
                    handleEapolPktTls(inPacket, sm, eapPacket);
                    break;

                default:
                    break;
            }
        }

        /**
         * Handles a request for ID access to RADIUS.
         *
         * @param inPacket  inbound packet
         * @param sm        associated session state machine
         * @param eapPacket the EAP packet
         */
        private void handleEapolPktIdentity(InboundPacket inPacket,
                                            StateMachine sm, EAP eapPacket) {
            // request id access to RADIUS
            sm.setUsername(eapPacket.getData());

            RADIUS payload = getRadiusPayload(sm, sm.assignMeTheNextIdentifier(),
                                              eapPacket);
            payload = pktCustomizer.customizePacket(payload, inPacket);
            payload.addMessageAuthenticator(radiusSecret);

            sendRadiusPacket(payload, inPacket);

            // change the state to "PENDING"
            sm.requestAccess();
        }

        /**
         * Handles an EAPOL MD5 packet.
         *
         * @param inPacket  inbound packet
         * @param sm        associated session state machine
         * @param eapPacket the EAP packet
         */
        private void handleEapolPktMd5(InboundPacket inPacket, StateMachine sm,
                                       EAP eapPacket) {
            // verify that the EAP identifier corresponds to the challenge
            // identifier from the client state machine.

            if (eapPacket.getIdentifier() == sm.challengeIdentifier()) {
                //send the RADIUS challenge response
                RADIUS payload = getRadiusPayload(sm, sm.assignMeTheNextIdentifier(),
                                                  eapPacket);

                payload = pktCustomizer.customizePacket(payload, inPacket);

                if (sm.challengeState() != null) {
                    payload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                         sm.challengeState());
                }

                payload.addMessageAuthenticator(radiusSecret);
                sendRadiusPacket(payload, inPacket);
            }
        }

        /**
         * Handles an EAPOL TLS packet.
         *
         * @param inPacket  inbound packet
         * @param sm        associated session state machine
         * @param eapPacket the EAP packet
         */
        private void handleEapolPktTls(InboundPacket inPacket, StateMachine sm,
                                       EAP eapPacket) {
            RADIUS payload = getRadiusPayload(sm, sm.assignMeTheNextIdentifier(),
                                              eapPacket);
            payload = pktCustomizer.customizePacket(payload, inPacket);

            if (sm.challengeState() != null) {
                payload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                     sm.challengeState());
            }
            sm.setRequestAuthenticator(payload.generateAuthCode());

            payload.addMessageAuthenticator(radiusSecret);
            sendRadiusPacket(payload, inPacket);

            if (sm.state() != AaaAuthState.PENDING) {
                sm.requestAccess();
            }
        }

        /**
         * Returns the state machine for the session associated with the
         * given connect point. If we don't have one yet, create and cache
         * a new state machine before returning it.
         *
         * @param cp the connect point that the request packet came in on
         * @return the associated state machine
         */
        private StateMachine getStateMachine(ConnectPoint cp) {
            String sessionId = String.valueOf(cp.deviceId()) + cp.port();

            StateMachine sm = lookupStateMachineBySessionId(sessionId);

            if (sm == null) {
                // none cached yet, so create (and cache) a new one...
                sm = new StateMachine(AaaManager.this, sessionId);
            }
            return sm;
        }

        /**
         * Creates and initializes common fields of a RADIUS packet.
         *
         * @param sm        state machine for the request
         * @param eapPacket EAP packet
         * @return RADIUS packet
         */
        private RADIUS getRadiusPayload(StateMachine sm,
                                        byte identifier, EAP eapPacket) {
            RADIUS payload = new RADIUS(RADIUS.RADIUS_CODE_ACCESS_REQUEST,
                                        eapPacket.getIdentifier());

            // set Request Authenticator in StateMachine
            sm.setRequestAuthenticator(payload.generateAuthCode());

            payload.setIdentifier(identifier);
            payload.setAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME,
                                 sm.username());
            payload.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_IP,
                                 nasIpAddress.getAddress());
            payload.encapsulateMessage(eapPacket);
            return payload;
        }
    }

    /**
     * Device listener, reacting to PORT_REMOVED events.
     */
    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            switch (event.type()) {
                case PORT_REMOVED:
                    DeviceId devId = event.subject().id();
                    PortNumber portNumber = event.port().number();
                    String sessionId = devId.toString() + portNumber.toString();
                    StateMachine.deleteBySessionId(sessionId);
                    break;

                default:
                    break;
            }
        }
    }

}
