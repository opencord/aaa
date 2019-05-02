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

import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.slf4j.LoggerFactory.getLogger;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EAP;
import org.onlab.packet.EAPOL;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
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
import org.opencord.sadis.SubscriberAndDeviceInformationService;
import org.osgi.service.component.annotations.Activate;
import org.slf4j.Logger;

/**
 * AAA application for ONOS.
 */
@Service
@Component(immediate = true)
public class AaaManager
        extends AbstractListenerManager<AuthenticationEvent, AuthenticationEventListener>
        implements AuthenticationService {

    private static final String APP_NAME = "org.opencord.aaa";

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

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

    private final DeviceListener deviceListener = new InternalDeviceListener();

    // NAS IP address
    protected InetAddress nasIpAddress;

    // self MAC address
    protected String nasMacAddress;

    // Parsed RADIUS server addresses
    protected InetAddress radiusIpAddress;

    // MAC address of RADIUS server or net hop router
    protected String radiusMacAddress;

    // RADIUS server secret
    protected String radiusSecret;

    // bindings
    protected CustomizationInfo customInfo;

    // our application-specific event handler
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    // our unique identifier
    private ApplicationId appId;

    // Setup specific customization/attributes on the RADIUS packets
    PacketCustomizer pktCustomizer;

    // packet customizer to use
    private String customizer;

    // Type of connection to use to communicate with Radius server, options are
    // "socket" or "packet_out"
    private String radiusConnectionType;

	AaaStatisticsManager aaaStatisticsManager;// = AaaStatisticsManager.getInstance();
   
    // Object for the specific type of communication with the RADIUS
    // server, socket based or packet_out based
    RadiusCommunicator impl = null;

    // latest configuration
    AaaConfig newCfg;

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

    private StateMachineDelegate delegate = new InternalStateMachineDelegate();

    List<Byte> identifiersOfPacketsSentList = new ArrayList<Byte>();
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
        appId = coreService.registerApplication(APP_NAME);
        eventDispatcher.addSink(AuthenticationEvent.class, listenerRegistry);
        netCfgService.addListener(cfgListener);
        netCfgService.registerConfigFactory(factory);
        customInfo = new CustomizationInfo(subsService, deviceService);
        cfgListener.reconfigureNetwork(netCfgService.getConfig(appId, AaaConfig.class));
        log.info("Starting with config {} {}", this, newCfg);

        configureRadiusCommunication();

        // register our event handler
        packetService.addProcessor(processor, PacketProcessor.director(2));


        StateMachine.initializeMaps();
        StateMachine.setDelegate(delegate);

        impl.initializeLocalState(newCfg);

        impl.requestIntercepts();

        deviceService.addListener(deviceListener);

        log.info("Started");
    }


    @Deactivate
    public void deactivate() {
        impl.withdrawIntercepts();
        packetService.removeProcessor(processor);
        netCfgService.removeListener(cfgListener);
        StateMachine.unsetDelegate(delegate);
        StateMachine.destroyMaps();
        impl.deactivate();
        deviceService.removeListener(deviceListener);
        eventDispatcher.removeSink(AuthenticationEvent.class);
        log.info("Stopped");
    }

    private void configureRadiusCommunication() {
        if (radiusConnectionType.toLowerCase().equals("socket")) {
            impl = new SocketBasedRadiusCommunicator(appId, packetService, this);
        } else {
            impl = new PortBasedRadiusCommunicator(appId, packetService, mastershipService,
                    deviceService, subsService, pktCustomizer, this);
        }
    }

    private void configurePacketCustomizer() {
        switch (customizer.toLowerCase()) {
            case "sample":
                pktCustomizer = new SamplePacketCustomizer(customInfo);
                log.info("Created SamplePacketCustomizer");
                break;
            case "att":
                pktCustomizer = new AttPacketCustomizer(customInfo);
                log.info("Created AttPacketCustomizer");
                break;
            default:
                pktCustomizer = new PacketCustomizer(customInfo);
                log.info("Created default PacketCustomizer");
                break;
        }
    }
    
    private void checkForInvalidValidator(RADIUS radiusPacket) {//TODO: check for this logic existence
		boolean isValid = radiusPacket.checkMessageAuthenticator(radiusSecret);
		if(!isValid) {
			log.info("Calling aaaStatisticsManager.increaseInvalidValidatorCounter() from AaaManager.checkForInvalidValidator()");
			aaaStatisticsManager.increaseInvalidValidatorCounter();
		}
		
	}
    
    public void checkForPacketFromUnknownServer(String hostAddress) {
		if(!hostAddress.equals(newCfg.radiusIp().getHostAddress())) {
			log.info("Calling aaaStatisticsManager.incrementNumberOfPacketFromUnknownServer() from AaaManager.checkForPacketFromUnknownServer()");
			aaaStatisticsManager.incrementNumberOfPacketFromUnknownServer();
		}
	}

    /**
     * Send RADIUS packet to the RADIUS server.
     *
     * @param radiusPacket RADIUS packet to be sent to server.
     * @param inPkt        Incoming EAPOL packet
     */
    protected void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
    	//if(radiusPacket.getCode() == RADIUS.RADIUS_CODE_ACCESS_REQUEST)//TODO- confirm this check. is it possible to send challenge response to radius
    	//adding identifier of sent packet to the list
    	identifiersOfPacketsSentList.add(radiusPacket.getIdentifier());//TODO : confirm if list is req or not. 
//    	since state is pending and cant be changed unless a req execution completes
    	log.info("Calling aaaStatisticsManager.increaseOrDecreasePendingCounter() from AaaManager.sendRadiusPacket()");
    	aaaStatisticsManager.increaseOrDecreasePendingCounter(true);
    	log.info("Calling aaaStatisticsManager.increaseAccessRequestPacketsCounter() from AaaManager.sendRadiusPacket()");
    	aaaStatisticsManager.increaseAccessRequestPacketsCounter();//this will increase only if context.pktType is EAPOL
    	impl.sendRadiusPacket(radiusPacket, inPkt);
    }

    /**
     * Handles RADIUS packets.
     *
     * @param radiusPacket RADIUS packet coming from the RADIUS server.
     * @throws StateMachineException if an illegal state transition is triggered
     * @throws DeserializationException if packet deserialization fails
     */
    public void handleRadiusPacket(RADIUS radiusPacket)
            throws StateMachineException, DeserializationException {
        if (log.isTraceEnabled()) {
            log.trace("Received RADIUS packet {}", radiusPacket);
        }
        StateMachine stateMachine = StateMachine.lookupStateMachineById(radiusPacket.getIdentifier());
        if (stateMachine == null) {
            log.error("Invalid packet identifier {}, could not find corresponding "
                    + "state machine ... exiting", radiusPacket.getIdentifier());
            return;
        }

        EAP eapPayload;
        Ethernet eth;
        // 8.	Number of malformed access response packets received from the server
//        aaaStatsManager.checkForMalformedPacket(radiusPacket);
        // 9: Number of access response packets received from the server with an invalid validator
        checkForInvalidValidator(radiusPacket);//TODO CHECK LOGIC IN THIS CLASS
        
        //checking if identifier is found in list then decrementing the pending req counter 
        if(identifiersOfPacketsSentList.contains(radiusPacket.getIdentifier())) {
        	log.info("Calling aaaStatisticsManager.increaseOrDecreasePendingCounter() from AaaManager.handleRadiusPacket()");
        	aaaStatisticsManager.increaseOrDecreasePendingCounter(false);
        	//removing identifier from list
        	identifiersOfPacketsSentList.remove(new Byte(radiusPacket.getIdentifier()));
        }
        
        switch (radiusPacket.getCode()) {//TODO check if identifier comparision is needed?
            case RADIUS.RADIUS_CODE_ACCESS_CHALLENGE:
                log.debug("RADIUS packet: RADIUS_CODE_ACCESS_CHALLENGE");
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
                log.debug("Send EAP challenge response to supplicant {}", stateMachine.supplicantAddress().toString());
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());
                log.info("Calling aaaStatisticsManager.increaseChallengePacketsCounter() from AaaManager.handleRadiusPacket()");
                aaaStatisticsManager.increaseChallengePacketsCounter();
                break;
            case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                log.debug("RADIUS packet: RADIUS_CODE_ACCESS_ACCEPT");
                //send an EAPOL - Success to the supplicant.
                byte[] eapMessageSuccess =
                        radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_EAP_MESSAGE).getValue();
                eapPayload = EAP.deserializer().deserialize(
                        eapMessageSuccess, 0, eapMessageSuccess.length);
                eth = buildEapolResponse(stateMachine.supplicantAddress(),
                        MacAddress.valueOf(nasMacAddress),
                        stateMachine.vlanId(),
                        EAPOL.EAPOL_PACKET,
                        eapPayload, stateMachine.priorityCode());
                log.info("Send EAP success message to supplicant {}", stateMachine.supplicantAddress().toString());
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());

                stateMachine.authorizeAccess();
                log.info("Calling aaaStatisticsManager.increaseAcceptPacketsCounter() from AaaManager.handleRadiusPacket()");
                aaaStatisticsManager.increaseAcceptPacketsCounter();
                break;
            case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                log.debug("RADIUS packet: RADIUS_CODE_ACCESS_REJECT");
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
                    eapPayload = EAP.deserializer().deserialize(
                            eapMessageFailure, 0, eapMessageFailure.length);
                }
                eth = buildEapolResponse(stateMachine.supplicantAddress(),
                        MacAddress.valueOf(nasMacAddress),
                        stateMachine.vlanId(),
                        EAPOL.EAPOL_PACKET,
                        eapPayload, stateMachine.priorityCode());
                log.warn("Send EAP failure message to supplicant {}", stateMachine.supplicantAddress().toString());
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());
                stateMachine.denyAccess();
                log.info("Calling aaaStatisticsManager.increaseRejectPacketsCounter() from AaaManager.handleRadiusPacket()");
                aaaStatisticsManager.increaseRejectPacketsCounter();
                break;
            default:
                log.warn("Unknown RADIUS message received with code: {}", radiusPacket.getCode());
                log.info("Calling aaaStatisticsManager.increaseUnknownPacketsCounter() from AaaManager.handleRadiusPacket()");
                aaaStatisticsManager.increaseUnknownPacketsCounter();
        }
        log.info("Calling aaaStatisticsManager.countNumberOfDroppedPackets() from AaaManager.handleRadiusPacket()");
        aaaStatisticsManager.countNumberOfDroppedPackets();//TODO - call this while publishing it to kafka
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
        if (log.isTraceEnabled()) {
            EAPOL eap = ((EAPOL) ethernetPkt.getPayload());
            log.trace("Sending eapol payload {} enclosed in {} to supplicant at {}",
                      eap, ethernetPkt, connectPoint);
        }
        packetService.emit(packet);
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
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
            EAPOL eapol = (EAPOL) ethPkt.getPayload();
            if (log.isTraceEnabled()) {
                log.trace("Received EAPOL packet {} in enclosing packet {} from "
                        + "dev/port: {}/{}", eapol, ethPkt, deviceId,
                          portNumber);
            }

            StateMachine stateMachine = StateMachine.lookupStateMachineBySessionId(sessionId);
            if (stateMachine == null) {
                log.debug("Creating new state machine for sessionId: {} for "
                                + "dev/port: {}/{}", sessionId, deviceId, portNumber);
                stateMachine = new StateMachine(sessionId);
            } else {
                log.debug("Using existing state-machine for sessionId: {}", sessionId);
            }


            switch (eapol.getEapolType()) {
                case EAPOL.EAPOL_START:
                    log.debug("EAP packet: EAPOL_START");
                    stateMachine.setSupplicantConnectpoint(inPacket.receivedFrom());
                    stateMachine.start();

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

                    log.debug("Getting EAP identity from supplicant {}", stateMachine.supplicantAddress().toString());
                    sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());

                    break;
                case EAPOL.EAPOL_LOGOFF:
                    log.debug("EAP packet: EAPOL_LOGOFF");
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
                            log.debug("EAP packet: EAPOL_PACKET ATTR_IDENTITY");
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
                            log.debug("EAP packet: EAPOL_PACKET ATTR_MD5");
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
                            log.debug("EAP packet: EAPOL_PACKET ATTR_TLS");
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
                            log.warn("Unknown EAP packet type");
                            return;
                    }
                    break;
                default:
                    log.debug("Skipping EAPOL message {}", eapol.getEapolType());
            }
        }
    }

    /**
     * Delegate allowing the StateMachine to notify us of events.
     */
    private class InternalStateMachineDelegate implements StateMachineDelegate {

        @Override
        public void notify(AuthenticationEvent authenticationEvent) {
            log.info("Auth event {} for {}",
                    authenticationEvent.type(), authenticationEvent.subject());
            post(authenticationEvent);
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
            log.info("Reconfiguring AaaConfig from config: {}", cfg);

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

            boolean reconfigureCustomizer = false;
            if (customizer == null || !customizer.equals(newCfg.radiusPktCustomizer())) {
                customizer = newCfg.radiusPktCustomizer();
                configurePacketCustomizer();
                reconfigureCustomizer = true;
            }

            if (radiusConnectionType == null
                    || reconfigureCustomizer
                    || !radiusConnectionType.equals(newCfg.radiusConnectionType())) {
                radiusConnectionType = newCfg.radiusConnectionType();
                if (impl != null) {
                    impl.withdrawIntercepts();
                    impl.clearLocalState();
                }
                configureRadiusCommunication();
                impl.initializeLocalState(newCfg);
                impl.requestIntercepts();
            } else if (impl != null) {
                impl.clearLocalState();
                impl.initializeLocalState(newCfg);
            }
        }

        @Override
        public void event(NetworkConfigEvent event) {

            if ((event.type() == NetworkConfigEvent.Type.CONFIG_ADDED ||
                    event.type() == NetworkConfigEvent.Type.CONFIG_UPDATED) &&
                    event.configClass().equals(AaaConfig.class)) {

                AaaConfig cfg = netCfgService.getConfig(appId, AaaConfig.class);
                reconfigureNetwork(cfg);

                log.info("Reconfigured: {}", cfg.toString());
            }
        }
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {

            switch (event.type()) {
                case PORT_REMOVED:
                    DeviceId devId = event.subject().id();
                    PortNumber portNumber = event.port().number();
                    String sessionId = devId.toString() + portNumber.toString();

                    Map<String, StateMachine> sessionIdMap = StateMachine.sessionIdMap();
                    StateMachine removed = sessionIdMap.remove(sessionId);
                    if (removed != null) {
                        StateMachine.deleteStateMachineMapping(removed);
                    }

                    break;
                default:
                    return;
            }
        }
    }
}
