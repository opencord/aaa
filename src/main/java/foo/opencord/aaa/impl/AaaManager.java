package foo.opencord.aaa.impl;

import foo.opencord.aaa.api.AaaConfig;
import foo.opencord.aaa.api.AaaService;
import foo.opencord.aaa.api.PacketCustomizer;
import foo.opencord.aaa.api.StateMachineException;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
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
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Map;

import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * AAA application: interacts with a RADIUS server and, if available,
 * Subscriber And Device Information Service (SADIS).
 * <p>
 * NOTE: This (refactoring work) is a WIP !!
 */
@Service
@Component(immediate = true)
public class AaaManager implements AaaService {

    private final Logger log = getLogger(getClass());

    private static final String APP_NAME = "org.opencord.aaa";
    private static final String CFGKEY_RADIUS = "radius";

    private static final VlanId VLAN_0 = VlanId.vlanId((short) 0);


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


    // TODO : Review semantics of OPTIONAL_UNARY
    // Does this just remain null if the service is not available??
    @Reference(cardinality = ReferenceCardinality.OPTIONAL_UNARY)
    protected SubscriberAndDeviceInformationService subsService;
    // NOTE: This puts a compile-time-dependency on the SADIS application.


    // bindings for Device Service and SADIS
    private CustomizationInfo customInfo;


    // === Radius Configuration

    // NAS IP address
    private InetAddress nasIpAddress;

    // self MAC address
    // TODO: review - why was this static?
    private/*static*/ String nasMacAddress;

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
            new ConfigFactory<ApplicationId, AaaConfig>(
                    APP_SUBJECT_FACTORY, AaaConfig.class, CFGKEY_RADIUS) {
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

    // Setup specific customization/attributes on the RADIUS packets
    PacketCustomizer pktCustomizer;


    // ===


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
        if (type.toLowerCase().equals("socket")) {
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
        // TODO: here also, is a point to break dependency -
        //   org.opencord.olt.AccessDeviceService
        StateMachine.setAccessDeviceService(accessDeviceService);

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
     * @param dstMac    destination MAC address
     * @param srcMac    source MAC address
     * @param vlan      vlan identifier
     * @param eapolType EAPOL type
     * @param eap       EAP payload
     * @return Ethernet frame
     */
    // TODO: Review - why was this static?
    private /* static */ Ethernet buildEapolResponse(MacAddress dstMac,
                                                     MacAddress srcMac,
                                                     short vlan, byte eapolType,
                                                     EAP eap, byte priorityCode) {
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

    /**
     * Sends the given ethernet packet to the supplicant.
     *
     * @param ethernetPkt  the ethernet packet
     * @param connectPoint the connect point to send out from
     */
    private void sendPacketToSupplicant(Ethernet ethernetPkt,
                                        ConnectPoint connectPoint) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(connectPoint.port()).build();

        OutboundPacket packet = new DefaultOutboundPacket(
                connectPoint.deviceId(), treatment,
                ByteBuffer.wrap(ethernetPkt.serialize()));

        packetService.emit(packet);
    }

    /**
     * Send RADIUS packet to the RADIUS server.
     *
     * @param radiusPacket RADIUS packet to be sent to server
     * @param inPkt        Incoming EAPOL packet
     */
    protected void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
        radComm.sendRadiusPacket(radiusPacket, inPkt);
    }


    @Override
    public void registerPacketCustomizer(PacketCustomizer customizer) {
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
        public void event(NetworkConfigEvent networkConfigEvent) {
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

            try {
                // identify if incoming packet is from supplicant (EAP) or RADIUS
                switch (EthType.EtherType.lookup(ethPkt.getEtherType())) {
                    // Supplicant ---> [AAA] ---> RADIUS
                    case EAPOL:
                        handleSupplicantPacket(pkt);
                        break;

                    // allow RadiusCommunicator implementation to handle others
                    //    (from RADIUS, in Port-Based- scenario)
                    default:
                        radComm.handlePacketFromServer(context);
                }

            } catch (StateMachineException e) {
                log.warn("Unable to process packet:", e);
            }
        }

        /**
         * Handles PAE packets (supplicant).
         *
         * @param inPacket Ethernet packet coming from the supplicant
         */
        private void handleSupplicantPacket(InboundPacket inPacket)
                throws StateMachineException {

            // retrieve authentication session state machine
            StateMachine stateMachine = getStateMachine(inPacket.receivedFrom());
            if (stateMachine == null) {
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
                    handleEapolStart(inPacket, stateMachine, ethPkt, srcMac);
                    break;

                case EAPOL.EAPOL_LOGOFF:
                    handleEapolLogoff(stateMachine);
                    break;

                case EAPOL.EAPOL_PACKET:
                    handleEapolPacket(inPacket, stateMachine, eapol);
                    break;

                default:
                    log.trace("Skipping EAPOL message {}", eapol.getEapolType());
            }
        }

        private void handleEapolStart(InboundPacket inPacket,
                                      StateMachine stateMachine, Ethernet ethPkt,
                                      MacAddress srcMac)
                throws StateMachineException {

            stateMachine.start();
            stateMachine.setSupplicantConnectpoint(inPacket.receivedFrom());

            //send an EAP Request/Identify to the supplicant
            EAP eapPayload = new EAP(EAP.REQUEST, stateMachine.identifier(),
                                     EAP.ATTR_IDENTITY, null);

            if (ethPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                stateMachine.setPriorityCode(ethPkt.getPriorityCode());
            }

            Ethernet eth = buildEapolResponse(srcMac,
                                              MacAddress.valueOf(nasMacAddress),
                                              ethPkt.getVlanID(),
                                              EAPOL.EAPOL_PACKET,
                                              eapPayload,
                                              stateMachine.priorityCode());

            stateMachine.setSupplicantAddress(srcMac);
            stateMachine.setVlanId(ethPkt.getVlanID());

            sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint());
        }

        private void handleEapolLogoff(StateMachine stateMachine)
                throws StateMachineException {

            if (stateMachine.state() == StateMachine.STATE_AUTHORIZED) {
                stateMachine.logoff();
            }
        }

        private void handleEapolPacket(InboundPacket inPacket,
                                       StateMachine stateMachine, EAPOL eapol)
                throws StateMachineException {
            // check if this is a Response/Identify or a Response/TLS
            EAP eapPacket = (EAP) eapol.getPayload();

            byte dataType = eapPacket.getDataType();
            switch (dataType) {

                case EAP.ATTR_IDENTITY:
                    handleEapolPktIdentity(inPacket, stateMachine, eapPacket);
                    break;

                case EAP.ATTR_MD5:
                    handleEapolPktMd5(inPacket, stateMachine, eapPacket);
                    break;

                case EAP.ATTR_TLS:
                    handleEapolPktTls(inPacket, stateMachine, eapPacket);
                    break;

                default:
                    // to appease CheckStyle?
                    return;
            }
        }

        /**
         * Handles a request for ID access to RADIUS.
         *
         * @param inPacket     inbound packet
         * @param stateMachine associated session state machine
         * @param eapPacket    the EAP packet
         * @throws StateMachineException if an invalid transition is invoked
         */
        private void handleEapolPktIdentity(InboundPacket inPacket,
                                            StateMachine stateMachine,
                                            EAP eapPacket)
                throws StateMachineException {

            // request id access to RADIUS
            RADIUS radiusPayload;
            stateMachine.setUsername(eapPacket.getData());

            radiusPayload = getRadiusPayload(stateMachine,
                                             stateMachine.identifier(), eapPacket);
            radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);
            radiusPayload.addMessageAuthenticator(radiusSecret);

            sendRadiusPacket(radiusPayload, inPacket);

            // change the state to "PENDING"
            stateMachine.requestAccess();
        }

        /**
         * Handles an EAPOL MD5 packet.
         *
         * @param inPacket     inbound packet
         * @param stateMachine associated session state machine
         * @param eapPacket    the EAP packet
         */
        private void handleEapolPktMd5(InboundPacket inPacket,
                                       StateMachine stateMachine,
                                       EAP eapPacket) {
            // verify that the EAP identifier corresponds to the challenge
            // identifier from the client state machine.

            if (eapPacket.getIdentifier() == stateMachine.challengeIdentifier()) {
                //send the RADIUS challenge response
                RADIUS radiusPayload = getRadiusPayload(stateMachine,
                                                        stateMachine.identifier(),
                                                        eapPacket);

                radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);

                if (stateMachine.challengeState() != null) {
                    radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                               stateMachine.challengeState());
                }

                radiusPayload.addMessageAuthenticator(radiusSecret);
                sendRadiusPacket(radiusPayload, inPacket);
            }
        }

        /**
         * Handles an EAPOL TLS packet.
         *
         * @param inPacket     inbound packet
         * @param stateMachine associated session state machine
         * @param eapPacket    the EAP packet
         * @throws StateMachineException if an invalid transition is invoked
         */
        private void handleEapolPktTls(InboundPacket inPacket,
                                       StateMachine stateMachine,
                                       EAP eapPacket)
                throws StateMachineException {

            RADIUS radiusPayload = getRadiusPayload(stateMachine,
                                                    stateMachine.identifier(),
                                                    eapPacket);
            radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);

            if (stateMachine.challengeState() != null) {
                radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                           stateMachine.challengeState());
            }
            stateMachine.setRequestAuthenticator(radiusPayload.generateAuthCode());

            radiusPayload.addMessageAuthenticator(radiusSecret);
            sendRadiusPacket(radiusPayload, inPacket);

            if (stateMachine.state() != StateMachine.STATE_PENDING) {
                stateMachine.requestAccess();
            }
        }

        /**
         * Returns the state machine for the session associated with the
         * given connect point. If we don't have one yet, create and cache
         * a new state machine before returning it.
         * <p>
         * If the device service is available, use the nasPortId (annotated on
         * the port of the connect point), to look up subscriber information
         * in SADIS; Cache the user's C-Tag in the new state machine.
         *
         * @param cp the connect point that the request packet came in on
         * @return the associated state machine
         */
        private StateMachine getStateMachine(ConnectPoint cp) {
            String sessionId = "" + cp.deviceId() + cp.port();

            StateMachine stateMachine =
                    StateMachine.lookupStateMachineBySessionId(sessionId);

            if (stateMachine == null) {
                // none cached yet, so create a new one...

                if (deviceService != null) {
                    String nasPortId = deviceService.getPort(cp)
                            .annotations().value(AnnotationKeys.PORT_NAME);

                    SubscriberAndDeviceInformation subscriber =
                            subsService.get(nasPortId);

                    if (subscriber != null) {
                        stateMachine = new StateMachine(sessionId,
                                                        subscriber.cTag());
                    } else {
                        log.error("Could not create new state machine for {}",
                                  nasPortId);
                        return null;
                    }

                } else {
                    // no device service available (?) so create a basic instance
                    stateMachine = new StateMachine(sessionId, VLAN_0);
                }
            }
            return stateMachine;
        }

        /**
         * Creates and initializes common fields of a RADIUS packet.
         *
         * @param stateMachine state machine for the request
         * @param eapPacket    EAP packet
         * @return RADIUS packet
         */
        private RADIUS getRadiusPayload(StateMachine stateMachine,
                                        byte identifier, EAP eapPacket) {
            RADIUS radiusPayload = new RADIUS(RADIUS.RADIUS_CODE_ACCESS_REQUEST,
                                              eapPacket.getIdentifier());

            // set Request Authenticator in StateMachine
            stateMachine.setRequestAuthenticator(radiusPayload.generateAuthCode());

            radiusPayload.setIdentifier(identifier);
            radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME,
                                       stateMachine.username());
            radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_IP,
                                       nasIpAddress.getAddress());
            radiusPayload.encapsulateMessage(eapPacket);

            return radiusPayload;
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
