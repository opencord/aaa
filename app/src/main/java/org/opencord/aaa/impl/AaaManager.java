/*
 * Copyright 2017-2023 Open Networking Foundation (ONF) and the ONF Contributors
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

import com.google.common.base.Strings;

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.onlab.util.Tools.groupedThreads;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.opencord.aaa.impl.OsgiPropertyConstants.*;
import static org.slf4j.LoggerFactory.getLogger;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EAP;
import org.onlab.packet.EAPOL;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onlab.util.KryoNamespace;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
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
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.opencord.aaa.AaaConfig;
import org.opencord.aaa.AaaMachineStatisticsEvent;
import org.opencord.aaa.AaaMachineStatisticsService;
import org.opencord.aaa.AaaSupplicantMachineStats;
import org.opencord.aaa.AuthenticationEvent;
import org.opencord.aaa.AuthenticationEventListener;
import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.AuthenticationService;
import org.opencord.aaa.AuthenticationStatisticsService;
import org.opencord.aaa.RadiusCommunicator;
import org.opencord.aaa.RadiusOperationalStatusEvent;
import org.opencord.aaa.RadiusOperationalStatusService;
import org.opencord.aaa.RadiusOperationalStatusService.RadiusOperationalStatusEvaluationMode;
import org.opencord.aaa.StateMachineDelegate;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Optional;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * AAA application for ONOS.
 */
@Component(immediate = true, property = {
        OPERATIONAL_STATUS_SERVER_EVENT_GENERATION + ":Integer=" + OPERATIONAL_STATUS_SERVER_EVENT_GENERATION_DEFAULT,
        OPERATIONAL_STATUS_SERVER_TIMEOUT + ":Integer=" + OPERATIONAL_STATUS_SERVER_TIMEOUT_DEFAULT,
        STATUS_SERVER_MODE + ":String=" + STATUS_SERVER_MODE_DEFAULT,
        PACKET_PROCESSOR_THREADS + ":Integer=" + PACKET_PROCESSOR_THREADS_DEFAULT,
        FORGE_EAPOL_PACKETS + ":Boolean=" + FORGE_EAPOL_PACKETS_DEFAULT,
})
public class AaaManager
        extends AbstractListenerManager<AuthenticationEvent, AuthenticationEventListener>
        implements AuthenticationService {
    private static final String SADIS_NOT_RUNNING = "Sadis is not running.";
    private static final String APP_NAME = "org.opencord.aaa";
    private static final int STATE_MACHINE_THREADS = 3;

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry netCfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL,
            bind = "bindSadisService",
            unbind = "unbindSadisService",
            policy = ReferencePolicy.DYNAMIC)
    protected volatile SadisService sadisService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected AuthenticationStatisticsService aaaStatisticsManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected AaaMachineStatisticsService aaaSupplicantStatsManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RadiusOperationalStatusService radiusOperationalStatusService;

    protected BaseInformationService<SubscriberAndDeviceInformation> subsService;
    private final DeviceListener deviceListener = new InternalDeviceListener();

    // Properties
    private int operationalStatusEventGenerationPeriodInSeconds = OPERATIONAL_STATUS_SERVER_EVENT_GENERATION_DEFAULT;
    private int operationalStatusServerTimeoutInSeconds = OPERATIONAL_STATUS_SERVER_TIMEOUT_DEFAULT;
    protected String operationalStatusEvaluationMode = STATUS_SERVER_MODE_DEFAULT;

    /**
     * If set to true the RADIUS server won't be involved in authentication.
     **/
    private Boolean forgeEapolPackets = FORGE_EAPOL_PACKETS_DEFAULT;

    /**
     * Number of threads used to process the packet.
     */
    protected int packetProcessorThreads = PACKET_PROCESSOR_THREADS_DEFAULT;

    private IdentifierManager idManager;

    private ConcurrentMap<String, StateMachine> stateMachines;

    private ConsistentMap<ConnectPoint, AuthenticationRecord> authenticationsConsistentMap;
    // NOTE consider to change this map to be Map<DeviceId,Map<ConnectPoint, AuthenticationRecord>> so that
    // we can iterate on smalled collection when dealing with authentications
    private Map<ConnectPoint, AuthenticationRecord> authentications;

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

    // TimeOut time for cleaning up stateMachines stuck due to pending AAA/EAPOL message.
    protected int cleanupTimerTimeOutInMins;

    // Setup specific customization/attributes on the RADIUS packets
    PacketCustomizer pktCustomizer;

    // packet customizer to use
    private String customizer;

    // Type of connection to use to communicate with Radius server, options are
    // "socket" or "packet_out"
    private String radiusConnectionType;

    // Object for the specific type of communication with the RADIUS
    // server, socket based or packet_out based
    RadiusCommunicator impl = null;

    // latest configuration
    AaaConfig newCfg;

    ScheduledFuture<?> scheduledStatusServerChecker;
    String configuredAaaServerAddress;
    HashSet<Byte> outPacketSet = new HashSet<>();
    HashSet<Byte> outPacketSupp = new HashSet<>();
    static final List<Byte> VALID_EAPOL_TYPE = Arrays.asList(EAPOL.EAPOL_START, EAPOL.EAPOL_LOGOFF, EAPOL.EAPOL_PACKET);
    static final int HEADER_LENGTH = 4;
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

    private final InternalMapEventListener mapListener = new InternalMapEventListener();

    private StateMachineDelegate delegate = new InternalStateMachineDelegate();

    protected ExecutorService packetProcessorExecutor;
    protected ScheduledExecutorService serverStatusAndStateMachineTimeoutExecutor;

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
    public void activate(ComponentContext context) {

        idManager = new IdentifierManager();
        stateMachines = Maps.newConcurrentMap();
        appId = coreService.registerApplication(APP_NAME);

        KryoNamespace authSerializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(AuthenticationRecord.class)
                .build();

        authenticationsConsistentMap = storageService.<ConnectPoint, AuthenticationRecord>consistentMapBuilder()
                .withApplicationId(appId)
                .withName("authentications")
                .withSerializer(Serializer.using(authSerializer))
                .build();
        authenticationsConsistentMap.addListener(mapListener);
        authentications = authenticationsConsistentMap.asJavaMap();

        eventDispatcher.addSink(AuthenticationEvent.class, listenerRegistry);
        netCfgService.addListener(cfgListener);
        netCfgService.registerConfigFactory(factory);
        cfgService.registerProperties(getClass());
        modified(context);
        if (sadisService != null) {
            subsService = sadisService.getSubscriberInfoService();
        } else {
            log.warn(SADIS_NOT_RUNNING);
        }
        if (customInfo == null) {
            customInfo = new CustomizationInfo(subsService, deviceService);
        }
        cfgListener.reconfigureNetwork(netCfgService.getConfig(appId, AaaConfig.class));
        log.info("Starting with config {} {}", this, newCfg);
        configureRadiusCommunication(false);
        // register our event handler
        packetService.addProcessor(processor, PacketProcessor.director(2));
        StateMachine.setDelegate(delegate);
        cleanupTimerTimeOutInMins = newCfg.sessionCleanupTimer();
        StateMachine.setcleanupTimerTimeOutInMins(cleanupTimerTimeOutInMins);
        impl.initializeLocalState(newCfg);
        impl.requestIntercepts();
        deviceService.addListener(deviceListener);
        getConfiguredAaaServerAddress();
        radiusOperationalStatusService.initialize(nasIpAddress.getAddress(), radiusSecret, impl);
        serverStatusAndStateMachineTimeoutExecutor = Executors.newScheduledThreadPool(STATE_MACHINE_THREADS,
              groupedThreads("onos/aaa", "machine-%d", log));

        scheduledStatusServerChecker = serverStatusAndStateMachineTimeoutExecutor.scheduleAtFixedRate(
                new ServerStatusChecker(), 0,
                operationalStatusEventGenerationPeriodInSeconds, TimeUnit.SECONDS);
        log.info("Started");
    }

    @Deactivate
    public void deactivate(ComponentContext context) {
        impl.withdrawIntercepts();
        packetService.removeProcessor(processor);
        netCfgService.removeListener(cfgListener);
        cfgService.unregisterProperties(getClass(), false);
        StateMachine.unsetDelegate(delegate);
        impl.deactivate();
        impl = null;
        deviceService.removeListener(deviceListener);
        eventDispatcher.removeSink(AuthenticationEvent.class);
        scheduledStatusServerChecker.cancel(true);
        serverStatusAndStateMachineTimeoutExecutor.shutdown();
        packetProcessorExecutor.shutdown();
        authenticationsConsistentMap.removeListener(mapListener);

        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<String, Object> properties = context.getProperties();

        String s = Tools.get(properties, "operationalStatusEventGenerationPeriodInSeconds");
        operationalStatusEventGenerationPeriodInSeconds = Strings.isNullOrEmpty(s)
                ? OPERATIONAL_STATUS_SERVER_EVENT_GENERATION_DEFAULT
                : Integer.parseInt(s.trim());

        s = Tools.get(properties, "operationalStatusServerTimeoutInSeconds");
        operationalStatusServerTimeoutInSeconds = Strings.isNullOrEmpty(s) ? OPERATIONAL_STATUS_SERVER_TIMEOUT_DEFAULT
                : Integer.parseInt(s.trim());

        Boolean p = Tools.isPropertyEnabled(properties, FORGE_EAPOL_PACKETS);
        forgeEapolPackets = (p == null) ? FORGE_EAPOL_PACKETS_DEFAULT : p;

        s = Tools.get(properties, "operationalStatusEvaluationMode");
        String newEvaluationModeString = Strings.isNullOrEmpty(s) ? STATUS_SERVER_MODE_DEFAULT : s.trim();

        radiusOperationalStatusService
                .setOperationalStatusServerTimeoutInMillis(operationalStatusServerTimeoutInSeconds * 1000);
        RadiusOperationalStatusEvaluationMode newEvaluationMode =
                RadiusOperationalStatusEvaluationMode.getValue(newEvaluationModeString);
        if (newEvaluationMode != null) {
            radiusOperationalStatusService.setRadiusOperationalStatusEvaluationMode(newEvaluationMode);
            operationalStatusEvaluationMode = newEvaluationModeString;
        } else {
            properties.put("operationalStatusEvaluationMode", operationalStatusEvaluationMode);
        }

        s = Tools.get(properties, PACKET_PROCESSOR_THREADS);
        int oldpacketProcessorThreads = packetProcessorThreads;
        packetProcessorThreads = Strings.isNullOrEmpty(s) ? oldpacketProcessorThreads
                : Integer.parseInt(s.trim());
        if (packetProcessorExecutor == null || oldpacketProcessorThreads != packetProcessorThreads) {
            if (packetProcessorExecutor != null) {
                packetProcessorExecutor.shutdown();
            }
            packetProcessorExecutor = newSingleThreadExecutor(
                    groupedThreads("onos/aaa", "packet-%d", log));
        }
    }

    protected void bindSadisService(SadisService service) {
        sadisService = service;
        subsService = sadisService.getSubscriberInfoService();
        if (customInfo == null) {
            customInfo = new CustomizationInfo(subsService, deviceService);
        } else {
            customInfo.updateSubscriberService(subsService);
        }
        if (radiusConnectionType == null) {
            log.debug("Configuration is not init yet.");
        } else {
            refreshRadiusCommunication();
        }
        log.info("Sadis-service binds to onos.");
    }

    protected void unbindSadisService(SadisService service) {
        sadisService = null;
        subsService = null;
        customInfo.updateSubscriberService(subsService);
        refreshRadiusCommunication();
        log.info("Sadis-service unbinds from onos.");
    }

    private void refreshRadiusCommunication() {
        if (!radiusConnectionType.toLowerCase().equals("socket")) {
            if (impl != null) {
                impl.withdrawIntercepts();
                impl.clearLocalState();
            }
            configureRadiusCommunication(true);
            impl.initializeLocalState(newCfg);
            impl.requestIntercepts();
        }
    }

    protected void configureRadiusCommunication(boolean isUpdate) {
        if (radiusConnectionType.toLowerCase().equals("socket")) {
            impl = new SocketBasedRadiusCommunicator(appId, packetService, this);
        } else {
            if (impl != null && isUpdate) {
                //update subsService
                ((PortBasedRadiusCommunicator) impl).updateSubsService(subsService);
            } else {
                impl = new PortBasedRadiusCommunicator(appId, packetService, mastershipService,
                        deviceService, subsService, pktCustomizer, this);
            }
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

    private void getConfiguredAaaServerAddress() {
        try {
            InetAddress address;
            if (newCfg.radiusHostName() != null) {
                address = InetAddress.getByName(newCfg.radiusHostName());
            } else {
                address = newCfg.radiusIp();
            }

            configuredAaaServerAddress = address.getHostAddress();
        } catch (UnknownHostException uhe) {
            log.warn("Unable to resolve host {}", newCfg.radiusHostName());
        }
    }

    private void checkReceivedPacketForValidValidator(RADIUS radiusPacket, byte[] requestAuthenticator) {
        if (!checkResponseMessageAuthenticator(radiusSecret, radiusPacket, requestAuthenticator)) {
            aaaStatisticsManager.getAaaStats().increaseInvalidValidatorsRx();
        }
    }

    private boolean checkResponseMessageAuthenticator(String key, RADIUS radiusPacket, byte[] requestAuthenticator) {
        byte[] newHash = new byte[16];
        Arrays.fill(newHash, (byte) 0);
        // looking for the attributes - exit if there are no such attributes
        if (radiusPacket.getAttributeList(RADIUSAttribute.RADIUS_ATTR_MESSAGE_AUTH).isEmpty()) {
            log.warn("Empty Attribute List for packet {} with identifier {}",
                      radiusPacket, radiusPacket.getIdentifier());
            return false;
        }
        // get the attribute - further verify if it is null or not (not really needed)
        RADIUSAttribute attribute = radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_MESSAGE_AUTH);
        if (attribute == null) {
            log.warn("Null Message Authenticator for packet {} with identifier {}",
                      radiusPacket, radiusPacket.getIdentifier());
            return false;
        }
        byte[] messageAuthenticator = attribute.getValue();
        byte[] authenticator = radiusPacket.getAuthenticator();
        radiusPacket.updateAttribute(RADIUSAttribute.RADIUS_ATTR_MESSAGE_AUTH, newHash);
        radiusPacket.setAuthenticator(requestAuthenticator);
        // Calculate the MD5 HMAC based on the message
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "HmacMD5");
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(keySpec);
            newHash = mac.doFinal(radiusPacket.serialize());
        } catch (Exception e) {
            log.error("Failed to generate message authenticator: {}", e.getMessage());
        }
        radiusPacket.updateAttribute(RADIUSAttribute.RADIUS_ATTR_MESSAGE_AUTH, messageAuthenticator);
        radiusPacket.setAuthenticator(authenticator);
        // Compare the calculated Message-Authenticator with the one in the message
        return Arrays.equals(newHash, messageAuthenticator);
    }

    public void checkForPacketFromUnknownServer(String hostAddress) {
        if (!hostAddress.equals(configuredAaaServerAddress)) {
            getConfiguredAaaServerAddress();
            if (!hostAddress.equals(configuredAaaServerAddress)) {
                aaaStatisticsManager.getAaaStats().incrementUnknownServerRx();
            }
        }
    }

    /**
     * Send RADIUS packet to the RADIUS server.
     *
     * @param radiusPacket RADIUS packet to be sent to server.
     * @param inPkt        Incoming EAPOL packet
     */
    protected void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
        outPacketSet.add(radiusPacket.getIdentifier());
        aaaStatisticsManager.getAaaStats().increaseOrDecreasePendingRequests(true);
        aaaStatisticsManager.getAaaStats().increaseAccessRequestsTx();
        aaaStatisticsManager.putOutgoingIdentifierToMap(radiusPacket.getIdentifier());
        impl.sendRadiusPacket(radiusPacket, inPkt);
    }

    /**
     * Handles RADIUS packets.
     *
     * @param radiusPacket RADIUS packet coming from the RADIUS server.
     */
    public void handleRadiusPacket(RADIUS radiusPacket) {
        if (log.isTraceEnabled()) {
            log.trace("Received RADIUS packet {} with identifier {}",
                      radiusPacket, radiusPacket.getIdentifier() & 0xff);
        }
        if (radiusOperationalStatusService.isRadiusResponseForOperationalStatus(radiusPacket.getIdentifier())) {
            if (log.isTraceEnabled()) {
                log.trace("Handling operational status RADIUS packet {} with identifier {}",
                          radiusPacket, radiusPacket.getIdentifier() & 0xff);
            }
            radiusOperationalStatusService.handleRadiusPacketForOperationalStatus(radiusPacket);
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Handling actual RADIUS packet for supplicant {} with identifier {}",
                      radiusPacket, radiusPacket.getIdentifier() & 0xff);
        }

        RequestIdentifier identifier = RequestIdentifier.of(radiusPacket.getIdentifier());
        String sessionId = idManager.getSessionId(identifier);

        if (sessionId == null) {
            log.error("Invalid packet identifier {}, could not find corresponding "
                              + "state machine ... exiting", radiusPacket.getIdentifier());
            aaaStatisticsManager.getAaaStats().incrementNumberOfSessionsExpired();
            aaaStatisticsManager.getAaaStats().countDroppedResponsesRx();
            return;
        }

        idManager.releaseIdentifier(identifier);
        StateMachine stateMachine = stateMachines.get(sessionId);
        if (stateMachine == null) {
            log.error("Invalid packet identifier {}, could not find corresponding "
                              + "state machine ... exiting", radiusPacket.getIdentifier());
            aaaStatisticsManager.getAaaStats().incrementNumberOfSessionsExpired();
            aaaStatisticsManager.getAaaStats().countDroppedResponsesRx();
            return;
        }

        //instance of StateMachine using the sessionId for updating machine stats
        StateMachine machineStats = stateMachines.get(stateMachine.sessionId());

        EAP eapPayload;
        Ethernet eth;
        checkReceivedPacketForValidValidator(radiusPacket, stateMachine.requestAuthenticator());

        //increasing packets and octets received from server
        machineStats.incrementTotalPacketsReceived();
        try {
            machineStats.incrementTotalOctetReceived(radiusPacket.decapsulateMessage().getLength());
        } catch (DeserializationException e) {
            log.error(e.getMessage());
            return;
        }

        if (outPacketSet.contains(radiusPacket.getIdentifier())) {
            aaaStatisticsManager.getAaaStats().increaseOrDecreasePendingRequests(false);
            outPacketSet.remove(new Byte(radiusPacket.getIdentifier()));
        }

        MacAddress dstMac = stateMachine.supplicantAddress();
        ConnectPoint supplicantCp = stateMachine.supplicantConnectpoint();
        switch (radiusPacket.getCode()) {
            case RADIUS.RADIUS_CODE_ACCESS_CHALLENGE:
                log.debug("RADIUS packet: RADIUS_CODE_ACCESS_CHALLENGE for dev/port: {}/{} " +
                                  "with MacAddress {} and Identifier {}",
                          supplicantCp.deviceId(), supplicantCp.port(), dstMac, radiusPacket.getIdentifier() & 0xff);
                RADIUSAttribute radiusAttrState = radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_STATE);
                byte[] challengeState = null;
                if (radiusAttrState != null) {
                    challengeState = radiusAttrState.getValue();
                }
                try {
                    eapPayload = radiusPacket.decapsulateMessage();
                    eth = buildEapolResponse(stateMachine.supplicantAddress(),
                                             MacAddress.valueOf(nasMacAddress),
                                             stateMachine.vlanId(),
                                             EAPOL.EAPOL_PACKET,
                                             eapPayload, stateMachine.priorityCode());
                    stateMachine.setChallengeInfo(eapPayload.getIdentifier(), challengeState);
                } catch (DeserializationException e) {
                    log.error(e.getMessage());
                    break;
                }
                log.debug("Send EAP challenge response to supplicant on dev/port: {}/{}" +
                                  " with MacAddress {} and Identifier {}",
                          supplicantCp.deviceId(), supplicantCp.port(), dstMac, radiusPacket.getIdentifier() & 0xff);
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint(), true);
                aaaStatisticsManager.getAaaStats().increaseChallengeResponsesRx();
                outPacketSupp.add(eapPayload.getIdentifier());
                aaaStatisticsManager.getAaaStats().incrementPendingReqSupp();
                //increasing packets send to server
                machineStats.incrementTotalPacketsSent();
                machineStats.incrementTotalOctetSent(eapPayload.getLength());
                break;
            case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                log.debug("RADIUS packet: RADIUS_CODE_ACCESS_ACCEPT for dev/port: {}/{}" +
                                  " with MacAddress {} and Identifier {}",
                          supplicantCp.deviceId(), supplicantCp.port(), dstMac, radiusPacket.getIdentifier() & 0xff);
                //send an EAPOL - Success to the supplicant.
                byte[] eapMessageSuccess =
                        radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_EAP_MESSAGE).getValue();
                try {
                    eapPayload = EAP.deserializer().deserialize(
                            eapMessageSuccess, 0, eapMessageSuccess.length);
                } catch (DeserializationException e) {
                    log.error(e.getMessage());
                    break;
                }

                eth = buildEapolResponse(stateMachine.supplicantAddress(),
                                         MacAddress.valueOf(nasMacAddress),
                                         stateMachine.vlanId(),
                                         EAPOL.EAPOL_PACKET,
                                         eapPayload, stateMachine.priorityCode());
                log.info("Send EAP success message to supplicant on dev/port: {}/{}" +
                                 " with MacAddress {} and Identifier {}",
                         supplicantCp.deviceId(), supplicantCp.port(), dstMac, radiusPacket.getIdentifier() & 0xff);
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint(), false);
                aaaStatisticsManager.getAaaStats().incrementEapolAuthSuccessTrans();

                stateMachine.authorizeAccess();
                aaaStatisticsManager.getAaaStats().increaseAcceptResponsesRx();
                //increasing packets send to server
                machineStats.incrementTotalPacketsSent();
                machineStats.incrementTotalOctetSent(eapPayload.getLength());
                break;
            case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                log.debug("RADIUS packet: RADIUS_CODE_ACCESS_REJECT for dev/port: {}/{}" +
                                  " with MacAddress {} and Identifier {}",
                          supplicantCp.deviceId(), supplicantCp.port(), dstMac, radiusPacket.getIdentifier() & 0xff);
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
                    try {
                        eapPayload = EAP.deserializer().deserialize(
                                eapMessageFailure, 0, eapMessageFailure.length);
                    } catch (DeserializationException e) {
                        log.error(e.getMessage());
                        break;
                    }
                }
                eth = buildEapolResponse(stateMachine.supplicantAddress(),
                                         MacAddress.valueOf(nasMacAddress),
                                         stateMachine.vlanId(),
                                         EAPOL.EAPOL_PACKET,
                                         eapPayload, stateMachine.priorityCode());
                log.warn("Send EAP failure message to supplicant on dev/port: {}/{}" +
                                 " with MacAddress {} and Identifier {}", supplicantCp.deviceId(), supplicantCp.port(),
                         dstMac, stateMachine.challengeIdentifier() & 0xff);
                sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint(), false);
                aaaStatisticsManager.getAaaStats().incrementEapolauthFailureTrans();

                stateMachine.denyAccess();
                aaaStatisticsManager.getAaaStats().increaseRejectResponsesRx();
                //increasing packets send to server
                machineStats.incrementTotalPacketsSent();
                machineStats.incrementTotalOctetSent(eapPayload.getLength());
                //pushing machine stats to kafka
                AaaSupplicantMachineStats machineObj = aaaSupplicantStatsManager.getSupplicantStats(machineStats);
                aaaSupplicantStatsManager.getMachineStatsDelegate()
                        .notify(new AaaMachineStatisticsEvent(AaaMachineStatisticsEvent.Type.STATS_UPDATE,
                                                              machineObj));
                break;
            default:
                log.warn("Unknown RADIUS message received with code: {} for dev/port: {}/{}" +
                                 " with MacAddress {} and Identifier {}",
                         radiusPacket.getCode(), supplicantCp.deviceId(), supplicantCp.port(), dstMac,
                         radiusPacket.getIdentifier() & 0xff);
                aaaStatisticsManager.getAaaStats().increaseUnknownTypeRx();
                //increasing packets received to server
                machineStats.incrementTotalPacketsReceived();
                try {
                    machineStats.incrementTotalOctetReceived(radiusPacket.decapsulateMessage().getLength());
                } catch (DeserializationException e) {
                    log.error(e.getMessage());
                    break;
                }
        }
        aaaStatisticsManager.getAaaStats().countDroppedResponsesRx();
    }

    /**
     * Send the ethernet packet to the supplicant.
     *
     * @param ethernetPkt  the ethernet packet
     * @param connectPoint the connect point to send out
     */
    private void sendPacketToSupplicant(Ethernet ethernetPkt, ConnectPoint connectPoint, boolean isChallengeResponse) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(connectPoint.port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(connectPoint.deviceId(),
                                                          treatment, ByteBuffer.wrap(ethernetPkt.serialize()));
        EAPOL eap = ((EAPOL) ethernetPkt.getPayload());
        if (log.isTraceEnabled()) {
            log.trace("Sending eapol payload {} to supplicant at {} with MacAddress {}",
                      eap, connectPoint, ethernetPkt.getDestinationMAC());
        }
        packetService.emit(packet);
        if (isChallengeResponse) {
            aaaStatisticsManager.getAaaStats().incrementEapPktTxauthEap();
        }
        aaaStatisticsManager.getAaaStats().incrementEapolFramesTx();
        aaaStatisticsManager.getAaaStats().countReqEapFramesTx();
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

    @Override
    public Iterable<AuthenticationRecord> getAuthenticationRecords() {
        return authentications.values();
    }

    @Override
    public boolean removeAuthenticationStateByMac(MacAddress mac) {

        Optional<AuthenticationRecord> r = authentications.values().stream()
                .filter(v -> v.supplicantAddress().equals(mac))
                .findFirst();

        if (r.isEmpty()) {
            return false;
        }

        AuthenticationRecord removed =
                authentications.remove(r.get().supplicantConnectPoint());

        return removed != null;
    }

    StateMachine getStateMachine(String sessionId) {
        return stateMachines.get(sessionId);
    }

    // our handler defined as a private inner class

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            packetProcessorExecutor.execute(() -> {
                try {
                    // Extract the original Ethernet frame from the packet information
                    InboundPacket pkt = context.inPacket();
                    if (pkt == null) {
                        log.warn("Dropping inbound packet as it can't be parsed (inpacket)");
                        return;
                    }
                    Ethernet ethPkt = pkt.parsed();
                    if (ethPkt == null) {
                        log.warn("Dropping inbound packet as it can't be parsed (ethpacket)");
                        return;
                    }

                    EthType.EtherType pktType;
                    try {
                        short ethType = ethPkt.getEtherType();
                        pktType = EthType.EtherType.lookup(ethType);
                    } catch (Exception e) {
                        log.error("Exception while reading packet type", e);
                        return;
                    }

                    // identify if incoming packet comes from supplicant (EAP) or RADIUS
                    switch (pktType) {
                        case EAPOL:
                            if (log.isTraceEnabled()) {
                                log.trace("Received EAPOL supplicant packet from dev/port: {} with MacAddress {}",
                                          context.inPacket().receivedFrom(), ethPkt.getSourceMAC());
                            }
                            handleSupplicantPacket(context.inPacket());
                            break;
                        default:
                            // any other packets let the specific implementation handle
                            if (log.isTraceEnabled()) {
                                log.trace("Received packet-in from RADIUS server {} in enclosing packet {} from "
                                                  + "dev/port: {} with MacAddress {}", ethPkt, context.inPacket(),
                                          context.inPacket().receivedFrom(), ethPkt.getSourceMAC());
                            }
                            impl.handlePacketFromServer(context);
                    }
                } catch (Exception e) {
                    log.error("Error while processing packet", e);
                }
            });
        }

        /**
         * Creates and initializes common fields of a RADIUS packet.
         *
         * @param stateMachine state machine for the request
         * @param eapPacket    EAP packet
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

        private void handleEapolStart(InboundPacket inPacket, StateMachine stateMachine) {

            DeviceId deviceId = inPacket.receivedFrom().deviceId();
            PortNumber portNumber = inPacket.receivedFrom().port();
            Ethernet ethPkt = inPacket.parsed();
            MacAddress srcMac = ethPkt.getSourceMAC();

            log.debug("EAP packet: EAPOL_START from dev/port: {}/{} with MacAddress {}",
                      deviceId, portNumber, srcMac);
            stateMachine.setSupplicantConnectpoint(inPacket.receivedFrom());
            stateMachine.setSupplicantAddress(srcMac);
            stateMachine.start();

            aaaStatisticsManager.getAaaStats().incrementEapolStartReqRx();
            //send an EAP Request/Identify to the supplicant
            EAP eapPayload = new EAP(EAP.REQUEST, stateMachine.identifier(), EAP.ATTR_IDENTITY, null);
            if (ethPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                stateMachine.setPriorityCode(ethPkt.getPriorityCode());
            }
            Ethernet eth = buildEapolResponse(srcMac, MacAddress.valueOf(nasMacAddress),
                                              ethPkt.getVlanID(), EAPOL.EAPOL_PACKET,
                                              eapPayload, stateMachine.priorityCode());

            stateMachine.setVlanId(ethPkt.getVlanID());
            log.debug("Getting EAP identity from supplicant {}", stateMachine.supplicantAddress().toString());
            sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint(), false);
            aaaStatisticsManager.getAaaStats().incrementRequestIdFramesTx();
        }

        private void hangleEapolLogoff(InboundPacket inPacket, StateMachine stateMachine) {

            DeviceId deviceId = inPacket.receivedFrom().deviceId();
            PortNumber portNumber = inPacket.receivedFrom().port();
            Ethernet ethPkt = inPacket.parsed();
            MacAddress srcMac = ethPkt.getSourceMAC();

            log.debug("EAP packet: EAPOL_LOGOFF from dev/port: {}/{} with MacAddress {}",
                      deviceId, portNumber, srcMac);
            //posting the machine stat data for current supplicant device.
            if (stateMachine.getSessionTerminateReason() == null ||
                    stateMachine.getSessionTerminateReason().equals("")) {
                stateMachine.setSessionTerminateReason(
                        StateMachine.SessionTerminationReasons.SUPPLICANT_LOGOFF.getReason());
            }
            AaaSupplicantMachineStats obj = aaaSupplicantStatsManager.getSupplicantStats(stateMachine);
            aaaSupplicantStatsManager.getMachineStatsDelegate()
                    .notify(new AaaMachineStatisticsEvent(AaaMachineStatisticsEvent.Type.STATS_UPDATE, obj));
            if (stateMachine.state() == StateMachine.STATE_AUTHORIZED) {
                stateMachine.logoff();
                aaaStatisticsManager.getAaaStats().incrementEapolLogoffRx();
            }
            if (stateMachine.state() == StateMachine.STATE_IDLE) {
                aaaStatisticsManager.getAaaStats().incrementAuthStateIdle();
            }
        }

        private void handleForgedEapolChallengeAuth(StateMachine stateMachine) {
            stateMachine.requestAccess();

            log.info("Forging EAP auth challenge");
            byte[] challengeState = EapolPacketGenerator.hexStringToByteArray("19056d66190469d738db2f7dc1e02591");
            EAP eapPayload = EapolPacketGenerator.forgeEapolChallengeAuth();

            Ethernet eth = buildEapolResponse(stateMachine.supplicantAddress(),
                                              MacAddress.valueOf(nasMacAddress),
                                              stateMachine.vlanId(),
                                              EAPOL.EAPOL_PACKET,
                                              eapPayload, stateMachine.priorityCode());
            stateMachine.setChallengeInfo(eapPayload.getIdentifier(), challengeState);

            ConnectPoint supplicantCp = stateMachine.supplicantConnectpoint();
            MacAddress dstMac = stateMachine.supplicantAddress();
            log.info("Send FORGED EAP auth challenge to supplicant {} on dev/port: {}/{} with MacAddress {}",
                     supplicantCp.deviceId(), supplicantCp.port(), dstMac);

            sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint(),
                                   true);

            // NOTE do we care about stats?
        }

        private void handleForgedEapolSuccess(StateMachine stateMachine) {
            ConnectPoint supplicantCp = stateMachine.supplicantConnectpoint();
            MacAddress dstMac = stateMachine.supplicantAddress();
            log.info("Forging EAP auth success");
            EAP eapPayload = EapolPacketGenerator.forgeEapolSuccess();

            Ethernet eth = buildEapolResponse(stateMachine.supplicantAddress(),
                                              MacAddress.valueOf(nasMacAddress),
                                              stateMachine.vlanId(),
                                              EAPOL.EAPOL_PACKET,
                                              eapPayload, stateMachine.priorityCode());
            log.info("Send FORGED EAP success message to supplicant {} on dev/port: {}/{} with MacAddress {}",
                     supplicantCp.deviceId(), supplicantCp.port(), dstMac);
            sendPacketToSupplicant(eth, stateMachine.supplicantConnectpoint(), false);
            aaaStatisticsManager.getAaaStats().incrementEapolAuthSuccessTrans();

            stateMachine.authorizeAccess();
        }


        /**
         * Handles PAE packets (supplicant).
         *
         * @param inPacket Ethernet packet coming from the supplicant
         */
        private void handleSupplicantPacket(InboundPacket inPacket) {

            Ethernet ethPkt = inPacket.parsed();
            // Where does it come from?
            MacAddress srcMac = ethPkt.getSourceMAC();

            DeviceId deviceId = inPacket.receivedFrom().deviceId();
            PortNumber portNumber = inPacket.receivedFrom().port();
            String sessionId = inPacket.receivedFrom().toString();
            EAPOL eapol = (EAPOL) ethPkt.getPayload();

            if (log.isTraceEnabled()) {
                log.trace("Received EAPOL packet {} in enclosing packet {} from "
                                  + "dev/port: {}/{} with MacAddress {} and type {}",
                          eapol, ethPkt, deviceId, portNumber, srcMac, eapol.getEapolType());
            }

            short pktlen = eapol.getPacketLength();
            byte[] eapPayLoadBuffer = eapol.serialize();
            int len = eapPayLoadBuffer.length;
            if (len != (HEADER_LENGTH + pktlen)) {
                log.warn("Invalid EAPOL pkt length {} (shoudl be {}) for packet {} from dev/port: {}/{} " +
                          "with MacAddress {}, dropping it",
                          len, HEADER_LENGTH + pktlen, eapol, deviceId, portNumber, srcMac);
                aaaStatisticsManager.getAaaStats().incrementInvalidBodyLength();
                return;
            }
            if (!VALID_EAPOL_TYPE.contains(eapol.getEapolType())) {
                log.warn("Invalid EAPOL Type {} for packet {} from dev/port: {}/{} with MacAddress {}, dropping it",
                          eapol.getEapolType(), eapol, deviceId, portNumber, srcMac);
                aaaStatisticsManager.getAaaStats().incrementInvalidPktType();
                return;
            }
            if (pktlen >= 0 && ethPkt.getEtherType() == EthType.EtherType.EAPOL.ethType().toShort()) {
                aaaStatisticsManager.getAaaStats().incrementValidEapolFramesRx();
            }
            StateMachine stateMachine = stateMachines.computeIfAbsent(sessionId, id ->
                    new StateMachine(id, serverStatusAndStateMachineTimeoutExecutor));
            stateMachine.setEapolTypeVal(eapol.getEapolType());

            switch (eapol.getEapolType()) {
                case EAPOL.EAPOL_START:
                    handleEapolStart(inPacket, stateMachine);
                    break;
                case EAPOL.EAPOL_LOGOFF:
                    hangleEapolLogoff(inPacket, stateMachine);
                    break;
                case EAPOL.EAPOL_PACKET:

                    // check if this is a Response/Identify or  a Response/TLS
                    EAP eapPacket = (EAP) eapol.getPayload();
                    Byte identifier = new Byte(eapPacket.getIdentifier());

                    log.debug("EAP packet: EAPOL_PACKET from dev/port: {}/{} with MacAddress {} with Identifier {}",
                              deviceId, portNumber, srcMac, identifier.doubleValue());

                    byte dataType = eapPacket.getDataType();

                    switch (dataType) {
                        case EAP.ATTR_IDENTITY:
                            handleAttrIdentity(inPacket, srcMac, deviceId, portNumber,
                                               eapol, stateMachine, eapPacket, sessionId);
                            break;
                        case EAP.ATTR_MD5:
                            handleMD5(inPacket, srcMac, deviceId, portNumber, stateMachine,
                                      eapPacket, identifier, sessionId);
                            break;
                        case EAP.ATTR_TLS:
                            handleTls(inPacket, srcMac, deviceId, portNumber, stateMachine,
                                      eapPacket, identifier, sessionId);
                            break;
                        default:
                            log.warn("Unknown EAP packet type from dev/port: {}/{} with MacAddress {} and " +
                                     "Identifier {}", deviceId, portNumber, srcMac, eapPacket.getIdentifier() & 0xff);
                            return;
                    }
                    break;
                default:
                    log.debug("Skipping EAPOL message {} from dev/port: {}/{} with MacAddress {}",
                              eapol.getEapolType(), deviceId, portNumber, srcMac);
            }
            aaaStatisticsManager.getAaaStats().countTransRespNotNak();
            aaaStatisticsManager.getAaaStats().countEapolResIdentityMsgTrans();
        }

        private void handleAttrIdentity(InboundPacket inPacket, MacAddress srcMac, DeviceId deviceId,
                                        PortNumber portNumber, EAPOL eapol, StateMachine stateMachine,
                                        EAP eapPacket, String sessionId) {

            if (forgeEapolPackets) {
                handleForgedEapolChallengeAuth(stateMachine);
                return;
            } else {
                // get identifier for request and store mapping to session ID
                RequestIdentifier radiusIdentifier = idManager.getNewIdentifier(sessionId);
                if (radiusIdentifier == null) {
                    log.warn("Cannot get identifier supplicant at dev/port: {}/{} " +
                                      "with MacAddress {}, dropping packet",
                              deviceId, portNumber, srcMac);
                    return;
                }
                log.debug("EAP packet: EAPOL_PACKET ATTR_IDENTITY from dev/port: {}/{} with MacAddress {}" +
                                  " and Identifier {}", deviceId, portNumber, srcMac, eapPacket.getIdentifier() & 0xff);
                //Setting the time of this response from RG, only when its not a re-transmission.
                if (stateMachine.getLastPacketReceivedTime() == 0) {
                    stateMachine.setLastPacketReceivedTime(System.currentTimeMillis());
                }
                // request id access to RADIUS
                stateMachine.setUsername(eapPacket.getData());

                RADIUS radiusPayload = getRadiusPayload(stateMachine, radiusIdentifier.identifier(), eapPacket);
                radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);
                radiusPayload.addMessageAuthenticator(radiusSecret);

                if (log.isTraceEnabled()) {
                    log.trace("Sending ATTR_IDENTITY packet to RADIUS for supplicant at dev/port: " +
                                      "{}/{} with MacAddress {} and Identifier {}", deviceId, portNumber,
                              srcMac, radiusIdentifier.getReadableIdentifier());
                }

                sendRadiusPacket(radiusPayload, inPacket);
                stateMachine.setWaitingForRadiusResponse(true);
                aaaStatisticsManager.getAaaStats().incrementRadiusReqIdTx();
                aaaStatisticsManager.getAaaStats().incrementEapolAtrrIdentity();
                // change the state to "PENDING"
                if (stateMachine.state() == StateMachine.STATE_PENDING) {
                    aaaStatisticsManager.getAaaStats().increaseRequestReTx();
                    stateMachine.incrementTotalPacketsSent();
                    stateMachine.incrementTotalOctetSent(eapol.getPacketLength());
                }
                stateMachine.requestAccess();
            }
        }

        private void handleMD5(InboundPacket inPacket, MacAddress srcMac, DeviceId deviceId,
                               PortNumber portNumber, StateMachine stateMachine, EAP eapPacket,
                               Byte identifier, String sessionId) {
            // get identifier for request and store mapping to session ID
            RequestIdentifier radiusIdentifier = idManager.getNewIdentifier(sessionId);
            if (radiusIdentifier == null) {
                log.warn("Cannot get identifier supplicant at dev/port: {}/{} " +
                                  "with MacAddress {}, dropping packet",
                          deviceId, portNumber, srcMac);
                return;
            }

            log.debug("EAP packet: EAPOL_PACKET ATTR_MD5 from dev/port: {}/{} with MacAddress {}" +
                              " and Identifier {}", deviceId, portNumber, srcMac, eapPacket.getIdentifier() & 0xff);
            // verify if the EAP identifier corresponds to the
            // challenge identifier from the client state
            // machine.
            stateMachine.setLastPacketReceivedTime(System.currentTimeMillis());
            if (eapPacket.getIdentifier() == stateMachine.challengeIdentifier()) {
                //send the RADIUS challenge response
                if (forgeEapolPackets) {
                    handleForgedEapolSuccess(stateMachine);
                } else {
                    RADIUS radiusPayload = getRadiusPayload(stateMachine,
                                                            radiusIdentifier.identifier(), eapPacket);
                    radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);

                    if (stateMachine.challengeState() != null) {
                        radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                                   stateMachine.challengeState());
                    }
                    radiusPayload.addMessageAuthenticator(radiusSecret);
                    if (outPacketSupp.contains(eapPacket.getIdentifier())) {
                        aaaStatisticsManager.getAaaStats().decrementPendingReqSupp();
                        outPacketSupp.remove(identifier);
                    }
                    if (log.isTraceEnabled()) {
                        log.trace("Sending ATTR_MD5 packet to RADIUS for supplicant at dev/port: {}/{}" +
                                          " with MacAddress {} and Identifier {}", deviceId, portNumber, srcMac,
                                  radiusIdentifier.getReadableIdentifier());
                    }
                    sendRadiusPacket(radiusPayload, inPacket);
                    stateMachine.setWaitingForRadiusResponse(true);
                    aaaStatisticsManager.getAaaStats().incrementRadiusReqChallengeTx();
                    aaaStatisticsManager.getAaaStats().incrementEapolMd5RspChall();
                }
            } else {
                log.error("eapolIdentifier {} and stateMachine Identifier {} do not " +
                                  "correspond for packet from dev/port: {}/{} with MacAddress {}",
                          eapPacket.getIdentifier() & 0xff, stateMachine.challengeIdentifier() & 0xff,
                          deviceId, portNumber, srcMac);
                aaaStatisticsManager.getAaaStats().incrementEapolMd5RspChall();
                if (outPacketSupp.contains(eapPacket.getIdentifier())) {
                    aaaStatisticsManager.getAaaStats().decrementPendingReqSupp();
                    outPacketSupp.remove(identifier);
                }
                aaaStatisticsManager.getAaaStats().incrementEapolauthFailureTrans();
            }
        }


        private void handleTls(InboundPacket inPacket, MacAddress srcMac, DeviceId deviceId,
                               PortNumber portNumber, StateMachine stateMachine, EAP eapPacket,
                               Byte identifier, String sessionId) {
            // get identifier for request and store mapping to session ID
            RequestIdentifier radiusIdentifier = idManager.getNewIdentifier(sessionId);

            if (radiusIdentifier == null) {
                log.warn("Cannot get identifier supplicant at dev/port: {}/{} " +
                                  "with MacAddress {}, dropping packet", deviceId, portNumber, srcMac);
                return;
            }
            log.debug("EAP packet: EAPOL_PACKET ATTR_TLS from dev/port: {}/{} with MacAddress {} " +
                              "and Identifier {}", deviceId, portNumber, srcMac, eapPacket.getIdentifier() & 0xff);
            // request id access to RADIUS
            RADIUS radiusPayload = getRadiusPayload(stateMachine, radiusIdentifier.identifier(), eapPacket);
            radiusPayload = pktCustomizer.customizePacket(radiusPayload, inPacket);
            if (stateMachine.challengeState() != null) {
                radiusPayload.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                                           stateMachine.challengeState());
            }
            stateMachine.setRequestAuthenticator(radiusPayload.generateAuthCode());
            radiusPayload.addMessageAuthenticator(radiusSecret);
            if (outPacketSupp.contains(eapPacket.getIdentifier())) {
                aaaStatisticsManager.getAaaStats().decrementPendingReqSupp();
                outPacketSupp.remove(identifier);
            }
            if (log.isTraceEnabled()) {
                log.trace("Sending ATTR_TLS packet to RADIUS for supplicant at dev/port: {}/{} with " +
                                  "MacAddress {} and Identifier {}", deviceId, portNumber, srcMac,
                          radiusIdentifier.getReadableIdentifier());
            }
            sendRadiusPacket(radiusPayload, inPacket);
            stateMachine.setWaitingForRadiusResponse(true);
            aaaStatisticsManager.getAaaStats().incrementRadiusReqChallengeTx();
            aaaStatisticsManager.getAaaStats().incrementEapolTlsRespChall();
            if (stateMachine.state() != StateMachine.STATE_PENDING) {
                stateMachine.requestAccess();
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

            if (authenticationEvent.type() == AuthenticationEvent.Type.TIMEOUT) {
                handleStateMachineTimeout(authenticationEvent.subject());
            }

            AuthenticationRecord record = authenticationEvent.authenticationRecord();
            if (record == null) {
                authentications.remove(authenticationEvent.subject());
            } else {
                authentications.put(authenticationEvent.subject(), record);
            }

            post(authenticationEvent);
        }
    }

    private void handleStateMachineTimeout(ConnectPoint supplicantConnectPoint) {
        StateMachine stateMachine = stateMachines.remove(supplicantConnectPoint.toString());
        //pushing captured machine stats to kafka
        stateMachine.setSessionTerminateReason("Time out");
        AaaSupplicantMachineStats obj = aaaSupplicantStatsManager
                .getSupplicantStats(stateMachine);
        aaaSupplicantStatsManager.getMachineStatsDelegate()
                .notify(new AaaMachineStatisticsEvent(
                        AaaMachineStatisticsEvent.Type.STATS_UPDATE, obj));

        if (stateMachine.state() == StateMachine.STATE_PENDING && stateMachine.isWaitingForRadiusResponse()) {
            aaaStatisticsManager.getAaaStats().increaseTimedOutPackets();
        }

        StateMachine.deleteStateMachineMapping(stateMachine);
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
            if (newCfg.radiusSecret() != null && !newCfg.radiusSecret().equals(radiusSecret)) {
                radiusSecret = newCfg.radiusSecret();
                radiusOperationalStatusService.initialize(nasIpAddress.getAddress(), radiusSecret, impl);
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
                configureRadiusCommunication(false);
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

    private class InternalMapEventListener implements MapEventListener<ConnectPoint, AuthenticationRecord> {
        @Override
        public void event(MapEvent<ConnectPoint, AuthenticationRecord> event) {
            if (event.type() == MapEvent.Type.REMOVE) {
                // remove local state machine if user has requested remove
                StateMachine sm = stateMachines.remove(event.key().toString());
                if (sm != null) {
                    sm.stop();
                }
            }
        }
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            DeviceId deviceId = event.subject().id();
            log.debug("AAA received device event {} ", event);
            switch (event.type()) {
                case PORT_REMOVED:
                    PortNumber portNumber = event.port().number();
                    String sessionId = deviceId.toString() + "/" + portNumber.toString();
                    log.debug("Received PORT_REMOVED event. Clearing AAA Session with Id {}", sessionId);

                    flushStateMachineSession(sessionId,
                                             StateMachine.SessionTerminationReasons.PORT_REMOVED.getReason());

                    break;
                case DEVICE_REMOVED:
                    log.debug("Received DEVICE_REMOVED event for {}", deviceId);
                    clearAllSessionStateForDevice(deviceId);
                    break;

                default:
                    return;
            }
        }

        private void clearAllSessionStateForDevice(DeviceId deviceId) {
            Set<String> associatedSessions = Sets.newHashSet();
            for (Entry<String, StateMachine> stateMachineEntry : stateMachines.entrySet()) {
                ConnectPoint cp = stateMachineEntry.getValue().supplicantConnectpoint();
                if (cp != null && cp.deviceId().toString().equals(deviceId.toString())) {
                    associatedSessions.add(stateMachineEntry.getKey());
                }
            }

            for (String session : associatedSessions) {
                log.debug("Clearing AAA Session {} associated with Removed Device", session);
                flushStateMachineSession(session,
                                         StateMachine.SessionTerminationReasons.DEVICE_REMOVED.getReason());
            }
        }

        private void flushStateMachineSession(String sessionId, String terminationReason) {
            StateMachine stateMachine = stateMachines.get(sessionId);
            //flushing the state machine state requires also to remove the authenticated user.
            //the removal of the user might happen once the state machine is gone (app update)
            authentications.remove(ConnectPoint.fromString(sessionId));

            if (stateMachine == null) {
                // No active AAA sessions for this UNI port
                log.debug("No Active AAA Session found with Id {}", sessionId);
                return;
            }

            stateMachine.setSessionTerminateReason(terminationReason);

            //pushing captured machine stats to kafka
            AaaSupplicantMachineStats obj = aaaSupplicantStatsManager.getSupplicantStats(stateMachine);
            aaaSupplicantStatsManager.getMachineStatsDelegate()
                    .notify(new AaaMachineStatisticsEvent(AaaMachineStatisticsEvent.Type.STATS_UPDATE, obj));
            StateMachine removed = stateMachines.remove(sessionId);

            if (removed != null) {
                StateMachine.deleteStateMachineMapping(removed);
            }
        }
    }

    private class ServerStatusChecker implements Runnable {
        @Override
        public void run() {
            log.debug("Notifying RadiusOperationalStatusEvent");
            radiusOperationalStatusService.checkServerOperationalStatus();
            log.trace("--POSTING--" + radiusOperationalStatusService.getRadiusServerOperationalStatus());
            radiusOperationalStatusService.getRadiusOprStDelegate()
                    .notify(new RadiusOperationalStatusEvent(
                            RadiusOperationalStatusEvent.Type.RADIUS_OPERATIONAL_STATUS,
                            radiusOperationalStatusService.
                                    getRadiusServerOperationalStatus()));
        }

    }

    @Override
    public AaaSupplicantMachineStats getSupplicantMachineStats(String sessionId) {
        StateMachine aaaSupplicantMachine = stateMachines.get(sessionId);
        if (aaaSupplicantMachine != null) {
            return aaaSupplicantStatsManager.getSupplicantStats(aaaSupplicantMachine);
        } else {
            return null;
        }
    }
}
