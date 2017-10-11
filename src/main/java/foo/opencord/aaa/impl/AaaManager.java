package foo.opencord.aaa.impl;

import foo.opencord.aaa.api.AaaConfig;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;

import java.net.InetAddress;

import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * AAA application: interacts with a RADIUS server and, if available,
 * Subscriber And Device Information Service (SADIS).
 */
@Component(immediate = true)
public class AaaManager {

    private static final String APP_NAME = "org.opencord.aaa";

    // for verbose output
    private final Logger log = getLogger(getClass());


    // === Service Dependencies

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry netCfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    // === Radius Configuration

    // NAS IP address
    protected InetAddress nasIpAddress;

    // self MAC address
    protected static String nasMacAddress;

    // Parsed RADIUS server address
    protected InetAddress radiusIpAddress;

    // MAC address of RADIUS server or next-hop router
    protected String radiusMacAddress;

    // RADIUS server secret
    protected String radiusSecret;

    // Type of connection to use to communicate with Radius server;
    // options are "socket" (default) or "packet_out"
    private String radiusConnectionType;

    // packet customizer to use; options are "default" (default) or "sample"
    private String packetCustomizerType;


    // === Internal State

    // our unique identifier
    private ApplicationId appId;

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

    // Processor for handling packets
//    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    // TODO:


    // Communicator implementation to communicate with the RADIUS server.
    // (socket-based or packet_out-based)
    private RadiusCommunicator radComm = null;


    // ===


    @Activate
    public void activate() {

        registration();

        configureRadiusComms();


        /*


        customInfo = new CustomizationInfo(subsService, deviceService);

        switch (customizer.toLowerCase()) {
            case "sample":
                pktCustomizer = new SamplePacketCustomizer(customInfo);
                log.info("Created SamplePacketCustomizer");
                break;
            default:
                pktCustomizer = new PacketCustomizer(customInfo);
                log.info("Created default PacketCustomizer");
                break;
        }

        if (radiusConnectionType.toLowerCase().equals("socket")) {
            impl = new SocketBasedRadiusCommunicator(appId, packetService, this);
        } else {
            impl = new PortBasedRadiusCommunicator(appId, packetService, mastershipService,
                    deviceService, subsService, pktCustomizer, this);
        }

        StateMachine.initializeMaps();
        StateMachine.setAccessDeviceService(accessDeviceService);

        impl.initializeLocalState(newCfg);
        netCfgService.addListener(cfgListener);

        impl.requestIntercepts();

        log.info("Started");

        */

    }

    private void registration() {
        netCfgService.registerConfigFactory(factory);
        appId = coreService.registerApplication(APP_NAME);

//        packetService.addProcessor(processor, PacketProcessor.director(2));
        // TODO

    }

    private void configureRadiusComms() {
        AaaConfig cfg = netCfgService.getConfig(appId, AaaConfig.class);
        cfgListener.reconfigureRadiusSettings(cfg);

    }

    @Deactivate
    public void deactivate() {
/*
       impl.withdrawIntercepts();
        // de-register and null our handler
        packetService.removeProcessor(processor);
        processor = null;
        StateMachine.destroyMaps();
        netCfgService.removeListener(cfgListener);
        impl.deactivate();

        log.info("Stopped");
 */
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
            packetCustomizerType = newCfg.radiusPktCustomizer();

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


    // NOTE : This is WIP
}
