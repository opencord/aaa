package foo.opencord.aaa.impl;

import com.google.common.collect.Maps;
import foo.opencord.aaa.api.AaaConfig;
import foo.opencord.aaa.api.PacketCustomizer;
import org.onlab.packet.RADIUS;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Handles communication with the RADIUS server through ports
 * of the SDN switches.
 */
public class PortBasedRadiusCommunicator implements RadiusCommunicator {

    private final Logger log = getLogger(getClass());
    private final ApplicationId appId;

    private final PacketService packetService;
    private final MastershipService mastershipService;
    private final DeviceService deviceService;
    private final SubscriberAndDeviceInformationService subsService;
    private final AaaManager aaaManager;

    private PacketCustomizer pktCustomizer;


    PortBasedRadiusCommunicator(ApplicationId appId, PacketService pktService,
                                MastershipService masService, DeviceService devService,
                                SubscriberAndDeviceInformationService subsService,
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


    // NOTE: This should be the same implementation as the existing class

    @Override
    public void initializeLocalState(AaaConfig newCfg) {

    }

    @Override
    public void clearLocalState() {

    }

    @Override
    public void deactivate() {

    }

    @Override
    public void requestIntercepts() {

    }

    @Override
    public void withdrawIntercepts() {

    }

    @Override
    public void sendRadiusPacket(RADIUS radiusPacket, InboundPacket eapolPacket) {

    }


    @Override
    public void handlePacketFromServer(PacketContext context) {

    }

    @Override
    public void setPacketCustomizer(PacketCustomizer customizer) {
        pktCustomizer = customizer;
    }
}
