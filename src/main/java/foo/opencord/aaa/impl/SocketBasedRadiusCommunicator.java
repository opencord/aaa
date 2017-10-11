package foo.opencord.aaa.impl;

import foo.opencord.aaa.api.AaaConfig;
import foo.opencord.aaa.api.PacketCustomizer;
import org.onlab.packet.RADIUS;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Handles Socket based communication with the RADIUS server.
 */
public class SocketBasedRadiusCommunicator implements RadiusCommunicator {

    private final Logger log = getLogger(getClass());

    private final ApplicationId appId;

    private final PacketService packetService;

    private final AaaManager aaaManager;

    SocketBasedRadiusCommunicator(ApplicationId appId,
                                  PacketService packetService,
                                  AaaManager aaaManager) {
        this.appId = appId;
        this.packetService = packetService;
        this.aaaManager = aaaManager;
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
        log.warn("Attempting to set packet customizer on socket-based RADIUS " +
                         "communicator: {}", customizer.getClass().getName());
    }
}
