package foo.opencord.aaa.impl;

import foo.opencord.aaa.api.AaaConfig;
import org.onlab.packet.RADIUS;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;

/**
 * Handles Socket based communication with the RADIUS server.
 */
public class SocketBasedRadiusCommunicator implements RadiusCommunicator {
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
}
