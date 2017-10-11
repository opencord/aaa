package foo.opencord.aaa.impl;

import foo.opencord.aaa.api.AaaConfig;
import org.onlab.packet.EthType;
import org.onlab.packet.RADIUS;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;

/**
 * Defines the API for RADIUS server side communication.
 */
public interface RadiusCommunicator {

    /**
     * Initializes the communicator's local state, making ready to interact
     * with the RADIUS server. Configuration parameters relevant to the
     * specific implementation will be contained within the specified
     * configuration object.
     * *
     *
     * @param newCfg the new configuration to be applied
     */
    void initializeLocalState(AaaConfig newCfg);

    /**
     * Clears local state.
     */
    void clearLocalState();

    /**
     * Invoked when the AAA application is deactivated; time to shutdown.
     */
    void deactivate();

    /**
     * Provisions intercepts on the switches, if needed.
     */
    void requestIntercepts();

    /**
     * Clears intercepts from the switches, if previously provisioned.
     */
    void withdrawIntercepts();

    /**
     * Sends a RADIUS packet to the RADIUS server.
     *
     * @param radiusPacket RADIUS packet to be sent to server
     * @param eapolPacket  incoming EAPOL packet
     */
    void sendRadiusPacket(RADIUS radiusPacket, InboundPacket eapolPacket);

    /**
     * Handles a packet from the RADIUS server.
     * <p>
     * Note: this method is invoked for all intercepted packets that are
     * not of EtherType {@link EthType.EtherType#EAPOL EAPOL}.
     *
     * @param context incoming packet context
     */
    void handlePacketFromServer(PacketContext context);
}
