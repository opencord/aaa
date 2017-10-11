package foo.opencord.olt.impl;

import foo.opencord.aaa.api.PacketCustomizer;
import foo.opencord.aaa.impl.CustomizationInfo;
import org.onlab.packet.Ethernet;
import org.onlab.packet.RADIUS;
import org.onosproject.net.packet.InboundPacket;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Sample RADIUS Packet Customization.
 */
public class SamplePacketCustomizer extends PacketCustomizer {

    private final Logger log = getLogger(getClass());

    private final CustomizationInfo info;

    /**
     * Creates a packet customizer, configured with the given services.
     *
     * @param info device service and SADIS references
     */
    public SamplePacketCustomizer(CustomizationInfo info) {
        this.info = info;
    }

    @Override
    public RADIUS customizePacket(RADIUS inPkt, InboundPacket eapPacket) {

        // TODO: customize the packet

        return inPkt;
    }

    @Override
    public Ethernet customizeEthernetIPHeaders(Ethernet inPkt,
                                               InboundPacket eapPacket) {

        // TODO: customize the packet

        return inPkt;
    }
}
