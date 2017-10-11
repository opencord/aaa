package foo.opencord.aaa.api;

import foo.opencord.aaa.impl.CustomizationInfo;
import org.onlab.packet.Ethernet;
import org.onlab.packet.RADIUS;
import org.onosproject.net.packet.InboundPacket;

/**
 * Facilitates the customization of RADIUS packets.
 * <p>
 * This default implementation does not change the packet.
 * <p>
 * Subclasses should override the appropriate methods to fill in attributes
 * according to the specifics of the RADIUS server set up.
 */
public class PacketCustomizer {

    // encapsulates device service and SADIS
    protected CustomizationInfo customInfo;

    /**
     * Creates a packet customizer, configured with the given services.
     *
     * @param info device service and SADIS references
     */
    public PacketCustomizer(CustomizationInfo info) {
        this.customInfo = info;
    }

    /**
     * Customize the packet as per specific Setup or RADIUS server requirements.
     *
     * @param inPkt     RADIUS packet to be customized
     * @param eapPacket Incoming packet containing EAP for which this RADIUS
     *                  message is being created
     * @return Customized RADIUS packet
     */
    public RADIUS customizePacket(RADIUS inPkt, InboundPacket eapPacket) {
        return inPkt;
    }

    /**
     * Customize the Ethernet header as per specific Setup or RADIUS
     * server requirements.
     *
     * @param inPkt     Ethernet packet to be changed
     * @param eapPacket Incoming packet containing EAP for which this the
     *                  RADIUS message is being created
     * @return Changed Ethernet packet
     */
    public Ethernet customizeEthernetIPHeaders(Ethernet inPkt,
                                               InboundPacket eapPacket) {
        return inPkt;
    }
}
