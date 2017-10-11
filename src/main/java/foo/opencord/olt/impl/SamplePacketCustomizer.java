package foo.opencord.olt.impl;

import foo.opencord.aaa.api.PacketCustomizer;
import foo.opencord.aaa.impl.CustomizationInfo;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Sample RADIUS Packet Customization.
 */
public class SamplePacketCustomizer extends PacketCustomizer {

    private final Logger log = getLogger(getClass());

    /**
     * Creates a packet customizer, configured with the given services.
     *
     * @param info device service and SADIS references
     */
    public SamplePacketCustomizer(CustomizationInfo info) {
        super(info);
    }
}
