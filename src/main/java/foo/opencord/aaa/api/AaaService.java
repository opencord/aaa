package foo.opencord.aaa.api;

/**
 * Service API for interacting with the AAA application.
 */
public interface AaaService {

    /**
     * Registers a packet customizer with AAA, to be used to customize
     * packets issued to and from the RADIUS server.
     *
     * @param customizer the customizer to register
     */
    void registerPacketCustomizer(PacketCustomizer customizer);

    /**
     * Unregisters the given packet customizer from AAA.
     * <p>
     * Note: AAA will revert to a default customizer, that does no
     * customization of the packets.
     *
     * @param customizer the customizer to unregister
     */
    void unregisterPacketCustomizer(PacketCustomizer customizer);

}
