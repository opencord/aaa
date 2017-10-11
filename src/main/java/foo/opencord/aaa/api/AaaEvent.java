package foo.opencord.aaa.api;

import org.onlab.packet.VlanId;
import org.onosproject.event.AbstractEvent;
import org.onosproject.net.ConnectPoint;

/**
 * Describes an authentication event.
 */
public class AaaEvent extends AbstractEvent<AaaEvent.Type, ConnectPoint> {

    private final VlanId cVlan;

    /**
     * Designates the type of authentication event.
     */
    public enum Type {
        /**
         * A supplicant has started an authorization request handshake.
         */
        AUTH_START,

        /**
         * A supplicant has submitted an authorization request.
         */
        AUTH_REQUEST_ACCESS,

        /**
         * The authorization request has been accepted.
         */
        ACCESS_AUTHORIZED,

        /**
         * The authorization request has been denied.
         */
        ACCESS_DENIED,

        /**
         * The supplicant has terminated the authenticated session.
         */
        AUTH_LOGOFF
    }

    /**
     * Creates an event of the given type, for the specified connect point and
     * C-Tag (may be null), and the current time.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     * @param cVlan   C-Tag associated with the event, if any
     */
    public AaaEvent(Type type, ConnectPoint subject, VlanId cVlan) {
        super(type, subject);
        this.cVlan = cVlan;
    }

    /**
     * Creates an event of the given type, for the specified connect point,
     * C-Tag (may be null), and time.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     * @param time    occurrence time
     * @param cVlan   C-Tag associated with the event, if any
     */
    public AaaEvent(Type type, ConnectPoint subject, long time, VlanId cVlan) {
        super(type, subject, time);
        this.cVlan = cVlan;
    }

    /**
     * Returns the C-Tag associated with the event.
     *
     * @return the C-VLAN
     */
    public VlanId cVlanId() {
        return cVlan;
    }
}
