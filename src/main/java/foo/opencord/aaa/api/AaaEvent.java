package foo.opencord.aaa.api;

import org.onosproject.event.AbstractEvent;
import org.onosproject.net.ConnectPoint;

/**
 * Describes an authentication event.
 */
public class AaaEvent extends AbstractEvent<AaaEvent.Type, ConnectPoint> {

    // TODO: do we need additional data in the event?
    // we have connect point (device and port) as the subject
    // but do we want additional identification?
    //  some generic value that might be associated with subscriber? /

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
     * Creates an event of the given type, for the specified connect point
     * and the current time.
     *
     * @param type authentication event type
     * @param subject event connect point subject
     */
    protected AaaEvent(Type type, ConnectPoint subject) {
        super(type, subject);
    }

    /**
     * Creates an event of the given type, for the specified connect point
     * and time.
     *
     * @param type authentication event type
     * @param subject event connect point subject
     * @param time occurrence time
     */
    protected AaaEvent(Type type, ConnectPoint subject, long time) {
        super(type, subject, time);
    }
}
