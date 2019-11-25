package org.opencord.aaa;

import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;

/**
 * Describes state of an authentication attempt.
 */
public class AuthenticationRecord {

    private final ConnectPoint supplicantConnectPoint;

    private final byte[] username;

    private final MacAddress supplicantAddress;

    private final String state;

    /**
     * Creates a new authentication record.
     *
     * @param supplicantConnectPoint connect point
     * @param username user name
     * @param supplicantAddress MAC address of supplicant
     * @param state authentication state
     */
    public AuthenticationRecord(ConnectPoint supplicantConnectPoint, byte[] username,
                                MacAddress supplicantAddress, String state) {
        this.supplicantConnectPoint = supplicantConnectPoint;
        this.username = username;
        this.supplicantAddress = supplicantAddress;
        this.state = state;
    }

    /**
     * Gets the connect point of supplicant.
     *
     * @return connect point
     */
    public ConnectPoint supplicantConnectPoint() {
        return supplicantConnectPoint;
    }

    /**
     * Gets the username of supplicant.
     *
     * @return username
     */
    public byte[] username() {
        return username;
    }

    /**
     * Gets the MAC address of the supplicant.
     *
     * @return MAC address
     */
    public MacAddress supplicantAddress() {
        return supplicantAddress;
    }

    /**
     * Gets the current state of the authentication attempt.
     *
     * @return state
     */
    public String state() {
        return state;
    }
}
