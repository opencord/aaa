package org.opencord.aaa;

/**
 * Maintains information about a subscriber including VLAN tags and NAS information.
 */
public class Info {

    private final short stag;
    private final short ctag;
    private final String nasPortId;
    private final int nasPortType;
    private final int nasPort;
    private final String sessionId;

    public Info(short stag, short ctag, String nasPortId, int nasPortType, int nasPort, String sessionId) {
        this.stag = stag;
        this.ctag = ctag;
        this.nasPortId = nasPortId;
        this.nasPortType = nasPortType;
        this.nasPort = nasPort;
        this.sessionId = sessionId;
    }

    public short stag() {
        return stag;
    }

    public short ctag() {
        return ctag;
    }

    public String nasPortId() {
        return nasPortId;
    }

    public int nasPortType() {
        return nasPortType;
    }

    public int nasPort() {
        return nasPort;
    }

    public String sessionId() {
        return sessionId;
    }
}
