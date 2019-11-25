package org.opencord.aaa.impl;

import java.util.Objects;

/**
 * An identifier for an authentication request.
 */
public final class RequestIdentifier {

    private byte identifier;

    /**
     * Creates a new request identifier.
     *
     * @param identifier id number
     */
    private RequestIdentifier(byte identifier) {
        this.identifier = identifier;
    }

    /**
     * Returns the id number.
     *
     * @return id
     */
    public byte identifier() {
        return this.identifier;
    }

    /**
     * Creates a new request identifier.
     *
     * @param identifier id number
     * @return identifier
     */
    public static RequestIdentifier of(byte identifier) {
        return new RequestIdentifier(identifier);
    }

    public boolean equals(Object other) {
        if (!(other instanceof RequestIdentifier)) {
            return false;
        }

        RequestIdentifier that = (RequestIdentifier) other;

        return identifier == that.identifier;
    }

    public int hashCode() {
        return Objects.hashCode(identifier);
    }
}
