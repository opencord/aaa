/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.opencord.aaa.api;

import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.event.AbstractEvent;
import org.onosproject.net.ConnectPoint;

import java.util.Objects;

/**
 * Describes an authentication event. Note that the subject of the event
 * is a {@link ConnectPoint}, but the event also carries fields for
 * a {@link VlanId VLAN} and {@link org.onlab.packet.MacAddress MAC} to
 * be specified if desired.
 */
public class AaaEvent extends AbstractEvent<AaaEvent.Type, ConnectPoint> {

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

    // a VLAN associated with the event
    private final VlanId vlanId;

    // a MAC address associated with the event
    private final MacAddress macAddress;

    /**
     * Creates an event of the given type, for the specified connect point and
     * the current time.
     * The VLAN and MAC fields are left as null.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     */
    public AaaEvent(Type type, ConnectPoint subject) {
        super(type, subject);
        vlanId = null;
        macAddress = null;
    }

    /**
     * Creates an event of the given type, for the specified connect point,
     * and time.
     * The VLAN and MAC fields are left as null.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     * @param time    occurrence time
     */
    public AaaEvent(Type type, ConnectPoint subject, long time) {
        super(type, subject, time);
        vlanId = null;
        macAddress = null;
    }

    /**
     * Creates an event of the given type, for the specified connect point and
     * the current time.
     * Additionally, associated VLAN and MAC may be defined (null permitted).
     *
     * @param type       authentication event type
     * @param subject    event connect point subject
     * @param vlanId     a VLAN associated with this event (or null)
     * @param macAddress a MAC address associated with ths event (or null)
     */
    public AaaEvent(Type type, ConnectPoint subject, VlanId vlanId,
                    MacAddress macAddress) {
        super(type, subject);
        this.vlanId = vlanId;
        this.macAddress = macAddress;
    }

    /**
     * Creates an event of the given type, for the specified connect point,
     * and time.
     * Additionally, associated VLAN and MAC may be defined (null permitted).
     *
     * @param type       authentication event type
     * @param subject    event connect point subject
     * @param time       occurrence time
     * @param vlanId     a VLAN associated with this event
     * @param macAddress a MAC address associated with ths event (or null)
     */
    public AaaEvent(Type type, ConnectPoint subject, long time, VlanId vlanId,
                    MacAddress macAddress) {
        super(type, subject, time);
        this.vlanId = vlanId;
        this.macAddress = macAddress;
    }

    /**
     * Returns the VLAN ID associated with this event (may be null).
     *
     * @return the associated VLAN ID
     */
    public VlanId vlanId() {
        return vlanId;
    }

    /**
     * Returns the MAC address associated with this event (may be null).
     *
     * @return the associated MAC address
     */
    public MacAddress macAddress() {
        return macAddress;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof AaaEvent) {
            final AaaEvent other = (AaaEvent) o;
            return Objects.equals(this.type(), other.type()) &&
                    Objects.equals(this.subject(), other.subject()) &&
                    Objects.equals(this.time(), other.time()) &&
                    Objects.equals(this.vlanId(), other.vlanId()) &&
                    Objects.equals(this.macAddress(), other.macAddress());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(type(), subject(), time(), vlanId(), macAddress());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        int len = sb.length();
        sb.replace(len - 1, len, ", ");
        sb.append("vlanId=").append(vlanId)
                .append(", mac=").append(macAddress)
                .append("}");
        return sb.toString();
    }
}
