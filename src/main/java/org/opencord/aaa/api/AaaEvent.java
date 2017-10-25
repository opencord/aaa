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

import org.onlab.packet.VlanId;
import org.onosproject.event.AbstractEvent;
import org.onosproject.net.ConnectPoint;

import java.util.Objects;

/**
 * Describes an authentication event.
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

    /**
     * Creates an event of the given type, for the specified connect point and
     * the current time.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     */
    public AaaEvent(Type type, ConnectPoint subject) {
        super(type, subject);
        vlanId = null;
    }

    /**
     * Creates an event of the given type, for the specified connect point,
     * and time.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     * @param time    occurrence time
     */
    public AaaEvent(Type type, ConnectPoint subject, long time) {
        super(type, subject, time);
        vlanId = null;
    }

    /**
     * Creates an event of the given type, for the specified connect point and
     * the current time.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     * @param vlanId  a VLAN associated with this event
     */
    public AaaEvent(Type type, ConnectPoint subject, VlanId vlanId) {
        super(type, subject);
        this.vlanId = vlanId;
    }

    /**
     * Creates an event of the given type, for the specified connect point,
     * and time.
     *
     * @param type    authentication event type
     * @param subject event connect point subject
     * @param time    occurrence time
     * @param vlanId  a VLAN associated with this event
     */
    public AaaEvent(Type type, ConnectPoint subject, long time, VlanId vlanId) {
        super(type, subject, time);
        this.vlanId = vlanId;
    }

    /**
     * Returns the VLAN ID associated with this event.
     *
     * @return the associated VLAN ID
     */
    public VlanId vlanId() {
        return vlanId;
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
                    Objects.equals(this.vlanId(), other.vlanId());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(type(), subject(), time(), vlanId());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        int len = sb.length();
        sb.replace(len - 1, len, ", ");
        sb.append("vlanId=").append(vlanId).append("}");
        return sb.toString();
    }
}
