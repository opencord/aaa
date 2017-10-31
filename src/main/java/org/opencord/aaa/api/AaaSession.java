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
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Represents an AAA authentication session.
 */
public final class AaaSession {
    // This defines supplicant device and port
    private final ConnectPoint supplicantConnectPoint;

    // User name associated with this session
    private final String username;

    // MAC associated with this session
    private final MacAddress supplicantMacAddress;

    // TODO: Review why isn't vlanId of type VlanId ??
    // VLAN from the EAP eth packet
    private final short vlanId;

    // VLAN from subscriber info : C-Tag
    private final VlanId ctag;

    // Current authentication state of this session
    private final AaaAuthState state;

    /**
     * Constructs an immutable AAA session description.
     *
     * @param supplicantConnectPoint the supplicant connect point
     * @param username               the associated user name
     * @param supplicantMacAddress   the associated mac address
     * @param vlanId                 the VLAN ID
     * @param ctag                   the C-TAG VLAN ID
     * @param state                  the current authentication state
     */
    public AaaSession(ConnectPoint supplicantConnectPoint, String username,
                      MacAddress supplicantMacAddress, short vlanId, VlanId ctag,
                      AaaAuthState state) {
        this.supplicantConnectPoint = supplicantConnectPoint;
        this.username = username;
        this.supplicantMacAddress = supplicantMacAddress;
        this.vlanId = vlanId;
        this.ctag = ctag;
        this.state = state;
    }

    /**
     * The supplicant connect point.
     *
     * @return the connect point
     */
    public ConnectPoint getConnectPoint() {
        return supplicantConnectPoint;
    }

    /**
     * The device identifier of the supplicant connect point.
     *
     * @return the device identifier
     */
    public DeviceId deviceId() {
        return supplicantConnectPoint.deviceId();
    }

    /**
     * The port number of the supplicant connect point.
     *
     * @return the port number
     */
    public PortNumber portNumber() {
        return supplicantConnectPoint.port();
    }

    /**
     * The user name of the supplicant.
     *
     * @return the user name
     */
    public String username() {
        return username;
    }

    /**
     * The MAC address of the supplicant.
     *
     * @return the MAC address
     */
    public MacAddress macAddress() {
        return supplicantMacAddress;
    }

    // TODO: Review this description of vlanId for correctness

    /**
     * The VLAN identifier for the supplicant connection.
     *
     * @return the VLAN ID
     */
    public short vlanId() {
        return vlanId;
    }

    // TODO: Review - does this make sense in the general (other-than-VOLTHA) case?

    /**
     * The C-TAG associated with this supplicant's session.
     *
     * @return the C-TAG VLAN ID
     */
    public VlanId cTag() {
        return ctag;
    }

    /**
     * The current state of this session.
     *
     * @return the session state
     */
    public AaaAuthState state() {
        return state;
    }
}
