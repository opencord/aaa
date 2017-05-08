/*
 *
 * Copyright 2015 AT&T Foundry
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opencord.aaa;

import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Information regarding an user authenticated by AAA.
 */

class AaaUserInfo {
    private byte[] username;
    // Supplicant connectivity info
    private ConnectPoint supplicantConnectpoint;
    private MacAddress supplicantAddress;
    private String state;
    private String otherInfo = "None";

    public AaaUserInfo(byte[] username) {
        this.username = username;
    }

    /**
     * Sets Information regarding this user.
     *
     * @return none
     */
    public void setInfo(ConnectPoint cp, MacAddress addr, String state) {
        this.supplicantAddress = addr;
        this.supplicantConnectpoint = cp;
        this.state = state;
    }

    /**
     * Gets the ConnectPoint of the user.
     *
     * @return connectPoint of user
     */
    public ConnectPoint connectPoint() {
        return supplicantConnectpoint;
    }

    /**
     * Gets the DeviceId of the user.
     *
     * @return deviceId of user
     */
    public DeviceId deviceId() {
        return supplicantConnectpoint.deviceId();
    }

    /**
     * Gets the PortNumber of the user.
     *
     * @return port number of user
     */
    public PortNumber port() {
        return supplicantConnectpoint.port();
    }

    /**
     * Gets the username of the user.
     *
     * @return username of user
     */
    public byte[] userName() {
        return username;
    }

    /**
     * Gets the Mac Address of the user.
     *
     * @return MacAddress of user
     */
    public MacAddress macAddress() {
        return this.supplicantAddress;
    }

    /**
     * Gets the current state of the user.
     *
     * @return current state of user
     */
    public String state() {
        return this.state;
    }

    /**
     * Sets more information for the the user.
     *
     * @return
     */
    public void setOtherInfo(String otherInfo) {
        this.otherInfo = otherInfo;
    }

    /**
     * Gets the additional information of the user.
     *
     * @return otherInfo of user
     */
    public String otherInfo() {
        return this.otherInfo;
    }
}
