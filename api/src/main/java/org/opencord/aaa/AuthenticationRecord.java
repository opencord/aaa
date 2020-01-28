/*
 * Copyright 2020-present Open Networking Foundation
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

    private final long lastChanged;

    /**
     * Creates a new authentication record.
     *
     * @param supplicantConnectPoint connect point
     * @param username user name
     * @param supplicantAddress MAC address of supplicant
     * @param state authentication state
     * @param lastChanged timestamp of latest activity
     */
    public AuthenticationRecord(ConnectPoint supplicantConnectPoint, byte[] username,
                                MacAddress supplicantAddress, String state, long lastChanged) {
        this.supplicantConnectPoint = supplicantConnectPoint;
        this.username = username;
        this.supplicantAddress = supplicantAddress;
        this.state = state;
        this.lastChanged = lastChanged;
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

    /**
     * Gets the timestamp of the last activity on this authentication.
     *
     * @return timestamp
     */
    public long lastChanged() {
        return lastChanged;
    }
}
