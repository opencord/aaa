/*
  Copyright 2015-present Open Networking Foundation
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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.basics.BasicElementConfig;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.ImmutableSet;

/**
 * Network config for the AAA app.
 */
public class AaaConfig extends Config<ApplicationId> {

    private static final String RADIUS_HOST = "radiusHost";
    private static final String RADIUS_IP = "radiusIp";
    private static final String RADIUS_SERVER_PORT = "radiusServerPort";
    public static final String CLEANUP_TIMER_TIMEOUT_IN_MINS = "cleanupTimerTimeoutInMins";
    private static final String RADIUS_MAC = "radiusMac";
    private static final String NAS_IP = "nasIp";
    private static final String NAS_MAC = "nasMac";
    private static final String RADIUS_SECRET = "radiusSecret";
    private static final String RADIUS_VLAN_ID = "vlanId";
    private static final String RADIUS_VLAN_PRIORITY_BIT = "radiusPBit";
    private static final String RADIUS_CONNECTION_TYPE = "radiusConnectionType";
    private static final String RADIUS_SERVER_CONNECTPOINTS = "radiusServerConnectPoints";
    // Which packet customizer to use
    // "packetCustomizer" : "sample" -- Means use SamplePAcketCustomizer
    // "packetCustomizer" : "default" -- No customization of packets
    // if param is missing it is treated as default
    // This class should be a subclass of PacketCustomizer
    private static final String PACKET_CUSTOMIZER = "packetCustomizer";

    // RADIUS server IP address
    protected static final String DEFAULT_RADIUS_IP = "10.128.10.4";

    // RADIUS MAC address
    public static final String DEFAULT_RADIUS_MAC = "00:00:00:00:01:10";

    // NAS IP address
    public static final String DEFAULT_NAS_IP = "10.128.9.244";

    // NAS MAC address
    public static final String DEFAULT_NAS_MAC = "00:00:00:00:10:01";

    // RADIUS server shared secret
    protected static final String DEFAULT_RADIUS_SECRET = "ONOSecret";

    // Radius Server UDP Port Number
    protected static final String DEFAULT_RADIUS_SERVER_PORT = "1812";

    // Time configured for triggering timeouts in AAA app
    protected static final String DEFAULT_CLEANUP_TIMER_TIMEOUT_IN_MINS = "10";

    // Radius Server Vlan ID
    protected static final String DEFAULT_RADIUS_VLAN_ID = "4093";

    // Radius Sever P-Bit
    protected static final String DEFAULT_RADIUS_VLAN_PRIORITY_BIT = "3";

    // Whether to use socket or not to communicate with RADIUS Server
    protected static final String DEFAULT_RADIUS_CONNECTION_TYPE = "socket";

    // Packet Customizer Default value
    protected static final String DEFAULT_PACKET_CUSTOMIZER = "default";

    /**
     * Gets the value of a string property, protecting for an empty JSON object.
     *
     * @param name         name of the property
     * @param defaultValue default value if none has been specified
     * @return String value if one os found, default value otherwise
     */
    private String getStringProperty(String name, String defaultValue) {
        if (object == null) {
            return defaultValue;
        }
        return get(name, defaultValue);
    }

    /**
     * Returns the NAS ip.
     *
     * @return ip address or null if not set
     */
    public InetAddress nasIp() {
        try {
            return InetAddress.getByName(getStringProperty(NAS_IP, DEFAULT_NAS_IP));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /**
     * Sets the NAS ip.
     *
     * @param ip new ip address; null to clear
     * @return self
     */
    public BasicElementConfig nasIp(String ip) {
        return (BasicElementConfig) setOrClear(NAS_IP, ip);
    }

    public String radiusHostName() {
        return getStringProperty(RADIUS_HOST, null);
    }

    /**
     * Returns the RADIUS server ip.
     *
     * @return ip address or null if not set
     */
    public InetAddress radiusIp() {
        try {
            return InetAddress.getByName(getStringProperty(RADIUS_IP, DEFAULT_RADIUS_IP));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /**
     * Sets the RADIUS server ip.
     *
     * @param ip new ip address; null to clear
     * @return self
     */
    public BasicElementConfig radiusIp(String ip) {
        return (BasicElementConfig) setOrClear(RADIUS_IP, ip);
    }

    /**
     * Returns the RADIUS MAC address.
     *
     * @return mac address or null if not set
     */
    public String radiusMac() {
        return getStringProperty(RADIUS_MAC, DEFAULT_RADIUS_MAC);
    }

    /**
     * Sets the RADIUS MAC address.
     *
     * @param mac new MAC address; null to clear
     * @return self
     */
    public BasicElementConfig radiusMac(String mac) {
        return (BasicElementConfig) setOrClear(RADIUS_MAC, mac);
    }

    /**
     * Returns the RADIUS MAC address.
     *
     * @return mac address or null if not set
     */
    public String nasMac() {
        return getStringProperty(NAS_MAC, DEFAULT_NAS_MAC);
    }

    /**
     * Sets the RADIUS MAC address.
     *
     * @param mac new MAC address; null to clear
     * @return self
     */
    public BasicElementConfig nasMac(String mac) {
        return (BasicElementConfig) setOrClear(NAS_MAC, mac);
    }

    /**
     * Returns the RADIUS secret.
     *
     * @return radius secret or null if not set
     */
    public String radiusSecret() {
        return getStringProperty(RADIUS_SECRET, DEFAULT_RADIUS_SECRET);
    }

    /**
     * Sets the RADIUS secret.
     *
     * @param secret new MAC address; null to clear
     * @return self
     */
    public BasicElementConfig radiusSecret(String secret) {
        return (BasicElementConfig) setOrClear(RADIUS_SECRET, secret);
    }

    /**
     * Returns the RADIUS server UDP port.
     *
     * @return radius server UDP port.
     */
    public short radiusServerUdpPort() {
        return Short.parseShort(getStringProperty(RADIUS_SERVER_PORT, DEFAULT_RADIUS_SERVER_PORT));
    }

    /**
     * Sets the RADIUS port.
     *
     * @param port new RADIUS UDP port; -1 to clear
     * @return self
     */
    public BasicElementConfig radiusServerUdpPort(short port) {
        return (BasicElementConfig) setOrClear(RADIUS_SERVER_PORT, (long) port);
    }

    /**
     * Returns the RADIUS server vlan ID.
     *
     * @return Radius Server VLan id or default if not set
     */
    public short radiusServerVlanId() {
        return Short.parseShort(getStringProperty(RADIUS_VLAN_ID, DEFAULT_RADIUS_VLAN_ID));
    }

    /**
     * Returns the type of connection to use to communicate with the RADIUS Server.
     *
     * @return "socket" or "packet_out"
     */
    public String radiusConnectionType() {
        return getStringProperty(RADIUS_CONNECTION_TYPE, DEFAULT_RADIUS_CONNECTION_TYPE);
    }

    /**
     * Returns the RADIUS server p-bit.
     *
     * @return Radius Server P-bit to use, default if not set
     */
    public byte radiusServerPBit() {
        return Byte.parseByte(getStringProperty(RADIUS_VLAN_PRIORITY_BIT, DEFAULT_RADIUS_VLAN_PRIORITY_BIT));
    }

    /**
     * Returns the PACKET CUSTOMIZER CLASS NAME.
     *
     * @return PACKET CUSTOMIZER, default if not set
     */
    public String radiusPktCustomizer() {
        return getStringProperty(PACKET_CUSTOMIZER, DEFAULT_PACKET_CUSTOMIZER);
    }

    /**
     * Returns the time configured for checking timeout .
     *
     * @return timerTimeout
     */
    public int cleanupTimerTimeoutInMins() {
        return Integer
                .parseInt(getStringProperty(CLEANUP_TIMER_TIMEOUT_IN_MINS, DEFAULT_CLEANUP_TIMER_TIMEOUT_IN_MINS));
    }

    /**
     * Returns the List of ConnectPoints to reach the Radius Server.
     *
     * @return List of ConnectPoints
     */
    public Set<ConnectPoint> radiusServerConnectPoints() {
        if (object == null) {
            return new HashSet<ConnectPoint>();
        }

        if (!object.has(RADIUS_SERVER_CONNECTPOINTS)) {
            return ImmutableSet.of();
        }

        ImmutableSet.Builder<ConnectPoint> builder = ImmutableSet.builder();
        ArrayNode arrayNode = (ArrayNode) object.path(RADIUS_SERVER_CONNECTPOINTS);
        for (JsonNode jsonNode : arrayNode) {
            String portName = jsonNode.asText(null);
            if (portName == null) {
                return null;
            }
            try {
                builder.add(ConnectPoint.deviceConnectPoint(portName));
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return builder.build();
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
