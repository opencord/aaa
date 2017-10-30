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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.ImmutableSet;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.basics.BasicElementConfig;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

import static org.onosproject.net.ConnectPoint.deviceConnectPoint;

/**
 * Network configuration for the AAA application.
 */
public class AaaConfig extends Config<ApplicationId> {

    private static final String RADIUS_IP = "radiusIp";
    private static final String RADIUS_SERVER_PORT = "radiusServerPort";
    private static final String RADIUS_MAC = "radiusMac";
    private static final String NAS_IP = "nasIp";
    private static final String NAS_MAC = "nasMac";
    private static final String RADIUS_SECRET = "radiusSecret";

    private static final String RADIUS_VLAN_ID = "vlanId";
    private static final String RADIUS_VLAN_PRIORITY_BIT = "radiusPBit";
    private static final String RADIUS_CONNECTION_TYPE = "radiusConnectionType";
    private static final String RADIUS_SERVER_CONNECTPOINTS = "radiusServerConnectPoints";

    // === Configuration default values

    // RADIUS server IP address
    protected static final String DEFAULT_RADIUS_IP = "10.128.10.4";

    /**
     * Default RADIUS MAC address.
     */
    public static final String DEFAULT_RADIUS_MAC = "00:00:00:00:01:10";

    /**
     * Default NAS IP address.
     */
    public static final String DEFAULT_NAS_IP = "10.128.9.244";

    /**
     * Default NAS MAC address.
     */
    public static final String DEFAULT_NAS_MAC = "00:00:00:00:10:01";

    // RADIUS server shared secret
    protected static final String DEFAULT_RADIUS_SECRET = "ONOSecret";

    // RADIUS Server UDP Port Number
    protected static final String DEFAULT_RADIUS_SERVER_PORT = "1812";

    // RADIUS Server Vlan ID
    protected static final String DEFAULT_RADIUS_VLAN_ID = "4093";

    // RADIUS Sever P-Bit
    protected static final String DEFAULT_RADIUS_VLAN_PRIORITY_BIT = "3";

    // Method of communication with the RADIUS server
    protected static final String DEFAULT_RADIUS_CONNECTION_TYPE = "socket";


    /**
     * Returns the value of the specified string property from this
     * configuration object, if such a property is defined; otherwise
     * returns the specified default value.
     *
     * @param name         name of the property
     * @param defaultValue default value if no such property defined
     * @return property value if one is defined, default value otherwise
     */
    private String getStringProperty(String name, String defaultValue) {
        return (object == null) ? defaultValue : get(name, defaultValue);
    }

    /**
     * Returns the NAS IP address if defined, otherwise returns the default
     * value {@value #DEFAULT_NAS_IP}.
     *
     * @return NAS IP address
     */
    public InetAddress nasIp() {
        try {
            return InetAddress.getByName(getStringProperty(NAS_IP,
                                                           DEFAULT_NAS_IP));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /**
     * Sets the NAS IP address. Use null to clear the property.
     *
     * @param ip new IP address to set; specify null to clear
     * @return self
     */
    public BasicElementConfig nasIp(String ip) {
        return (BasicElementConfig) setOrClear(NAS_IP, ip);
    }

    /**
     * Returns the RADIUS server IP address if defined, otherwise returns
     * the default value {@value #DEFAULT_RADIUS_IP}.
     *
     * @return RADIUS server IP address
     */
    public InetAddress radiusIp() {
        try {
            return InetAddress.getByName(getStringProperty(RADIUS_IP,
                                                           DEFAULT_RADIUS_IP));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /**
     * Sets the RADIUS server IP address. Use null to clear the property.
     *
     * @param ip new IP address to set; specify null to clear
     * @return self
     */
    public BasicElementConfig radiusIp(String ip) {
        return (BasicElementConfig) setOrClear(RADIUS_IP, ip);
    }

    /**
     * Returns the RADIUS server MAC address if defined, otherwise returns the
     * default value {@value #DEFAULT_RADIUS_MAC}.
     *
     * @return RADIUS server MAC address
     */
    public String radiusMac() {
        return getStringProperty(RADIUS_MAC, DEFAULT_RADIUS_MAC);
    }

    /**
     * Sets the RADIUS MAC address. Use null to clear the property.
     *
     * @param mac new MAC address to set; specify null to clear
     * @return self
     */
    public BasicElementConfig radiusMac(String mac) {
        return (BasicElementConfig) setOrClear(RADIUS_MAC, mac);
    }

    /**
     * Returns the NAS MAC address if defined; otherwise returns the
     * default value {@value #DEFAULT_NAS_MAC}.
     *
     * @return NAS MAC address
     */
    public String nasMac() {
        return getStringProperty(NAS_MAC, DEFAULT_NAS_MAC);
    }

    /**
     * Sets the NAS MAC address. Use null to clear the property.
     *
     * @param mac new MAC address to set; specify null to clear
     * @return self
     */
    public BasicElementConfig nasMac(String mac) {
        return (BasicElementConfig) setOrClear(NAS_MAC, mac);
    }

    /**
     * Returns the RADIUS secret if defined; otherwise returns the
     * default value {@value #DEFAULT_RADIUS_SECRET}.
     *
     * @return RADIUS secret
     */
    public String radiusSecret() {
        return getStringProperty(RADIUS_SECRET, DEFAULT_RADIUS_SECRET);
    }

    /**
     * Sets the RADIUS secret. Use null to clear the property.
     *
     * @param secret new RADIUS secret to set; specify null to clear
     * @return self
     */
    public BasicElementConfig radiusSecret(String secret) {
        return (BasicElementConfig) setOrClear(RADIUS_SECRET, secret);
    }

    /**
     * Returns the RADIUS server UDP port if defined; otherwise returns the
     * default value {@value #DEFAULT_RADIUS_SERVER_PORT}.
     *
     * @return RADIUS server UDP port
     */
    public short radiusServerUdpPort() {
        return Short.parseShort(getStringProperty(RADIUS_SERVER_PORT,
                                                  DEFAULT_RADIUS_SERVER_PORT));
    }

    /**
     * Sets the RADIUS server UDP port. Use -1 to clear the property.
     *
     * @param port new RADIUS server UDP port to set; specify -1 to clear
     * @return self
     */
    public BasicElementConfig radiusServerUdpPort(short port) {
        return (BasicElementConfig) setOrClear(RADIUS_SERVER_PORT, (long) port);
    }

    // The following properties have getters only...

    /**
     * Returns the RADIUS server VLAN ID if defined; otherwise returns the
     * default value {@value #DEFAULT_RADIUS_VLAN_ID}.
     *
     * @return RADIUS Server VLAN ID
     */
    public short radiusServerVlanId() {
        return Short.parseShort(getStringProperty(RADIUS_VLAN_ID,
                                                  DEFAULT_RADIUS_VLAN_ID));
    }

    /**
     * Returns the type of connection to use to communicate with the
     * RADIUS Server.
     *
     * @return "socket" or "packet_out"
     */
    public String radiusConnectionType() {
        return getStringProperty(RADIUS_CONNECTION_TYPE,
                                 DEFAULT_RADIUS_CONNECTION_TYPE);
    }

    /**
     * Returns the RADIUS server VLAN priority bit (p-bit) if defined; otherwise
     * returns the default value {@value #DEFAULT_RADIUS_VLAN_PRIORITY_BIT}.
     *
     * @return RADIUS server P-bit to use
     */
    public byte radiusServerPBit() {
        return Byte.parseByte(getStringProperty(RADIUS_VLAN_PRIORITY_BIT,
                                                DEFAULT_RADIUS_VLAN_PRIORITY_BIT));
    }

    /**
     * Returns the set of connect points that may be used to reach the
     * RADIUS server.
     * <p>
     * This method will return null if any string representation of the
     * connect ports are malformed.
     *
     * @return the set of connect points to reach RADIUS
     */
    public Set<ConnectPoint> radiusServerConnectPoints() {
        if (object == null || !object.has(RADIUS_SERVER_CONNECTPOINTS)) {
            return ImmutableSet.of();
        }

        ImmutableSet.Builder<ConnectPoint> builder = ImmutableSet.builder();
        ArrayNode cps = (ArrayNode) object.path(RADIUS_SERVER_CONNECTPOINTS);
        for (JsonNode jsonNode : cps) {
            String portName = jsonNode.asText(null);
            if (portName == null) {
                return null;
            }

            try {
                builder.add(deviceConnectPoint(portName));
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return builder.build();
    }
}