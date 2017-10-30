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

import org.junit.Test;
import org.opencord.aaa.PrintableTest;

import java.net.InetAddress;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for {@link AaaConfig}.
 */
public class AaaConfigTest extends PrintableTest {

    private AaaConfig cfg;

    @Test
    public void basic() {
        cfg = new AaaConfig();
        print(cfg);

        InetAddress radAddr = cfg.radiusIp();
        print(radAddr);
        assertEquals("wrong default radius addr",
                     AaaConfig.DEFAULT_RADIUS_IP, radAddr.getHostAddress());

        InetAddress nasAddr = cfg.nasIp();
        print(nasAddr);
        assertEquals("wrong default nas addr",
                     AaaConfig.DEFAULT_NAS_IP, nasAddr.getHostAddress());

        String radMac = cfg.radiusMac();
        print(radMac);
        assertEquals("wrong default radius mac",
                     AaaConfig.DEFAULT_RADIUS_MAC, radMac);

        String nasMac = cfg.nasMac();
        print(nasMac);
        assertEquals("wrong default nas mac",
                     AaaConfig.DEFAULT_NAS_MAC, nasMac);

        String radSecret = cfg.radiusSecret();
        print(radSecret);
        assertEquals("wrong default secret",
                     AaaConfig.DEFAULT_RADIUS_SECRET, radSecret);

        short radUdpPort = cfg.radiusServerUdpPort();
        print(radUdpPort);
        short defaultPort = Short.valueOf(AaaConfig.DEFAULT_RADIUS_SERVER_PORT);
        assertEquals("wrong default UDP port", defaultPort, radUdpPort);

        short vlanId = cfg.radiusServerVlanId();
        print(vlanId);
        short defaultVlanId = Short.valueOf(AaaConfig.DEFAULT_RADIUS_VLAN_ID);
        assertEquals("wrong default vlan id", defaultVlanId, vlanId);

        byte pBit = cfg.radiusServerPBit();
        print(pBit);
        byte defaultPBit = Byte.valueOf(AaaConfig.DEFAULT_RADIUS_VLAN_PRIORITY_BIT);
        assertEquals("wrong default priority bit", defaultPBit, pBit);

        String radConnType = cfg.radiusConnectionType();
        print(radConnType);
        assertEquals("wrong default connection type",
                     AaaConfig.DEFAULT_RADIUS_CONNECTION_TYPE, radConnType);
    }
}
