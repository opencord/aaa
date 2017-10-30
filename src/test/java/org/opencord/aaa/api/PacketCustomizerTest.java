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
import org.onlab.packet.Ethernet;
import org.onlab.packet.RADIUS;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

/**
 * Unit tests for {@link PacketCustomizer}.
 */
public class PacketCustomizerTest {

    private static final RADIUS RADIUS_PACKET = new RADIUS();
    private static final Ethernet ETHERNET_PACKET = new Ethernet();

    private PacketCustomizer customizer;

    @Test
    public void noChangeToRadius() {
        customizer = new PacketCustomizer();
        RADIUS transformed = customizer.customizePacket(RADIUS_PACKET, null);
        assertSame(RADIUS_PACKET, transformed);
        assertEquals(RADIUS_PACKET, transformed);
    }

    @Test
    public void noChangeToEthernet() {
        customizer = new PacketCustomizer();
        Ethernet transformed =
                customizer.customizeEthernetIPHeaders(ETHERNET_PACKET, null);
        assertSame(ETHERNET_PACKET, transformed);
        assertEquals(ETHERNET_PACKET, transformed);
    }
}
