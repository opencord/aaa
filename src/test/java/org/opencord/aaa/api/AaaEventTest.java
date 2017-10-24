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
import org.onlab.packet.VlanId;
import org.onosproject.net.ConnectPoint;
import org.opencord.aaa.PrintableTest;

import static org.junit.Assert.assertEquals;
import static org.onosproject.net.ConnectPoint.deviceConnectPoint;

/**
 * Unit tests for {@link AaaEvent}.
 */
public class AaaEventTest extends PrintableTest {

    private static final long TIME = 12345L;
    private static final ConnectPoint CP = deviceConnectPoint("of:01/1");
    private static final VlanId VLAN_32 = VlanId.vlanId((short) 32);

    private AaaEvent event;

    @Test
    public void basic() {
        event = new AaaEvent(AaaEvent.Type.ACCESS_DENIED, CP, TIME);
        print(event);
        assertEquals(AaaEvent.Type.ACCESS_DENIED, event.type());
        assertEquals(TIME, event.time());
        assertEquals(CP, event.subject());
        assertEquals(null, event.vlanId());
    }

    @Test
    public void vlan32() {
        event = new AaaEvent(AaaEvent.Type.ACCESS_AUTHORIZED, CP, VLAN_32);
        print(event);
        assertEquals(AaaEvent.Type.ACCESS_AUTHORIZED, event.type());
        assertEquals(CP, event.subject());
        assertEquals(VLAN_32, event.vlanId());
    }

}
