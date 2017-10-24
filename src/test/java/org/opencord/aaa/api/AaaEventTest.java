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
import org.opencord.aaa.api.AaaEvent.Type;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotSame;
import static org.onosproject.net.ConnectPoint.deviceConnectPoint;

/**
 * Unit tests for {@link AaaEvent}.
 */
public class AaaEventTest extends PrintableTest {

    private static final long TIME1 = 12345L;
    private static final long TIME2 = 54321L;
    private static final ConnectPoint CP1 = deviceConnectPoint("of:01/1");
    private static final ConnectPoint CP2 = deviceConnectPoint("of:02/2");
    private static final VlanId VLAN_32 = VlanId.vlanId((short) 32);
    private static final VlanId VLAN_64 = VlanId.vlanId((short) 64);

    private static final AaaEvent AEV_1 =
            new AaaEvent(Type.AUTH_START, CP1, TIME1);
    private static final AaaEvent AEV_2 =
            new AaaEvent(Type.AUTH_START, CP1, TIME1, VLAN_32);
    private static final AaaEvent AEV_3 =
            new AaaEvent(Type.AUTH_LOGOFF, CP1, TIME1);
    private static final AaaEvent AEV_4 =
            new AaaEvent(Type.AUTH_LOGOFF, CP1, TIME2);
    private static final AaaEvent AEV_5 =
            new AaaEvent(Type.AUTH_LOGOFF, CP2, TIME2);
    private static final AaaEvent AEV_6 =
            new AaaEvent(Type.AUTH_LOGOFF, CP2, VLAN_64);
    private static final AaaEvent AEV_7 =
            new AaaEvent(Type.AUTH_REQUEST_ACCESS, CP1, TIME1, VLAN_64);
    private static final AaaEvent AEV_7_AGAIN =
            new AaaEvent(Type.AUTH_REQUEST_ACCESS, CP1, TIME1, VLAN_64);


    private AaaEvent event;

    @Test
    public void basic() {
        event = new AaaEvent(Type.ACCESS_DENIED, CP1, TIME1);
        print(event);
        assertEquals(Type.ACCESS_DENIED, event.type());
        assertEquals(TIME1, event.time());
        assertEquals(CP1, event.subject());
        assertEquals(null, event.vlanId());
    }

    @Test
    public void vlan32() {
        event = new AaaEvent(Type.ACCESS_AUTHORIZED, CP1, VLAN_32);
        print(event);
        assertEquals(Type.ACCESS_AUTHORIZED, event.type());
        assertEquals(CP1, event.subject());
        assertEquals(VLAN_32, event.vlanId());
    }

    @Test
    public void checkEquivalence() {
        assertNotEquals(AEV_1, AEV_2);
        assertNotEquals(AEV_1, AEV_3);
        assertNotEquals(AEV_3, AEV_4);
        assertNotEquals(AEV_4, AEV_5);
        assertNotEquals(AEV_5, AEV_6);
        assertNotEquals(AEV_6, AEV_7);
        assertNotSame(AEV_7, AEV_7_AGAIN);
        assertEquals(AEV_7, AEV_7_AGAIN);
    }
}
