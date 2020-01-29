/*
 * Copyright 2015-present Open Networking Foundation
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
package org.opencord.aaa.impl;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.packet.BasePacket;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EAP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IpAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onosproject.cluster.ClusterServiceAdapter;
import org.onosproject.cluster.LeadershipServiceAdapter;
import org.onosproject.cluster.NodeId;
import org.onosproject.core.CoreServiceAdapter;
import org.onosproject.event.DefaultEventSinkRegistry;
import org.onosproject.event.Event;
import org.onosproject.event.EventDeliveryService;
import org.onosproject.event.EventSink;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.NetworkConfigRegistryAdapter;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.store.cluster.messaging.ClusterCommunicationServiceAdapter;
import org.onosproject.store.service.TestStorageService;
import org.opencord.aaa.AaaConfig;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static com.google.common.base.Preconditions.checkState;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Set of tests of the ONOS application component.
 */
public class AaaManagerTest extends AaaTestBase {

    static final String BAD_IP_ADDRESS = "198.51.100.0";

    private AaaManager aaaManager;
    private AaaStatisticsManager aaaStatisticsManager;

    class AaaManagerWithoutRadiusServer extends AaaManager {
        protected void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
            savePacket(radiusPacket);
        }
    }
    /**
     * Mocks the AAAConfig class to force usage of an unroutable address for the
     * RADIUS server.
     */
    static class MockAaaConfig extends AaaConfig {
        @Override
        public InetAddress radiusIp() {
            try {
                return InetAddress.getByName(BAD_IP_ADDRESS);
            } catch (UnknownHostException ex) {
                // can't happen
                throw new IllegalStateException(ex);
            }
        }
    }

    static final class TestLeadershipService extends LeadershipServiceAdapter {
        @Override
        public NodeId getLeader(String path) {
            return new ClusterServiceAdapter().getLocalNode().id();
        }
    }

    /**
     * Mocks the network config registry.
     */
    @SuppressWarnings("unchecked")
    private static final class TestNetworkConfigRegistry
            extends NetworkConfigRegistryAdapter {
        @Override
        public <S, C extends Config<S>> C getConfig(S subject, Class<C> configClass) {
            AaaConfig aaaConfig = new MockAaaConfig();
            return (C) aaaConfig;
        }
    }

    public static class TestEventDispatcher extends DefaultEventSinkRegistry
            implements EventDeliveryService {
        @Override
        @SuppressWarnings("unchecked")
        public synchronized void post(Event event) {
            EventSink sink = getSink(event.getClass());
            checkState(sink != null, "No sink for event %s", event);
            sink.process(event);
        }

        @Override
        public void setDispatchTimeLimit(long millis) {
        }

        @Override
        public long getDispatchTimeLimit() {
            return 0;
        }
    }

    /**
     * Sets up the services required by the AAA application.
     */
    @Before
    public void setUp() {
        aaaManager = new AaaManagerWithoutRadiusServer();
        aaaManager.netCfgService = new TestNetworkConfigRegistry();
        aaaManager.coreService = new CoreServiceAdapter();
        aaaManager.packetService = new MockPacketService();
        aaaManager.deviceService = new TestDeviceService();
        aaaManager.sadisService = new MockSadisService();
        aaaManager.cfgService = new MockCfgService();
        aaaManager.storageService = new TestStorageService();
        aaaStatisticsManager = new AaaStatisticsManager();
        aaaStatisticsManager.storageService = new TestStorageService();
        aaaStatisticsManager.clusterService = new ClusterServiceAdapter();
        aaaStatisticsManager.leadershipService = new TestLeadershipService();
        aaaStatisticsManager.clusterCommunicationService = new ClusterCommunicationServiceAdapter();
        aaaManager.radiusOperationalStatusService = new RadiusOperationalStatusManager();
        TestUtils.setField(aaaStatisticsManager, "eventDispatcher", new TestEventDispatcher());
        aaaStatisticsManager.activate(new MockComponentContext());
        aaaManager.aaaStatisticsManager = this.aaaStatisticsManager;
        TestUtils.setField(aaaManager, "eventDispatcher", new TestEventDispatcher());
        aaaManager.activate(new AaaTestBase.MockComponentContext());
    }

    /**
     * Tears down the AAA application.
     */
    @After
    public void tearDown() {
        aaaManager.deactivate(new AaaTestBase.MockComponentContext());
    }

    /**
     * Extracts the RADIUS packet from a packet sent by the supplicant.
     *
     * @param radius RADIUS packet sent by the supplicant
     * @throws DeserializationException if deserialization of the packet contents
     *         fails.
     */
    private void checkRadiusPacketFromSupplicant(RADIUS radius)
            throws DeserializationException {
        assertThat(radius, notNullValue());

        EAP eap = radius.decapsulateMessage();
        assertThat(eap, notNullValue());
    }

    /**
     * Fetches the sent packet at the given index. The requested packet
     * must be the last packet on the list.
     *
     * @param index index into sent packets array
     * @return packet
     */
    private BasePacket fetchPacket(int index) {
        BasePacket packet = savedPackets.get(index);
        assertThat(packet, notNullValue());
        return packet;
    }

    /**
     * Tests the authentication path through the AAA application.
     *
     * @throws DeserializationException if packed deserialization fails.
     */
    @Test
    public void testAuthentication() throws Exception {

        //  (1) Supplicant start up

        Ethernet startPacket = constructSupplicantStartPacket();
        sendPacket(startPacket);

        Ethernet responsePacket = (Ethernet) fetchPacket(0);
        checkRadiusPacket(aaaManager, responsePacket, EAP.ATTR_IDENTITY);

        //  (2) Supplicant identify

        Ethernet identifyPacket = constructSupplicantIdentifyPacket(null,
                EAP.ATTR_IDENTITY, (byte) 3, null);
        sendPacket(identifyPacket);

        RADIUS radiusIdentifyPacket = (RADIUS) fetchPacket(1);
        byte reqId = radiusIdentifyPacket.getIdentifier();

        checkRadiusPacketFromSupplicant(radiusIdentifyPacket);

        assertThat(radiusIdentifyPacket.getCode(), is(RADIUS.RADIUS_CODE_ACCESS_REQUEST));
        assertThat(new String(radiusIdentifyPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME).getValue()),
                   is("testuser"));

        IpAddress nasIp =
                IpAddress.valueOf(IpAddress.Version.INET,
                                  radiusIdentifyPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_IP)
                                          .getValue());
        assertThat(nasIp.toString(), is(aaaManager.nasIpAddress.getHostAddress()));

        //  State machine should have been created by now

        StateMachine stateMachine = aaaManager.getStateMachine(SESSION_ID);
        assertThat(stateMachine, notNullValue());
        assertThat(stateMachine.state(), is(StateMachine.STATE_PENDING));

        // (3) RADIUS MD5 challenge

        RADIUS radiusCodeAccessChallengePacket =
                constructRadiusCodeAccessChallengePacket(RADIUS.RADIUS_CODE_ACCESS_CHALLENGE, EAP.ATTR_MD5,
                reqId, aaaManager.radiusSecret.getBytes());
        aaaManager.handleRadiusPacket(radiusCodeAccessChallengePacket);

        Ethernet radiusChallengeMD5Packet = (Ethernet) fetchPacket(2);
        checkRadiusPacket(aaaManager, radiusChallengeMD5Packet, EAP.ATTR_MD5);

        // (4) Supplicant MD5 response

        Ethernet md5RadiusPacket =
                constructSupplicantIdentifyPacket(stateMachine,
                                                  EAP.ATTR_MD5,
                                                  stateMachine.challengeIdentifier(),
                                                  radiusChallengeMD5Packet);
        sendPacket(md5RadiusPacket);

        RADIUS responseMd5RadiusPacket = (RADIUS) fetchPacket(3);

        checkRadiusPacketFromSupplicant(responseMd5RadiusPacket);
        //assertThat(responseMd5RadiusPacket.getIdentifier(), is((byte) 9));
        reqId = responseMd5RadiusPacket.getIdentifier();
        assertThat(responseMd5RadiusPacket.getCode(), is(RADIUS.RADIUS_CODE_ACCESS_REQUEST));

        //  State machine should be in pending state

        assertThat(stateMachine, notNullValue());
        assertThat(stateMachine.state(), is(StateMachine.STATE_PENDING));

        // (5) RADIUS Success

        RADIUS successPacket =
                constructRadiusCodeAccessChallengePacket(RADIUS.RADIUS_CODE_ACCESS_ACCEPT,
                EAP.SUCCESS, reqId, aaaManager.radiusSecret.getBytes());
        aaaManager.handleRadiusPacket((successPacket));
        Ethernet supplicantSuccessPacket = (Ethernet) fetchPacket(4);

        checkRadiusPacket(aaaManager, supplicantSuccessPacket, EAP.SUCCESS);

        //  State machine should be in authorized state

        assertThat(stateMachine, notNullValue());
        assertThat(stateMachine.state(), is(StateMachine.STATE_AUTHORIZED));
    }

    @Test
    public void testRemoveAuthentication() {
        Ethernet startPacket = constructSupplicantStartPacket();
        sendPacket(startPacket);

        StateMachine stateMachine = aaaManager.getStateMachine(SESSION_ID);

        assertThat(stateMachine, notNullValue());
        assertThat(stateMachine.state(), is(StateMachine.STATE_STARTED));

        aaaManager.removeAuthenticationStateByMac(stateMachine.supplicantAddress());

        assertThat(aaaManager.getStateMachine(SESSION_ID), nullValue());
    }

    /**
     * Tests the default configuration.
     */
    @Test
    public void testConfig() {
        assertThat(aaaManager.nasIpAddress.getHostAddress(), is(AaaConfig.DEFAULT_NAS_IP));
        assertThat(aaaManager.nasMacAddress, is(AaaConfig.DEFAULT_NAS_MAC));
        assertThat(aaaManager.radiusIpAddress.getHostAddress(), is(BAD_IP_ADDRESS));
        assertThat(aaaManager.radiusMacAddress, is(AaaConfig.DEFAULT_RADIUS_MAC));
    }
}
