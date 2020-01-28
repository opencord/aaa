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

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import org.onlab.packet.BasePacket;
import org.onlab.packet.EAP;
import org.onlab.packet.EAPOL;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onlab.packet.VlanId;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cfg.ConfigProperty;
import org.onosproject.net.Annotations;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Element;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceServiceAdapter;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.DefaultPacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketServiceAdapter;
import org.opencord.sadis.BandwidthProfileInformation;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.UniTagInformation;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.ComponentInstance;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.onosproject.net.NetTestTools.connectPoint;

/**
 * Common methods for AAA app testing.
 */
public class AaaTestBase {

    MacAddress clientMac = MacAddress.valueOf("1a:1a:1a:1a:1a:1a");
    MacAddress serverMac = MacAddress.valueOf("2a:2a:2a:2a:2a:2a");

    // Our session id will be the device ID ("of:1") with the port ("1") concatenated
    static final String SESSION_ID = "of:11";

    List<BasePacket> savedPackets = new LinkedList<>();
    PacketProcessor packetProcessor;

    /**
     * Saves the given packet onto the saved packets list.
     *
     * @param packet packet to save
     */
    void savePacket(BasePacket packet) {
        savedPackets.add(packet);
    }

    /**
     * Keeps a reference to the PacketProcessor and saves the OutboundPackets.
     */
    class MockPacketService extends PacketServiceAdapter {

        @Override
        public void addProcessor(PacketProcessor processor, int priority) {
            packetProcessor = processor;
        }

        @Override
        public void emit(OutboundPacket packet) {
            try {
                Ethernet eth = Ethernet.deserializer().deserialize(packet.data().array(),
                                                                   0, packet.data().array().length);
                savePacket(eth);
            } catch (Exception e) {
                fail(e.getMessage());
            }
        }
    }
    class MockComponentContext implements ComponentContext {

                @Override
                public Dictionary<String, Object> getProperties() {
                        Dictionary<String, Object> cfgDict = new Hashtable<String, Object>();
                        cfgDict.put("statisticsGenerationEvent", 20);
                        return cfgDict;
                }

                @Override
                public Object locateService(String name) {
                        // TODO Auto-generated method stub
                        return null;
                }

                @Override
                public Object locateService(String name, ServiceReference reference) {
                        // TODO Auto-generated method stub
                        return null;
                }

                @Override
                public Object[] locateServices(String name) {
                        // TODO Auto-generated method stub
                        return null;
                }

                @Override
                public BundleContext getBundleContext() {
                        // TODO Auto-generated method stub
                        return null;
                }

                @Override
                public Bundle getUsingBundle() {
                        // TODO Auto-generated method stub
                        return null;
                }

                @Override
                public ComponentInstance getComponentInstance() {
                        // TODO Auto-generated method stub
                        return null;
                }

                @Override
                public void enableComponent(String name) {
                        // TODO Auto-generated method stub
                }

                @Override
                public void disableComponent(String name) {
                       // TODO Auto-generated method stub
                }

                @Override
                public ServiceReference getServiceReference() {
                       // TODO Auto-generated method stub
                       return null;
                }
    }

    /**
     * Mocks the DeviceService.
     */
    final class TestDeviceService extends DeviceServiceAdapter {
        @Override
        public Port getPort(ConnectPoint cp) {
            return new MockPort();
        }
    }
    private class  MockPort implements Port {

        @Override
        public boolean isEnabled() {
            return true;
        }
        public long portSpeed() {
            return 1000;
        }
        public Element element() {
            return null;
        }
        public PortNumber number() {
            return null;
        }
        public Annotations annotations() {
            return new MockAnnotations();
        }
        public Type type() {
            return Port.Type.FIBER;
        }

        private class MockAnnotations implements Annotations {

            @Override
            public String value(String val) {
                return "PON 1/1";
            }
            public Set<String> keys() {
                return null;
            }
        }
    }

    private class MockSubscriberAndDeviceInformation extends SubscriberAndDeviceInformation {

        MockSubscriberAndDeviceInformation(String id, VlanId uniTagMatch, VlanId ctag,
                                           VlanId stag, int dsPonPrio, int upPonPrio,
                                           int techProfileId, String dsBpId, String usBpId,
                                           String nasPortId, String circuitId, MacAddress hardId,
                                           Ip4Address ipAddress) {
            // Builds UniTagInformation
            UniTagInformation.Builder tagInfoBuilder = new UniTagInformation.Builder();
            UniTagInformation uniTagInfo = tagInfoBuilder.setUniTagMatch(uniTagMatch)
                    .setPonCTag(ctag)
                    .setPonSTag(stag)
                    .setDsPonCTagPriority(dsPonPrio)
                    .setUsPonSTagPriority(upPonPrio)
                    .setTechnologyProfileId(techProfileId)
                    .setDownstreamBandwidthProfile(dsBpId)
                    .setUpstreamBandwidthProfile(usBpId)
                    .build();

            this.setHardwareIdentifier(hardId);
            this.setId(id);
            this.setIPAddress(ipAddress);
            this.setNasPortId(nasPortId);
            this.setCircuitId(circuitId);
            this.setUniTagList(Lists.newArrayList(uniTagInfo));
        }
    }

    final class MockSadisService implements SadisService {

        @Override
        public BaseInformationService<SubscriberAndDeviceInformation> getSubscriberInfoService() {
            return new MockSubService();
        }

        @Override
        public BaseInformationService<BandwidthProfileInformation> getBandwidthProfileService() {
            return null;
        }
    }

    final class MockCfgService implements ComponentConfigService {
        @Override
        public Set<String> getComponentNames() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void registerProperties(Class<?> componentClass) {
            // TODO Auto-generated method stub
        }

        @Override
        public void unregisterProperties(Class<?> componentClass, boolean clear) {
            // TODO Auto-generated method stub
        }

        @Override
        public Set<ConfigProperty> getProperties(String componentName) {
           return null;
        }

        @Override
        public void setProperty(String componentName, String name, String value) {
            // TODO Auto-generated method stub
        }

        @Override
        public void preSetProperty(String componentName, String name, String value) {
            // TODO Auto-generated method stub
        }

        @Override
        public void preSetProperty(String componentName, String name, String value, boolean override) {
            // TODO Auto-generated method stub
        }

        @Override
        public void unsetProperty(String componentName, String name) {
            // TODO Auto-generated method stub
        }

        @Override
        public ConfigProperty getProperty(String componentName, String attribute) {
           return null;
        }

}

    final class MockSubService implements BaseInformationService<SubscriberAndDeviceInformation> {
        private final VlanId uniTagMatch = VlanId.vlanId((short) 35);
        private final VlanId clientCtag = VlanId.vlanId((short) 999);
        private final VlanId clientStag = VlanId.vlanId((short) 111);
        private final int dsPrio = 0;
        private final int usPrio = 0;
        private final int techProfileId = 64;
        private final String usBpId = "HSIA-US";
        private final String dsBpId = "HSIA-DS";
        private final String clientNasPortId = "PON 1/1";
        private final String clientCircuitId = "CIR-PON 1/1";


        MockSubscriberAndDeviceInformation sub =
                new MockSubscriberAndDeviceInformation(clientNasPortId, uniTagMatch, clientCtag,
                                                       clientStag, dsPrio, usPrio,
                                                       techProfileId, dsBpId, usBpId,
                                                       clientNasPortId, clientCircuitId, null,
                                                       null);
        @Override
        public SubscriberAndDeviceInformation get(String id) {

                return  sub;

        }

        @Override
        public void invalidateAll() {}
        public void invalidateId(String id) {}
        public SubscriberAndDeviceInformation getfromCache(String id) {
            return null;
        }
    }
    /**
     * Mocks the DefaultPacketContext.
     */
    final class TestPacketContext extends DefaultPacketContext {

        TestPacketContext(long time, InboundPacket inPkt,
                                  OutboundPacket outPkt, boolean block) {
            super(time, inPkt, outPkt, block);
        }

        @Override
        public void send() {
            // We don't send anything out.
        }
    }

    /**
     * Sends an Ethernet packet to the process method of the Packet Processor.
     *
     * @param reply Ethernet packet
     */
    void sendPacket(Ethernet reply) {
        final ByteBuffer byteBuffer = ByteBuffer.wrap(reply.serialize());
        InboundPacket inPacket = new DefaultInboundPacket(connectPoint("1", 1),
                                                          reply,
                                                          byteBuffer);

        PacketContext context = new TestPacketContext(127L, inPacket, null, false);
        packetProcessor.process(context);
    }

    /**
     * Constructs an Ethernet packet containing identification payload.
     *
     * @return Ethernet packet
     */
    Ethernet constructSupplicantIdentifyPacket(StateMachine stateMachine,
                                                       byte type,
                                                       byte id,
                                                       Ethernet radiusChallenge)
            throws Exception {
        Ethernet eth = new Ethernet();
        eth.setDestinationMACAddress(clientMac.toBytes());
        eth.setSourceMACAddress(serverMac.toBytes());
        eth.setEtherType(EthType.EtherType.EAPOL.ethType().toShort());
        eth.setVlanID((short) 2);

        String username = "testuser";
        byte[] data = username.getBytes();


        if (type == EAP.ATTR_MD5) {
            String password = "testpassword";
            EAPOL eapol = (EAPOL) radiusChallenge.getPayload();
            EAP eap = (EAP) eapol.getPayload();

            byte[] identifier = new byte[password.length() + eap.getData().length];

            identifier[0] = stateMachine.challengeIdentifier();
            System.arraycopy(password.getBytes(), 0, identifier, 1, password.length());
            System.arraycopy(eap.getData(), 1, identifier, 1 + password.length(), 16);

            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(identifier);
            data = new byte[17];
            data[0] = (byte) 16;
            System.arraycopy(hash, 0, data, 1, 16);
        }
        EAP eap = new EAP(EAP.RESPONSE, (byte) 1, type,
                          data);
        eap.setIdentifier(id);

        // eapol header
        EAPOL eapol = new EAPOL();
        eapol.setEapolType(EAPOL.EAPOL_PACKET);
        eapol.setPacketLength(eap.getLength());

        // eap part
        eapol.setPayload(eap);

        eth.setPayload(eapol);
        eth.setPad(true);
        return eth;
    }

    /**
     * Constructs an Ethernet packet containing a EAPOL_START Payload.
     *
     * @return Ethernet packet
     */
    Ethernet constructSupplicantStartPacket() {
        Ethernet eth = new Ethernet();
        eth.setDestinationMACAddress(clientMac.toBytes());
        eth.setSourceMACAddress(serverMac.toBytes());
        eth.setEtherType(EthType.EtherType.EAPOL.ethType().toShort());
        eth.setVlanID((short) 2);

        EAP eap = new EAP(EAPOL.EAPOL_START, (byte) 3, EAPOL.EAPOL_START, null);

        // eapol header
        EAPOL eapol = new EAPOL();
        eapol.setEapolType(EAPOL.EAPOL_START);
        eapol.setPacketLength(eap.getLength());

        // eap part
        eapol.setPayload(eap);

        eth.setPayload(eapol);
        eth.setPad(true);
        return eth;
    }

    /**
     * Constructs an Ethernet packet containing a EAPOL_ASF Payload.
     *
     * @return Ethernet packet
     */
    Ethernet constructSupplicantAsfPacket() {
        Ethernet eth = new Ethernet();
        eth.setDestinationMACAddress(clientMac.toBytes());
        eth.setSourceMACAddress(serverMac.toBytes());
        eth.setEtherType(EthType.EtherType.EAPOL.ethType().toShort());
        eth.setVlanID((short) 2);

        EAP eap = new EAP(EAPOL.EAPOL_START, (byte) 3, EAPOL.EAPOL_START, null);

        // eapol header
        EAPOL eapol = new EAPOL();
        eapol.setEapolType(EAPOL.EAPOL_ASF);
        eapol.setPacketLength(eap.getLength());

        // eap part
        eapol.setPayload(eap);

        eth.setPayload(eapol);
        eth.setPad(true);
        return eth;
    }

    /**
     * Checks the contents of a RADIUS packet being sent to the RADIUS server.
     *
     * @param radiusPacket packet to check
     * @param code expected code
     */
    void checkRadiusPacket(AaaManager aaaManager, Ethernet radiusPacket, byte code) {

        assertThat(radiusPacket.getSourceMAC(),
                   is(MacAddress.valueOf(aaaManager.nasMacAddress)));
        assertThat(radiusPacket.getDestinationMAC(), is(serverMac));

        assertThat(radiusPacket.getPayload(), instanceOf(EAPOL.class));
        EAPOL eapol = (EAPOL) radiusPacket.getPayload();
        assertThat(eapol, notNullValue());

        assertThat(eapol.getEapolType(), is(EAPOL.EAPOL_PACKET));
        assertThat(eapol.getPayload(), instanceOf(EAP.class));
        EAP eap = (EAP) eapol.getPayload();
        assertThat(eap, notNullValue());

        assertThat(eap.getCode(), is(code));
    }

    /**
     * Constructs an Ethernet packet containing a EAPOL_LOGOFF Payload.
     *
     * @return Ethernet packet
     */
    Ethernet constructSupplicantLogoffPacket() {
        Ethernet eth = new Ethernet();
        eth.setDestinationMACAddress(clientMac.toBytes());
        eth.setSourceMACAddress(serverMac.toBytes());
        eth.setEtherType(EthType.EtherType.EAPOL.ethType().toShort());
        eth.setVlanID((short) 2);

        EAP eap = new EAP(EAPOL.EAPOL_LOGOFF, (byte) 2, EAPOL.EAPOL_LOGOFF, null);

        // eapol header
        EAPOL eapol = new EAPOL();
        eapol.setEapolType(EAPOL.EAPOL_LOGOFF);
        eapol.setPacketLength(eap.getLength());

        // eap part
        eapol.setPayload(eap);

        eth.setPayload(eapol);
        eth.setPad(true);
        return eth;
    }

    /**
     * Constructs an Ethernet packet containing a RADIUS challenge
     * packet.
     *
     * @param challengeCode code to use in challenge packet
     * @param challengeType type to use in challenge packet
     * @return Ethernet packet
     */
    RADIUS constructRadiusCodeAccessChallengePacket(byte challengeCode, byte challengeType,
            byte identifier, byte[] messageAuth) {

        String challenge = "12345678901234567";

        EAP eap = new EAP(challengeType, (byte) 4, challengeType,
                challenge.getBytes(Charsets.US_ASCII));
        //eap.setIdentifier((byte) 4);
        eap.setIdentifier(identifier);

        RADIUS radius = new RADIUS();
        radius.setCode(challengeCode);
        //radius.setIdentifier((byte) 4);
        radius.setIdentifier(identifier);
        radius.setAttribute(RADIUSAttribute.RADIUS_ATTR_STATE,
                challenge.getBytes(Charsets.US_ASCII));

        radius.setPayload(eap);
        radius.setAttribute(RADIUSAttribute.RADIUS_ATTR_EAP_MESSAGE, eap.serialize());
        radius.setAttribute(RADIUSAttribute.RADIUS_ATTR_MESSAGE_AUTH, messageAuth);
        return radius;
    }
}
