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
package org.opencord.aaa.impl;

import static org.onosproject.net.packet.PacketPriority.CONTROL;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.onlab.packet.DeserializationException;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.RADIUS;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketService;
import org.opencord.aaa.AaaConfig;
import org.opencord.aaa.RadiusCommunicator;
import org.slf4j.Logger;

import com.google.common.util.concurrent.ThreadFactoryBuilder;

/**
 * Handles Socket based communication with the RADIUS server.
 */
public class SocketBasedRadiusCommunicator implements RadiusCommunicator {

    // for verbose output
    private final Logger log = getLogger(getClass());

    // our unique identifier
    private ApplicationId appId;

    // to receive Packet-in events that we'll respond to
    PacketService packetService;

    // Socket used for UDP communications with RADIUS server
    private DatagramSocket radiusSocket;

    private String radiusHost;

    // Parsed RADIUS server addresses
    protected InetAddress radiusIpAddress;

    // RADIUS server TCP port number
    protected short radiusServerPort;

    // Executor for RADIUS communication thread
    private ExecutorService executor;

    AaaManager aaaManager;

    SocketBasedRadiusCommunicator(ApplicationId appId, PacketService pktService,
                                  AaaManager aaaManager) {
        this.appId = appId;
        this.packetService = pktService;
        this.aaaManager = aaaManager;
    }

    @Override
    public void initializeLocalState(AaaConfig newCfg) {
        if (newCfg.radiusIp() != null) {
            radiusIpAddress = newCfg.radiusIp();
        }
        radiusServerPort = newCfg.radiusServerUdpPort();
        radiusHost = newCfg.radiusHostName();

        try {
            radiusSocket = new DatagramSocket(null);
            radiusSocket.setReuseAddress(true);
            radiusSocket.bind(new InetSocketAddress(radiusServerPort));
        } catch (Exception ex) {
            log.error("Can't open RADIUS socket", ex);
        }

        log.info("Remote RADIUS Server: {}:{}", radiusIpAddress, radiusServerPort);

        executor = Executors.newSingleThreadExecutor(
                new ThreadFactoryBuilder()
                        .setNameFormat("AAA-radius-%d").build());
        executor.execute(radiusListener);
    }

    @Override
    public void clearLocalState() {
        radiusSocket.close();
        executor.shutdownNow();
    }

    @Override
    public void deactivate() {
       clearLocalState();
    }

    @Override
    public void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(EthType.EtherType.EAPOL.ethType().toShort());
        packetService.requestPackets(selector.build(), CONTROL, appId);
    }

    @Override
    public void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(EthType.EtherType.EAPOL.ethType().toShort());
        packetService.cancelPackets(selector.build(), CONTROL, appId);
    }

    @Override
    public void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
        try {
            final byte[] data = radiusPacket.serialize();
            final DatagramSocket socket = radiusSocket;

            try {
                InetAddress address;
                if (radiusHost != null) {
                    address = InetAddress.getByName(radiusHost);
                } else {
                    address = radiusIpAddress;
                }
                DatagramPacket packet =
                        new DatagramPacket(data, data.length, address, radiusServerPort);
                if (log.isTraceEnabled()) {
                    log.trace("Sending packet {} to Radius Server {}:{} using socket",
                              radiusPacket, address, radiusServerPort);
                }
                if (radiusPacket.getIdentifier() == RadiusOperationalStatusManager.AAA_REQUEST_ID_STATUS_REQUEST ||
                        radiusPacket.getIdentifier() == RadiusOperationalStatusManager.
                            AAA_REQUEST_ID_FAKE_ACCESS_REQUEST) {
                    aaaManager.radiusOperationalStatusService.setOutTimeInMillis(radiusPacket.getIdentifier());
                } else {
                    aaaManager.aaaStatisticsManager.putOutgoingIdentifierToMap(radiusPacket.getIdentifier());
                }
                socket.send(packet);
                aaaManager.radiusOperationalStatusService.setStatusServerReqSent(true);
            } catch (UnknownHostException uhe) {
                log.warn("Unable to resolve host {}", radiusHost);
                aaaManager.radiusOperationalStatusService.setStatusServerReqSent(false);
            }
        } catch (IOException e) {
            log.info("Cannot send packet to RADIUS server", e);
        }
    }

    @Override
    public void handlePacketFromServer(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        if (log.isTraceEnabled() && ethPkt.getEtherType() != Ethernet.TYPE_LLDP
                && ethPkt.getEtherType() != Ethernet.TYPE_BSN) {
            log.trace("Skipping Ethernet packet type {}",
                      EthType.EtherType.lookup(ethPkt.getEtherType()));
        }
    }

    class RadiusListener implements Runnable {

        @Override
        public void run() {
            boolean done = false;
            int packetNumber = 1;

            log.info("UDP listener thread starting up");
            RADIUS inboundRadiusPacket;
            while (!done) {
                try {
                    byte[] packetBuffer = new byte[RADIUS.RADIUS_MAX_LENGTH];
                    DatagramPacket inboundBasePacket =
                            new DatagramPacket(packetBuffer, packetBuffer.length);
                    DatagramSocket socket = radiusSocket;
                    socket.receive(inboundBasePacket);
                    aaaManager.checkForPacketFromUnknownServer(inboundBasePacket.getAddress().getHostAddress());
                    log.debug("Packet #{} received", packetNumber++);
                    try {
                        inboundRadiusPacket =
                                RADIUS.deserializer()
                                        .deserialize(inboundBasePacket.getData(),
                                                0,
                                                inboundBasePacket.getLength());
                        aaaManager.aaaStatisticsManager.handleRoundtripTime(inboundRadiusPacket.getIdentifier());
                        aaaManager.handleRadiusPacket(inboundRadiusPacket);
                    } catch (DeserializationException dex) {
                        aaaManager.aaaStatisticsManager.getAaaStats().increaseMalformedResponsesRx();
                        log.error("Cannot deserialize packet", dex);
                    } catch (StateMachineException sme) {
                        log.error("Illegal state machine operation", sme);
                    }

                } catch (IOException e) {
                    log.info("Socket was closed, exiting listener thread");
                    done = true;
                }
            }
        }
    }

    RadiusListener radiusListener = new RadiusListener();
}
