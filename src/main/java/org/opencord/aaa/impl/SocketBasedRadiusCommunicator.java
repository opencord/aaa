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

import com.google.common.util.concurrent.ThreadFactoryBuilder;
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
import org.opencord.aaa.api.AaaConfig;
import org.opencord.aaa.api.PacketCustomizer;
import org.opencord.sadis.SubscriberAndDeviceInformationService;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.onosproject.net.packet.PacketPriority.CONTROL;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Handles Socket based communication with the RADIUS server.
 */
public class SocketBasedRadiusCommunicator implements RadiusCommunicator {

    private static final TrafficSelector EAPOL_SELECTOR =
            DefaultTrafficSelector.builder()
                    .matchEthType(EthType.EtherType.EAPOL.ethType().toShort())
                    .build();

    // for verbose output
    private final Logger log = getLogger(getClass());

    // our unique identifier
    private ApplicationId appId;

    // to receive Packet-in events that we'll respond to
    private PacketService packetService;

    // Socket used for UDP communications with RADIUS server
    private DatagramSocket radiusSocket;

    // Parsed RADIUS server addresses
    private InetAddress radiusIpAddress;

    // RADIUS server TCP port number
    private short radiusServerPort;

    // Executor for RADIUS communication thread
    private ExecutorService executor;

    private RadiusListener radiusListener = new RadiusListener();

    private AaaManager aaaManager;

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

        try {
            radiusSocket = new DatagramSocket(null);
            radiusSocket.setReuseAddress(true);
            radiusSocket.bind(new InetSocketAddress(radiusServerPort));
        } catch (Exception ex) {
            log.error("Can't open RADIUS socket", ex);
        }

        executor = Executors.newSingleThreadExecutor(
                new ThreadFactoryBuilder().setNameFormat("AAA-radius-%d").build());
        executor.execute(radiusListener);
    }

    @Override
    public void clearLocalState() {
        radiusSocket.close();
        executor.shutdownNow();
    }

    @Override
    public void deactivate() {
    }

    @Override
    public void requestIntercepts() {
        packetService.requestPackets(EAPOL_SELECTOR, CONTROL, appId);
    }

    @Override
    public void withdrawIntercepts() {
        packetService.cancelPackets(EAPOL_SELECTOR, CONTROL, appId);
    }

    @Override
    public void sendRadiusPacket(RADIUS radiusPacket, InboundPacket inPkt) {
        try {
            final byte[] data = radiusPacket.serialize();
            final DatagramSocket socket = radiusSocket;

            DatagramPacket packet =
                    new DatagramPacket(data, data.length,
                                       radiusIpAddress, radiusServerPort);

            socket.send(packet);
            log.info("Packet sent to Radius Server using socket packet = {}", packet);
        } catch (IOException e) {
            log.info("Cannot send packet to RADIUS server", e);
        }
    }

    @Override
    public void handlePacketFromServer(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();

        log.trace("Skipping Ethernet packet type {}",
                  EthType.EtherType.lookup(ethPkt.getEtherType()));
    }

    @Override
    public void setPacketCustomizer(PacketCustomizer customizer) {
        log.warn("attempting to set packet customizer on socket-based " +
                         "radius listener: {}", customizer.getClass().getName()
        );
    }

    @Override
    public void sadisServiceChanged(SubscriberAndDeviceInformationService sadis) {
        // we don't particularly care
        log.debug("SADIS change: {}", sadis);
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
                    log.info("Packet #{} received", packetNumber++);
                    try {
                        inboundRadiusPacket = RADIUS.deserializer().deserialize(
                                inboundBasePacket.getData(), 0,
                                inboundBasePacket.getLength());
                        aaaManager.handleRadiusPacket(inboundRadiusPacket);
                    } catch (DeserializationException dex) {
                        log.error("Cannot deserialize packet", dex);
                    }

                } catch (IOException e) {
                    log.info("Socket was closed, exiting listener thread");
                    done = true;
                }
            }
        }
    }

}
