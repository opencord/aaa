/*
 * Copyright 2018-present. * Open Networking Foundation.
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

import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.onosproject.net.Port;

import org.onlab.packet.EAPOLMkpduBasicParameterSet.SCI;

import java.util.List;
import java.util.Optional;

/**
 *  * SecY interface for interacting switches.
 *  
 */
public interface MacSecSecY {

    interface MessageBuilder {
        MessageBuilder buildMessage(Optional<XMLConfiguration> cfgOpt,
                                    Optional<Port> port,
                                    Optional<String> operation);

        MessageBuilder withProperty(Optional<XMLConfiguration> xmlCfg,
                                    Optional<String> property,
                                    Optional<String> value);

        MessageBuilder withChild(Optional<XMLConfiguration> cfgOpt,
                                 Optional<String> location,
                                 Optional<HierarchicalConfiguration.Node> child);
    }

    boolean validateFrames(Port port, CpStateMachine.MacSecValidate validate);

    boolean protectFrames(Port port, boolean status);

    boolean createTransmitSC(Port port, SCI sci);

    boolean deleteTransmitSC(Port port, SCI sci);

    boolean createTransmitSA(Port port, SCI sci, int an, long pn);

    boolean deleteTransmitSA(Port port, SCI sci, int an);

    boolean enableTransmitSA(Port port, SCI sci, int an);

    boolean createReceiveSC(Port port, SCI sci);

    boolean deleteReceiveSC(Port port, SCI sci);

    boolean createReceiveSA(Port port, SCI sci,
                            int an, long pn, long lowestPn);

    boolean deleteReceiveSA(Port port, SCI sci, int an);

    boolean enableReceiveSA(Port port, SCI sci, int an);

    boolean installKey(Port port, int index, byte[] key, byte[] keyIdentifier,
                       boolean transmits, boolean receives);

    boolean removeKey(Port port, int index);

    /* CipherSuit configuration. */
    boolean addCipherSuite(int cipherSuitID, boolean enable,
                           boolean confidentiality, Port port);

    boolean setCurrentCipherSuit(Port port, long cipherSuitID);

    List<MacSecCipherSuit> getCipherSuites();

    boolean enablePort(Port port, boolean status);

    boolean replayProtect(Port port, boolean status, int window);

    boolean createCipherSuite(String interfaceName, int ciphersuiteID, String protection, int protectionOffset,
                                      int icvLength, Port port);
}
