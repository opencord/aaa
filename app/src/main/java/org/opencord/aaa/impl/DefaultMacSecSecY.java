/*
 * Copyright 2017-present. * Open Networking Foundation .
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


import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.EAPOLMkpduBasicParameterSet.SCI;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfException;
import org.onosproject.netconf.NetconfSession;
import org.opencord.aaa.impl.CpStateMachine.MacSecValidate;
import org.slf4j.Logger;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Optional;

import static org.onosproject.cli.AbstractShellCommand.get;
import static org.opencord.aaa.impl.DefaultMacSecSecY.MessageBuilder.ecExpandedTags;
import static org.opencord.aaa.impl.DefaultMacSecSecY.MessageBuilder.ylTable;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Default SecY interface, ie. IEEE 802.1AE based SecY interface.
 * Enabled using "secy-driver=default" configuration.
 */
public class DefaultMacSecSecY implements MacSecSecY {


    public static final class MessageBuilder implements MacSecSecY.MessageBuilder {

        // Yang edit-config RPC tag hierarchy table indices
        enum YlIndex {
            EC_TH_BASE,
            EC_TH_CONFIG,
            EC_TH_TARGET,
            EC_TH_RUNNING,
            EC_TH_INTERFACES,
            EC_TH_INTERFACE,
            EC_TH_SECY,
            EC_TH_GENERATION,
            EC_TH_VERIFICATION,
            EC_TH_RECEIVESC,
            EC_TH_RECEIVESA,
            EC_TH_TRANSMITSC,
            EC_TH_TRANSMITSA,
            EC_TH_CURRENTCIPHERSUITE,
            EC_TH_DAYAKEY,
            EC_TH_SYSTEM,
            EC_TH_CIPHERSUITE,
            EC_TH_CIPHERSUITCONTROL,

            // Yang namespaces
            RPCNS,
            SYSTEMNS,
            INTERFACENS,
            TYPENS,
            IEEE802DOT1AENS,

            // Netconf Edit-Config/Delete-Config operation modes
            NETCONF_EC_MODE,
            NETCONF_DC_MODE,

            // Interface types
            MACSEC_INTERFACE_TYPE
        }

        // Yang edit-config RPC tag hierarchy
        public static EnumMap<YlIndex, String> ylTable = new EnumMap<YlIndex, String>(YlIndex.class) {{
            put(YlIndex.EC_TH_BASE, "edit-config");
            put(YlIndex.EC_TH_TARGET, "target");
            put(YlIndex.EC_TH_RUNNING, "running");
            put(YlIndex.EC_TH_CONFIG, "config");
            put(YlIndex.EC_TH_INTERFACE, "interface");
            put(YlIndex.EC_TH_INTERFACES, "interfaces");
            put(YlIndex.EC_TH_SECY, "SecY");
            put(YlIndex.EC_TH_GENERATION, "Generation");
            put(YlIndex.EC_TH_VERIFICATION, "Verification");
            put(YlIndex.EC_TH_RECEIVESC, "ReceiveSC");
            put(YlIndex.EC_TH_RECEIVESA, "ReceiveSA");
            put(YlIndex.EC_TH_TRANSMITSC, "TransmitSC");
            put(YlIndex.EC_TH_TRANSMITSA, "TransmitSA");
            put(YlIndex.EC_TH_CURRENTCIPHERSUITE, "CurrentCipherSuite");
            put(YlIndex.EC_TH_DAYAKEY, "Data_key");
            put(YlIndex.EC_TH_SYSTEM, "system");
            put(YlIndex.EC_TH_CIPHERSUITE, "CipherSuite)");
            put(YlIndex.EC_TH_CIPHERSUITCONTROL, "CipherSuiteControl");

            // Yang namespaces
            put(YlIndex.RPCNS, "urn:ietf:params:xml:ns:netconf:base:1.0");
            put(YlIndex.SYSTEMNS, "urn:ietf:params:xml:ns:yang:ietf-system");
            put(YlIndex.INTERFACENS, "urn:ietf:params:xml:ns:yang:ietf-interfaces");
            put(YlIndex.TYPENS, "urn:ietf:params:xml:ns:yang:iana-if-type");
            put(YlIndex.IEEE802DOT1AENS, "urn:ietf:params:xml:ns:yang:ieee802-dot1ae");

            // Netconf Edit-Config/Delete-Config operation modes
            put(YlIndex.NETCONF_EC_MODE, "merge");
            put(YlIndex.NETCONF_DC_MODE, "none");

            // Interface types
            put(YlIndex.MACSEC_INTERFACE_TYPE, "ianaif:macSecControlledIF");
        }};

        // Edit-config tag hierarchy lookup indices.
        enum ECTags {
            EC_TAG_INTERFACE,
            EC_TAG_GENERATION,
            EC_TAG_TRANSMITSC,
            EC_TAG_TRANSMITSA,
            EC_TAG_VERIFICATION,
            EC_TAG_RECEIVESC,
            EC_TAG_RECEIVESA,
            EC_TAG_CURRENTCIPHERSUIT,
            EC_TAG_DATAKEY,
            EC_TAG_CIPHERSUITCONTROL,
            EC_TAG_CIPHERSUITE
        }

        // Edit-config tags lookup table
        public static EnumMap<ECTags, String> ecExpandedTags =
                new EnumMap<ECTags, String>(ECTags.class) {{
                    put(ECTags.EC_TAG_INTERFACE,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_BASE),
                                    ylTable.get(YlIndex.EC_TH_CONFIG),
                                    ylTable.get(YlIndex.EC_TH_INTERFACES),
                                    ylTable.get(YlIndex.EC_TH_INTERFACE)));
                    put(ECTags.EC_TAG_GENERATION,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_GENERATION)));
                    put(ECTags.EC_TAG_TRANSMITSC,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_GENERATION),
                                    ylTable.get(YlIndex.EC_TH_TRANSMITSC)));
                    put(ECTags.EC_TAG_TRANSMITSA,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_GENERATION),
                                    ylTable.get(YlIndex.EC_TH_TRANSMITSC),
                                    ylTable.get(YlIndex.EC_TH_TRANSMITSA)));
                    put(ECTags.EC_TAG_VERIFICATION,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_VERIFICATION)));
                    put(ECTags.EC_TAG_RECEIVESC,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_VERIFICATION),
                                    ylTable.get(YlIndex.EC_TH_RECEIVESC)));
                    put(ECTags.EC_TAG_RECEIVESA,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_VERIFICATION),
                                    ylTable.get(YlIndex.EC_TH_RECEIVESC),
                                    ylTable.get(YlIndex.EC_TH_RECEIVESA)));
                    put(ECTags.EC_TAG_CURRENTCIPHERSUIT,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_CURRENTCIPHERSUITE)));
                    put(ECTags.EC_TAG_DATAKEY,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_CURRENTCIPHERSUITE),
                                    ylTable.get(YlIndex.EC_TH_DAYAKEY)));
                    put(ECTags.EC_TAG_CIPHERSUITCONTROL,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_CIPHERSUITCONTROL)));
                    put(ECTags.EC_TAG_CIPHERSUITE,
                        String.join(".",
                                    ylTable.get(YlIndex.EC_TH_BASE),
                                    ylTable.get(YlIndex.EC_TH_CONFIG),
                                    ylTable.get(YlIndex.EC_TH_SYSTEM),
                                    ylTable.get(YlIndex.EC_TH_CIPHERSUITE)));
                }};

        /**
         * Utility for building up basic RPC message.
         *
         * @return
         */
        @Override
        public MacSecSecY.MessageBuilder buildMessage(Optional<XMLConfiguration> cfgOpt,
                                                      Optional<Port> port,
                                                      Optional<String> operation) {

            if (!cfgOpt.isPresent() || !port.isPresent() || !operation.isPresent()) {
                return this;
            }

            XMLConfiguration cfg = cfgOpt.get();
            HierarchicalConfiguration.Node hcNode = new HierarchicalConfiguration.Node("rpc");
            hcNode.addAttribute(new HierarchicalConfiguration.Node("xmlns",
                                                                   ylTable.get(YlIndex.RPCNS)));
            cfg.setRootElementName("rpc");

            HierarchicalConfiguration.Node baseNode = new HierarchicalConfiguration
                    .Node(ylTable.get(YlIndex.EC_TH_BASE));
            HierarchicalConfiguration.Node targetNode = new HierarchicalConfiguration
                    .Node(ylTable.get(YlIndex.EC_TH_TARGET));
            targetNode.addChild(new HierarchicalConfiguration
                    .Node(ylTable.get(YlIndex.EC_TH_RUNNING)));
            // Yang level : config
            HierarchicalConfiguration.Node configNode = new HierarchicalConfiguration
                    .Node(ylTable.get(YlIndex.EC_TH_CONFIG));
            configNode.addAttribute(new HierarchicalConfiguration
                    .Node("xmlns:xc",
            ylTable.get(YlIndex.RPCNS)));

            // Yang level : config.interfaces.interface
            HierarchicalConfiguration.Node interfacesNode = new HierarchicalConfiguration
                    .Node(ylTable.get(YlIndex.EC_TH_INTERFACES));
            interfacesNode.addAttribute(new HierarchicalConfiguration
                    .Node("xmlns",
            ylTable.get(YlIndex.INTERFACENS)));
            HierarchicalConfiguration.Node interfaceNode = new HierarchicalConfiguration
                    .Node(ylTable.get(YlIndex.EC_TH_INTERFACE));
            interfaceNode.addChild(new HierarchicalConfiguration.Node("name", "eth0"));

            // Yang level : config.interfaces.interface.type
            HierarchicalConfiguration.Node type = new HierarchicalConfiguration
                    .Node("type");
            type.addAttribute(new HierarchicalConfiguration.Node("xmlns:ianaif",
                                                                 ylTable.get(YlIndex.TYPENS)));
            cfg.setProperty("type", ylTable.get(YlIndex.MACSEC_INTERFACE_TYPE));
            interfaceNode.addChild(type);

            // Yang level : config.interfaces.interface.
            HierarchicalConfiguration.Node secYNode = new HierarchicalConfiguration
                    .Node(ylTable.get(YlIndex.EC_TH_SECY));
            secYNode.addAttribute(new HierarchicalConfiguration.Node("xmlns",
                                                                     ylTable.get(YlIndex.IEEE802DOT1AENS)));
            interfaceNode.addChild(secYNode);
            interfacesNode.addChild(interfaceNode);
            baseNode.addChild(targetNode);
            configNode.addChild(interfacesNode);
            baseNode.addChild(configNode);
            hcNode.addChild(baseNode);
            cfg.setRoot(hcNode);
            return this;
        }


        @Override
        public MacSecSecY.MessageBuilder withProperty(Optional<XMLConfiguration> cfgOpt,
                                                      Optional<String> property,
                                                      Optional<String> value) {
            if (!cfgOpt.isPresent() || !property.isPresent() || !value.isPresent()) {
                return this;
            }

            XMLConfiguration cfg = cfgOpt.get();
            cfg.setProperty(property.get().toString(), value.get());
            return this;
        }

        @Override
        public MacSecSecY.MessageBuilder withChild(Optional<XMLConfiguration> cfgOpt,
                                                   Optional<String> location,
                                                   Optional<HierarchicalConfiguration.Node> child) {
            if (!cfgOpt.isPresent() || !child.isPresent()) {
                return this;
            }

            XMLConfiguration cfg = cfgOpt.get();
            HierarchicalConfiguration hcfg = new HierarchicalConfiguration();
            hcfg.setProperty(location.get(), child.get());
            cfg.configurationsAt(location.get()).add(hcfg);
            return this;
        }
    }

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    NetconfController netconfController;

    DeviceId deviceId;
    NetconfSession netconfSession;

    private final Logger log = getLogger(getClass());

    DefaultMacSecSecY(DeviceId deviceId) {
        this.deviceId = deviceId;
        netconfController = get(NetconfController.class);

        /* Initialize NETCONF session for device. */
        netconfSession = netconfController.getDevicesMap().get(deviceId).getSession();
    }

    /**
     * Utility for sending NETCONF Edit-Conf RPC message.
     *
     * @param cfg - XML RPC message
     * @return - Boolean RPC transmission status
     */
    private boolean sendEditConfMessage(XMLConfiguration cfg) {
        boolean edited = false;
        try {
            StringWriter writer = new StringWriter();
            cfg.save(writer);
            edited = netconfSession.editConfig(writer.toString());
        } catch (NetconfException | ConfigurationException e) {
            log.error("RPC failed. Exception details {} ", e);
        }
        return edited;
    }

    /**
     * Utility for sending NETCONF Get-Conf RPC message.
     *
     * @param cfg - XML RPC message
     * @return - Result of Get-Conf operation.
     */
    private String sendGetConfMessage(XMLConfiguration cfg) {
        String rpcResult = new String("");
        try {
            StringWriter writer = new StringWriter();
            cfg.save(writer);
            log.trace("Sending get-config RPC message. {}", cfg);
            rpcResult = netconfSession.get(writer.toString());
        } catch (NetconfException | ConfigurationException e) {
            log.error("RPC failed. Exception details : ", e);
        }
        return rpcResult;
    }

    public static MessageBuilder messageBuilder() {
        return new MessageBuilder();
    }

    /**
     * SecY frame verification configuration.
     *
     * @param port     - Port for verification is configuring.
     * @param validate -
     * @return - Boolean status of validate configuration.
     */
    @Override
    public boolean validateFrames(Port port, MacSecValidate validate) {
        log.trace("Request for Validate Frames : {} {}", port, validate);
        return true;
    }

    /**
     * SecY frame generation configuration.
     *
     * @param port   - Port for validation is configuring.
     * @param status - Enable/disable frame protection
     */
    @Override
    public boolean protectFrames(Port port, boolean status) {
        log.trace("Request for enabling/disabling Protect Frames : {} {}", port, status);
        return true;
    }

    /**
     * Create TransmitSC for given port and SCI.
     *
     * @param port -
     * @param sci  -
     * @return
     */
    @Override
    public boolean createTransmitSC(Port port, SCI sci) {
        log.trace("Transmit SC creation request : {}, {}", port, sci);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))

                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_TRANSMITSC), "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())));
        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean deleteTransmitSC(Port port, SCI sci) {
        log.trace("Transmit SC delete request : [{}, {}]", port, sci);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        HierarchicalConfiguration.Node txSc = new HierarchicalConfiguration
                .Node(ylTable.get(MessageBuilder.YlIndex.EC_TH_TRANSMITSC));
        txSc.addAttribute(new HierarchicalConfiguration
                .Node("xc:operation", "delete"));

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_DC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg,
                              Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_GENERATION)),
                              Optional.of(""))
                .withChild(xmlCfg,
                           Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_GENERATION)),
                           Optional.of(txSc))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_TRANSMITSC), "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())));
        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean createTransmitSA(Port port, SCI sci, int an, long pn) {
        log.trace("Transmit SA creation request : [{}, {}, {}, {}]", port, sci, an, pn);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_TRANSMITSC),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_TRANSMITSA),
                                                      "index")),
                              Optional.of(String.valueOf(an)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_TRANSMITSA),
                                                      "inUse")),
                              Optional.of(Boolean.toString(false)));

        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean deleteTransmitSA(Port port, SCI sci, int an) {
        log.trace("Transmit SA deletion request : [{},{},{},{}]", port, sci, an);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        HierarchicalConfiguration.Node txSa = new HierarchicalConfiguration
                .Node(ylTable.get(MessageBuilder.YlIndex.EC_TH_TRANSMITSA));
        txSa.addAttribute(new HierarchicalConfiguration
                .Node("xc:operation", "delete"));

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_DC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                               MessageBuilder.ecExpandedTags.get(ylTable.get(MessageBuilder.YlIndex.EC_TH_TRANSMITSC)),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withChild(xmlCfg,
                           Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_TRANSMITSC)), Optional.of(txSa))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                              MessageBuilder.ecExpandedTags.get(ylTable.get(MessageBuilder.YlIndex.EC_TH_TRANSMITSA)),
                                                      "index")),
                              Optional.of(String.valueOf(an)));
        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean enableTransmitSA(Port port, SCI sci, int an) {
        log.trace("Transmit SA enable request : [{},{},{},{}]", port, sci, an);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                               MessageBuilder.ecExpandedTags.get(MessageBuilder.ECTags.EC_TAG_TRANSMITSC),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                              MessageBuilder.ecExpandedTags.get(MessageBuilder.ECTags.EC_TAG_TRANSMITSA),
                                                      "index")),
                              Optional.of(String.valueOf(an)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_TRANSMITSA),
                                                      "inUse")),
                              Optional.of(Boolean.toString(true)));
        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean createReceiveSC(Port port, SCI sci) {
        log.trace("Receive SC creation request : [{}, {}]", port, sci);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESC),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESC),
                                                      "receiving")),
                              Optional.of(Boolean.toString(true)));

        return sendEditConfMessage(xmlCfg.get());

    }

    @Override
    public boolean deleteReceiveSC(Port port, SCI sci) {
        log.trace("Receive SC deletion request : [{}, {}]", port, sci);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        HierarchicalConfiguration.Node rxSc = new HierarchicalConfiguration
                .Node(ylTable.get(MessageBuilder.YlIndex.EC_TH_RECEIVESC));
        rxSc.addAttribute(new HierarchicalConfiguration
                .Node("xc:operation", "delete"));

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_DC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg, Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_VERIFICATION)),
                              Optional.of(""))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESC),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withChild(xmlCfg, Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_RECEIVESC)), Optional.of(rxSc));

        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean createReceiveSA(Port port, SCI sci, int an, long pn, long lowestPn) {
        log.trace("Receive SA creation request : [{}, {}, {}, {}, {}]", port, sci, an, pn, lowestPn);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESC),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESA),
                                                      "index")),
                              Optional.of(String.valueOf(an)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESA),
                                                      "inUse")),
                              Optional.of(Boolean.toString(false)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESA),
                                                      "lowestPN")),
                              Optional.of(String.valueOf(lowestPn)));
        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean deleteReceiveSA(Port port, SCI sci, int an) {
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        HierarchicalConfiguration.Node txSc = new HierarchicalConfiguration
                .Node(ylTable.get(MessageBuilder.YlIndex.EC_TH_RECEIVESA));
        txSc.addAttribute(new HierarchicalConfiguration.Node("xc:operation", "delete"));

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_DC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg, Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_VERIFICATION)),
                              Optional.of(""))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESC),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withChild(xmlCfg, Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_RECEIVESC)), Optional.of(txSc))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESA),
                                                      "index")),
                              Optional.of(String.valueOf(an)));

        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean enableReceiveSA(Port port, SCI sci, int an) {
        log.trace("Receive SA enable request : [{},{},{}]", port, sci, an);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                      .get(MessageBuilder.ECTags.EC_TAG_INTERFACE), "name")),
                              Optional.of("eth0"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESC),
                                                      "SCI")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(sci.array())))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESA),
                                                      "index")),
                              Optional.of(String.valueOf(an)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_RECEIVESA),
                                                      "inUse")),
                              Optional.of(Boolean.toString(true)));

        return sendEditConfMessage(xmlCfg.get());

    }

    /* SAK Keys. */
    @Override
    public boolean installKey(Port port, int index, byte[] key, byte[] keyIdentifier,
                              boolean transmits, boolean receives) {
        log.trace("Request for installing key");
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags.get(MessageBuilder.ECTags
                                                                                                .EC_TAG_DATAKEY),
                                                      "key-index")),
                              Optional.of(String.valueOf(index)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "sak")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(key)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "keyIdentifier")),
                              Optional.of(MkaKeyUtils.byteArrayToHexString(keyIdentifier)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "transmits")),
                              Optional.of(Boolean.toString(transmits)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "receives")),
                              Optional.of(Boolean.toString(receives)));


        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean removeKey(Port port, int index) {
        log.trace("Key removal request : [{}, {}]", port, index);
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        HierarchicalConfiguration.Node key = new HierarchicalConfiguration
                .Node(ecExpandedTags.get(MessageBuilder.ECTags.EC_TAG_DATAKEY));
        key.addAttribute(new HierarchicalConfiguration.Node("xc:operation",
                                                            MessageBuilder.ylTable
                                                                    .get(MessageBuilder.YlIndex.NETCONF_DC_MODE)));

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(MessageBuilder.ylTable.get(MessageBuilder.YlIndex.NETCONF_DC_MODE)))
                .withProperty(xmlCfg, Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_CURRENTCIPHERSUITE)),
                              Optional.of(""))
                .withChild(xmlCfg, Optional.of(ylTable.get(MessageBuilder.YlIndex.EC_TH_DAYAKEY)),
                           Optional.of(key))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".", MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "key-index")),
                              Optional.of(String.valueOf(index)));

        return sendEditConfMessage(xmlCfg.get());
    }

    /* CipherSuit configuration. */
    @Override
    public boolean addCipherSuite(int cipherSuitID, boolean enable,
                                  boolean confidentiality, Port port) {

        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_CIPHERSUITCONTROL),
                                                      "implementedCipherSuites")),
                              Optional.of("1"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "enableUse")),
                              Optional.of(Boolean.toString(enable)))

                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "requireConfidentiality")),
                              Optional.of(Boolean.toString(confidentiality)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_DATAKEY),
                                                      "ciphersuite")),
                              Optional.of(String.valueOf(cipherSuitID)));

        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean setCurrentCipherSuit(Port port, long cipherSuitID) {
        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_CURRENTCIPHERSUIT),
                                                      "ciphersuite")),
                              Optional.of(String.valueOf(cipherSuitID)));

        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public List<MacSecCipherSuit> getCipherSuites() {
        String cipherSuites = sendGetConfMessage(getConfigRpcRequest("system/CipherSuite"));
        Document doc = convertStringToDocument(cipherSuites);
        return collectsCiphersuites(doc);
    }

    /* Port enable/disable*/
    @Override
    public boolean enablePort(Port port, boolean status) {

        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_INTERFACE),
                                                      "enabled")),
                              Optional.of(String.valueOf(status)));

        return sendEditConfMessage(xmlCfg.get());
    }

    @Override
    public boolean replayProtect(Port port, boolean status, int window) {
        return true;
    }

    @Override
    public boolean createCipherSuite(String interfaceName, int ciphersuiteID, String protection, int protectionOffset,
                                     int icvLength, Port port) {

        Optional<XMLConfiguration> xmlCfg = Optional.of(new XMLConfiguration());

        messageBuilder().buildMessage(xmlCfg, Optional.of(port),
                                      Optional.of(ylTable.get(MessageBuilder.YlIndex.NETCONF_EC_MODE)))

                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_CIPHERSUITE),
                                                      "ciphersuite")),
                              Optional.of("0080020001000001"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_CIPHERSUITE),
                                                      "protection")),
                              Optional.of("Integrity"))

                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_CIPHERSUITE),
                                                      "protectionOffset")),
                              Optional.of("30"))
                .withProperty(xmlCfg,
                              Optional.of(String.join(".",
                                                      MessageBuilder.ecExpandedTags
                                                              .get(MessageBuilder.ECTags.EC_TAG_CIPHERSUITE),
                                                      "ICVLength")),
                              Optional.of("16"));

        return sendEditConfMessage(xmlCfg.get());
    }

    private XMLConfiguration getConfigRpcRequest(String filter) {
        XMLConfiguration cfg = new XMLConfiguration();
        HierarchicalConfiguration.Node node = new HierarchicalConfiguration.Node("rpc");
        node.addAttribute(new HierarchicalConfiguration.Node("xmlns", ylTable.get(MessageBuilder.YlIndex.RPCNS)));
        cfg.setRootElementName("rpc");

        HierarchicalConfiguration.Node getNode = new HierarchicalConfiguration.Node("get-config");
        HierarchicalConfiguration.Node filterNode = new HierarchicalConfiguration.Node("filter");
        filterNode.addAttribute(new HierarchicalConfiguration.Node("select", filter));
        filterNode.addAttribute(new HierarchicalConfiguration.Node("type", "xpath"));
        getNode.addChild(filterNode);
        node.addChild(getNode);
        cfg.setRoot(node);
        return cfg;
    }


    private Document convertStringToDocument(String xmlStr) {
        Document doc = null;
        try {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            InputSource is = new InputSource();
            is.setCharacterStream(new StringReader(xmlStr));
            doc = db.parse(is);
        } catch (SAXException | IOException | ParserConfigurationException e) {
            log.error("Exception in converting XML string to Document : " + e);
        }
        return doc;
    }

    private String getCharacterDataFromElement(Element element) {
        Node child = element.getFirstChild();
        if (child instanceof CharacterData) {
            return ((CharacterData) child).getData();
        }
        return "";
    }

    private List<MacSecCipherSuit> collectsCiphersuites(Document doc) {
        List<MacSecCipherSuit> macSecCipherSuites = new ArrayList<MacSecCipherSuit>();
        String name = "GCM-AES-128";
        NodeList nodes = doc.getElementsByTagName("CipherSuite");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element element = (Element) nodes.item(i);
            NodeList node = element.getElementsByTagName("ciphersuite");
            Element id = (Element) node.item(0);

            node = element.getElementsByTagName("protection");
            Element protection = (Element) node.item(0);

            node = element.getElementsByTagName("protectionOffset");
            Element offset = (Element) node.item(0);

            node = element.getElementsByTagName("ICVLength");
            Element icvLength = (Element) node.item(0);
            String macSecCipherSuiteid = getCharacterDataFromElement(id);
            MacSecCipherSuit macSecCipherSuit = new MacSecCipherSuit(
                    Long.valueOf(macSecCipherSuiteid), name,
                    MacSecCipherSuit.MacSecCapabilities
                            .valueOf(getCharacterDataFromElement(protection).toUpperCase()),
                    getProtectionOffsetValue(offset),
                    Integer.parseInt(getCharacterDataFromElement(icvLength))
            );
            macSecCipherSuites.add(macSecCipherSuit);
        }
        return macSecCipherSuites;
    }

    private MacSecCipherSuit.MacSecConfidentialityOffset getProtectionOffsetValue(Element protectionOffsetValue) {
        MacSecCipherSuit.MacSecConfidentialityOffset offset = MacSecCipherSuit.
                MacSecConfidentialityOffset.CONFIDENTIALITY_NONE;

        if (getCharacterDataFromElement(protectionOffsetValue).equals("0")) {
            offset = MacSecCipherSuit.MacSecConfidentialityOffset.CONFIDENTIALITY_OFFSET_0;

        } else if (getCharacterDataFromElement(protectionOffsetValue).equals("30")) {
            offset = MacSecCipherSuit.MacSecConfidentialityOffset.CONFIDENTIALITY_OFFSET_30;

        } else if (getCharacterDataFromElement(protectionOffsetValue).equals("50")) {
            offset = MacSecCipherSuit.MacSecConfidentialityOffset.CONFIDENTIALITY_OFFSET_50;
        }
        return offset;
    }
}

