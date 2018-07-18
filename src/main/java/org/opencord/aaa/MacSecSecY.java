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

package org.opencord.aaa;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.slf4j.Logger;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfException;
import org.onosproject.netconf.NetconfSession;

import org.onlab.packet.EAPOLMkpduBasicParameterSet.SCI;

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
import java.util.List;

import org.onosproject.net.DeviceId;

import static org.onosproject.cli.AbstractShellCommand.get;

import org.opencord.aaa.CpStateMachine.MacSecValidate;

import static org.slf4j.LoggerFactory.getLogger;

public class MacSecSecY {

    private final String editConfigOperation = "merge";
    private final String deleteOperation = "none";
    private final String rpcNS = "urn:ietf:params:xml:ns:netconf:base:1.0";
    private final String systemNS = "urn:ietf:params:xml:ns:yang:ietf-system";
    private final String interfaceNS = "urn:ietf:params:xml:ns:yang:ietf-interfaces";
    private final String typeNS = "urn:ietf:params:xml:ns:yang:iana-if-type";
    private final String namespace = "urn:ietf:params:xml:ns:yang:ieee802-dot1ae";
    private final String interfaceTag = "edit-config.config.interfaces.interface";
    private final String generation = "edit-config.config.interfaces.interface.SecY.Generation";
    private final String verification = "edit-config.config.interfaces.interface.SecY.Verification";
    private final String receiveSC = "edit-config.config.interfaces.interface.SecY.Verification.ReceiveSC";
    private final String transmitSC = "edit-config.config.interfaces.interface.SecY.Generation.TransmitSC";
    private final String receiveSA = "edit-config.config.interfaces.interface.SecY.Verification.ReceiveSC.ReceiveSA";
    private final String dataKey = "edit-config.config.interfaces.interface.SecY.CurrentCipherSuite.Data_key";
    private final String currentCiphersuite = "edit-config.config.interfaces.interface.SecY.CurrentCipherSuite";
    private final String ciphersuiteControl = "edit-config.config.interfaces.interface.SecY.CipherSuiteControl";
    NetconfSession session;
    NetconfController controller;
    private final Logger log = getLogger(getClass());
    DeviceId deviceId;

    MacSecSecY(DeviceId deviceId) {
        this.deviceId = deviceId;
        controller = get(NetconfController.class);
    }

    /* Verification */
    public boolean validateFrames(String portName, MacSecValidate validate) {
        log.trace("Request for Validate Frames: {} {}", portName, validate);
        return true;
    }

    /* Generation */
    public boolean protectFrames(String portName, boolean status) {
        log.trace("Request for enabling/disabling Protect Frames : {} {}", portName, status);
        return true;
    }

    /* Transmit & Receive SCs & SAs. */
    public boolean createTransmitSC(String portName, SCI sci) {
        log.trace("Transmit SC creation request : {} {}", portName, sci);
        XMLConfiguration txSc = createRpcMessage(portName, editConfigOperation);
        txSc.setProperty(transmitSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        return sendEditConfRpc(txSc);
    }

    public boolean deleteTransmitSC(String portName, SCI sci) {
        log.trace("Transmit SC delete request : [{}, {}]", portName, sci);
        XMLConfiguration cfg = createRpcMessage(portName, deleteOperation);
        HierarchicalConfiguration.Node transmitSc = new HierarchicalConfiguration.Node(
                "TransmitSC");
        transmitSc.addAttribute(new HierarchicalConfiguration.Node("xc:operation",
                "delete"));
        cfg.setProperty(generation, "");
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("interfaces").get(0).getChildren("interface")
                .get(0).getChildren("SecY").get(0).getChildren("Generation")
                .get(0).addChild(transmitSc);
        cfg.setProperty(transmitSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        return sendEditConfRpc(cfg);
    }

    public boolean createTransmitSA(String portName, SCI sci, int an, long pn) {
        log.trace("Transmit SA creation request : [{}, {}, {}, {}]", portName, sci, an, pn);
        XMLConfiguration cfg = createRpcMessage(portName, editConfigOperation);
        cfg.setProperty(transmitSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        cfg.setProperty(transmitSC.concat(".TransmitSA.index"), an);
        cfg.setProperty(transmitSC.concat(".TransmitSA.inUse"), false);
        return sendEditConfRpc(cfg);

    }

    public boolean deleteTransmitSA(String portName, SCI sci, int an) {
        log.trace("Transmit SA deletion request : [{},{},{},{}]", portName, sci, an);
        XMLConfiguration cfg = createRpcMessage(portName, deleteOperation);
        cfg.setProperty(transmitSC.concat(".SCI"), sci);
        HierarchicalConfiguration.Node transmitSA = new HierarchicalConfiguration.Node(
                "TransmitSA");
        transmitSA.addAttribute(new HierarchicalConfiguration.Node("xc:operation",
                "delete"));
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("interfaces").get(0).getChildren("interface")
                .get(0).getChildren("SecY").get(0).getChildren("Generation")
                .get(0).getChildren("TransmitSC").get(0).addChild(transmitSA);
        cfg.setProperty(transmitSC.concat(".TransmitSA.index"), an);
        return sendEditConfRpc(cfg);
    }

    public boolean enableTransmitSA(String portName, SCI sci, int an) {
        log.trace("Transmit SA enable request : [{},{},{},{}]", portName, sci, an);
        XMLConfiguration cfg = createRpcMessage(portName, editConfigOperation);
        cfg.setProperty(transmitSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        cfg.setProperty(transmitSC.concat(".TransmitSA.index"), an);
        cfg.setProperty(transmitSC.concat(".TransmitSA.inUse"), true);
        return sendEditConfRpc(cfg);
    }

    public boolean createReceiveSC(String portName, SCI sci) {
        log.trace("Receive SC creation request : [{}, {}]", portName, sci);
        XMLConfiguration config = createRpcMessage(portName, editConfigOperation);
        config.setProperty(receiveSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        config.setProperty(receiveSC.concat(".receiving"), true);
        return sendEditConfRpc(config);
    }

    public boolean deleteReceiveSC(String portName, SCI sci) {
        log.trace("Receive SC deletion request : [{}, {}]", portName, sci);
        XMLConfiguration cfg = createRpcMessage(portName, deleteOperation);
        HierarchicalConfiguration.Node receiveSc = new HierarchicalConfiguration.Node(
                "ReceiveSC");
        receiveSc.addAttribute(new HierarchicalConfiguration.Node("xc:operation",
                "delete"));
        cfg.setProperty(verification, "");
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("interfaces").get(0).getChildren("interface")
                .get(0).getChildren("SecY").get(0).getChildren("Verification")
                .get(0).addChild(receiveSc);
        cfg.setProperty(receiveSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        return sendEditConfRpc(cfg);
    }

    public boolean createReceiveSA(String portName, SCI sci, int an, long pn, long lowestPn) {
        log.trace("Receive SA creation request : [{}, {}, {}, {}, {}]", portName, sci, an, pn,
                lowestPn);
        XMLConfiguration config = createRpcMessage(portName, editConfigOperation);
        config.setProperty(receiveSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        config.setProperty(receiveSA.concat(".index"), an);
        config.setProperty(receiveSA.concat(".inUse"), false);
        config.setProperty(receiveSA.concat(".lowestPN"), lowestPn);
        //config.setProperty(receiveSA.concat(".key"), key);
        return sendEditConfRpc(config);
    }

    public boolean deleteReceiveSA(String portName, SCI sci, int an) {
        log.trace("Receive SA deletion request : [{},{},{},{}]", portName, sci, an);
        XMLConfiguration cfg = createRpcMessage(portName, deleteOperation);
        cfg.setProperty(receiveSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        HierarchicalConfiguration.Node receiveSaData = new HierarchicalConfiguration.Node(
                "ReceiveSA");
        receiveSaData.addAttribute(new HierarchicalConfiguration.Node("xc:operation",
                "delete"));
        cfg.setProperty(verification, "");
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("interfaces").get(0).getChildren("interface")
                .get(0).getChildren("SecY").get(0).getChildren("Verification")
                .get(0).getChildren("ReceiveSC").get(0).addChild(receiveSaData);
        cfg.setProperty(receiveSA.concat(".index"), an);
        return sendEditConfRpc(cfg);
    }

    public boolean enableReceiveSA(String portName, SCI sci, int an) {
        log.trace("Receive SA enable request : [{},{},{},{}]", portName, sci, an);
        XMLConfiguration config = createRpcMessage(portName, editConfigOperation);
        config.setProperty(receiveSC.concat(".SCI"), MkaKeyUtils.byteArrayToHexString(sci.array()));
        config.setProperty(receiveSA.concat(".index"), an);
        config.setProperty(receiveSA.concat(".inUse"), true);
        return sendEditConfRpc(config);
    }

    /* SAK Keys. */
    public boolean installKey(String portName, int index, byte[] key, byte[] keyIdentifier,
                              boolean transmits, boolean receives) {
        log.trace("Received Key Installation request : {} {} {} {} {} {}", portName, index, key,
                keyIdentifier, transmits, receives);
        XMLConfiguration cfg = createRpcMessage(portName, editConfigOperation);
        cfg.setProperty(dataKey.concat(".key-index"), index);
        cfg.setProperty(dataKey.concat(".sak"), MkaKeyUtils.byteArrayToHexString(key)); //0080020001000001
        cfg.setProperty(dataKey.concat(".keyIdentifier"), MkaKeyUtils.byteArrayToHexString(keyIdentifier));
        cfg.setProperty(dataKey.concat(".transmits"), transmits);
        cfg.setProperty(dataKey.concat(".receives"), receives);
        return sendEditConfRpc(cfg);
    }

    public boolean removeKey(String portName, int index) {
        log.trace("Received Key Removal request : {} {}", portName, index);
        XMLConfiguration cfg = createRpcMessage(portName, deleteOperation);
        HierarchicalConfiguration.Node data = new HierarchicalConfiguration.Node(
                "Data_key");
        data.addAttribute(new HierarchicalConfiguration.Node("xc:operation",
                "delete"));
        cfg.setProperty(currentCiphersuite, "");
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("interfaces").get(0).getChildren("interface")
                .get(0).getChildren("SecY").get(0).getChildren("CurrentCipherSuite")
                .get(0).addChild(data);
        cfg.setProperty(dataKey.concat(".key-index"), index);
        return sendEditConfRpc(cfg);
    }

    /* CipherSuit configuration. */
    public boolean addCipherSuite(int cipherSuitID, boolean enable,
                                  boolean confidentiality) {
        String interfaceName = "";
        XMLConfiguration cfg = createRpcMessage(interfaceName, editConfigOperation);
        cfg.setProperty(ciphersuiteControl.concat(".implementedCipherSuites"), 1);
        cfg.setProperty(ciphersuiteControl.concat(".enableUse"), enable);
        cfg.setProperty(ciphersuiteControl.concat(".requireConfidentiality"), confidentiality);
        cfg.setProperty(ciphersuiteControl.concat(".ciphersuite"), cipherSuitID);
        return sendEditConfRpc(cfg);
    }

    public boolean setCurrentCipherSuit(String portName, long cipherSuitID) {
        log.trace("Request for setting current Cipher Suit : {} {}", portName, cipherSuitID);
        XMLConfiguration cfg = createRpcMessage(portName, editConfigOperation);
        cfg.setProperty(currentCiphersuite.concat(".ciphersuite"), (int) cipherSuitID);
        return sendEditConfRpc(cfg);
    }

    public List<MacSecCipherSuit> getCipherSuites() {
        String cipherSuites = sendGetConfRpc(getConfigRpcRequest("system/CipherSuite"));
        Document doc = convertStringToDocument(cipherSuites);
        return collectsCiphersuites(doc);
    }

    /* Port enable/disable*/
    public boolean enablePort(String portName, boolean status) {
        log.trace("Enable port request : {} {} {}", portName, status);
        XMLConfiguration cfg = createRpcMessage(portName, editConfigOperation);
        cfg.setProperty(interfaceTag.concat(".enabled"), status);
        return sendEditConfRpc(cfg);
    }

    public boolean replayProtect(String portName, boolean status, int window) {
        log.trace("Replay protection request : {} {} {}", portName, status, window);
        return true;
    }

    public boolean createCipherSuite(String interfaceName, int ciphersuiteID, String protection, int protectionOffset,
                                     int icvLength) {
        XMLConfiguration cfg = new XMLConfiguration();
        HierarchicalConfiguration.Node node = new HierarchicalConfiguration.Node(
                "rpc");
        node.addAttribute(new HierarchicalConfiguration.Node("xmlns",
                rpcNS));
        cfg.setRootElementName("rpc");
        cfg.setRoot(node);
        cfg.setProperty("edit-config.target", "");
        cfg.setProperty("edit-config.target.running", "");
        cfg.setProperty("edit-config.default-operation", editConfigOperation);
        cfg.setProperty("edit-config.config", "");
        node = new HierarchicalConfiguration.Node(
                "system");
        node.addAttribute(new HierarchicalConfiguration.Node("xmlns",
                systemNS));
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).addChild(node);
        node = new HierarchicalConfiguration.Node(
                "CipherSuite");
        node.addAttribute(new HierarchicalConfiguration.Node("xmlns",
                "urn:ietf:params:xml:ns:yang:ieee802-dot1ae"));
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("system").get(0).addChild(node);
        cfg.setProperty("edit-config.config.system.CipherSuite.ciphersuite", "0080020001000001");
        cfg.setProperty("edit-config.config.system.CipherSuite.protection", "Integrity");
        cfg.setProperty("edit-config.config.system.CipherSuite.protectionOffset", 30);
        cfg.setProperty("edit-config.config.system.CipherSuite.ICVLength", 16);
        return sendEditConfRpc(cfg);
    }

    private XMLConfiguration getConfigRpcRequest(String filter) {
        XMLConfiguration cfg = new XMLConfiguration();
        HierarchicalConfiguration.Node node = new HierarchicalConfiguration.Node("rpc");
        node.addAttribute(new HierarchicalConfiguration.Node("xmlns", rpcNS));
        cfg.setRootElementName("rpc");
        cfg.setRoot(node);
        cfg.setProperty("get-config.source", "");
        cfg.setProperty("get-config.source.running", "");
        node = new HierarchicalConfiguration.Node("filter");
        node.addAttribute(new HierarchicalConfiguration.Node("select", filter));
        node.addAttribute(new HierarchicalConfiguration.Node("type", "xpath"));
        cfg.getRoot().getChildren("get-config").get(0).addChild(node);
        return cfg;
    }

    private String sendGetConfRpc(XMLConfiguration request) {
        String sysInfo = "";
        StringWriter writer = new StringWriter();
        try {
            session = controller.getDevicesMap().get(deviceId).getSession();
            request.save(writer);
            sysInfo = session.get(writer.toString());
        } catch (NetconfException e) {
            log.error("Sending RPC message for get-config operation: " + e);
        } catch (ConfigurationException ex) {
            log.error("Sending RPC message for get-config operation: " + ex);
        }
        return sysInfo;
    }

    private boolean sendEditConfRpc(XMLConfiguration cfg) {
        boolean edited = false;
        StringWriter writer = new StringWriter();
        try {
            session = controller.getDevicesMap().get(deviceId).getSession();
            cfg.save(writer);
            edited = session.editConfig(writer.toString());
        } catch (NetconfException e) {
            log.error("Sending RPC message for edit-config operation: " + e);
        } catch (ConfigurationException ex) {
            log.error("Sending RPC message for edit-config operation: " + ex);
        }
        return edited;
    }

    private XMLConfiguration createRpcMessage(String interfaceName, String operation) {
        XMLConfiguration cfg = new XMLConfiguration();
        HierarchicalConfiguration.Node node = new HierarchicalConfiguration.Node("rpc");
        node.addAttribute(new HierarchicalConfiguration.Node("xmlns", rpcNS));
        cfg.setRootElementName("rpc");
        cfg.setRoot(node);
        cfg.setProperty("edit-config.target", "");
        cfg.setProperty("edit-config.target.running", "");
        cfg.setProperty("edit-config.default-operation", operation);
        HierarchicalConfiguration.Node config = new HierarchicalConfiguration.Node("config");
        config.addAttribute(new HierarchicalConfiguration.Node("xmlns:xc", rpcNS));
        cfg.getRoot().getChildren("edit-config").get(0).addChild(config);
        config = new HierarchicalConfiguration.Node("interfaces");
        config.addAttribute(new HierarchicalConfiguration.Node("xmlns", interfaceNS));
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).addChild(config);
        cfg.setProperty(interfaceTag.concat(".name"), interfaceName);
        config = new HierarchicalConfiguration.Node("type");
        config.addAttribute(new HierarchicalConfiguration.Node("xmlns:ianaif", typeNS));
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("interfaces").get(0).getChildren("interface")
                .get(0).addChild(config);
        config = new HierarchicalConfiguration.Node("SecY");
        config.addAttribute(new HierarchicalConfiguration.Node("xmlns", namespace));
        cfg.getRoot().getChildren("edit-config").get(0).getChildren("config")
                .get(0).getChildren("interfaces").get(0).getChildren("interface")
                .get(0).addChild(config);
        cfg.setProperty(interfaceTag.concat(".type"), "ianaif:macSecControlledIF");
        return cfg;
    }

    private Document convertStringToDocument(String xmlStr) {
        Document doc = null;
        try {
            DocumentBuilder db = null;
            db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            InputSource is = new InputSource();
            is.setCharacterStream(new StringReader(xmlStr));
            doc = db.parse(is);
        } catch (SAXException e) {
            log.error("Converting XML string to document object: " + e);
        } catch (IOException ex) {
            log.error("Converting XML string to document object: " + ex);
        } catch (ParserConfigurationException ex) {
            log.error("Converting XML string to document object: " + ex);
        }
        return doc;
    }

    private String getCharacterDataFromElement(Element element) {
        Node child = element.getFirstChild();
        if (child instanceof CharacterData) {
            CharacterData cd = (CharacterData) child;
            return cd.getData();
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

