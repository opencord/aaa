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

import org.slf4j.Logger;

import org.onlab.packet.EAPOLMkpduBasicParameterSet.SCI;

import org.onosproject.net.DeviceId;

import org.opencord.aaa.CpStateMachine.MacSecValidate;

import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;

public class MacSecSecY {

    private final Logger log = getLogger(getClass());
    DeviceId deviceId;

    MacSecSecY(DeviceId deviceId) {
        this.deviceId = deviceId;
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
        log.trace("Transmit SC creation request : {}, {}", portName, sci);
        return true;
    }

    public boolean deleteTransmitSC(String portName, SCI sci) {
        log.trace("Transmit SC delete request : [{}, {}]", portName, sci);
        return true;
    }

    public boolean createTransmitSA(String portName, SCI sci, int an, long pn) {
        log.trace("Transmit SA creation request : [{}, {}, {}, {}]", portName, sci, an, pn);
        return true;
    }

    public boolean deleteTransmitSA(String portName, SCI sci, int an) {
        log.trace("Transmit SA deletion request : [{},{},{},{}]", portName, sci, an);
        return true;
    }

    public boolean enableTransmitSA(String portName, SCI sci, int an) {
        log.trace("Transmit SA enable request : [{},{},{},{}]", portName, sci, an);
        return true;
    }

    public boolean createReceiveSC(String portName, SCI sci) {
        log.trace("Receive SC creation request : [{}, {}]", portName, sci);
        return true;
    }

    public boolean deleteReceiveSC(String portName, SCI sci) {
        log.trace("Receive SC deletion request : [{}, {}]", portName, sci);
        return true;
    }

    public boolean createReceiveSA(String portName, SCI sci, int an, long pn, long lowestPn) {
        log.trace("Receive SA creation request : [{}, {}, {}, {}, {}]", portName, sci, an, pn,
                lowestPn);
        return true;
    }

    public boolean deleteReceiveSA(String portName, SCI sci, int an) {
        log.trace("Receive SA deletion request : [{},{},{},{}]", portName, sci, an);
        return true;
    }

    public boolean enableReceiveSA(String portName, SCI sci, int an) {
        log.trace("Receive SA enable request : [{},{},{},{}]", portName, sci, an);
        return true;
    }

    /* SAK Keys. */
    public boolean installKey(String portName, int index, byte[] key, byte[] keyIdentifier,
                              boolean transmits, boolean receives) {
        log.trace("Received Key Installation request : {} {} {} {} {} {}", portName, index, key,
                keyIdentifier, transmits, receives);
        return true;
    }

    public boolean removeKey(String portName, int index) {
        log.trace("Received Key Removal request : {} {}", portName, index);
        return true;
    }

    /* CipherSuit configuration. */
    public boolean addCipherSuite(int cipherSuitID, boolean enable,
                                     boolean confidentiality) {
        return true;
    }

    public boolean setCurrentCipherSuit(String portName, long cipherSuitID) {
        log.trace("Request for setting current Cipher Suit : {} {}", portName, cipherSuitID);
        return true;
    }

    public List<MacSecCipherSuit> getCipherSuites() {
        return null;
    }

    /* Port enable/disable*/
    public boolean enablePort(String portName, boolean status) {
        log.trace("Enable port request : {} {} {}", portName, status);
        return true;
    }

    public boolean replayProtect(String portName, boolean status, int window) {
        log.trace("Replay protection request : {} {} {}", portName, status, window);
        return true;
    }
}

