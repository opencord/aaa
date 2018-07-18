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

import org.onlab.packet.EAPOLMkpduBasicParameterSet.SCI;
import org.onosproject.net.DeviceId;
import org.slf4j.Logger;

import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Created by stack on 25/7/18.
 */

public class Default extends MacSecSecY {
    DeviceId deviceId;
    private final Logger log = getLogger(getClass());

    Default(DeviceId deviceId) {
         this.deviceId = deviceId;
    }

    @Override
    public boolean validateFrames(String portName, CpStateMachine.MacSecValidate validate) {
        log.trace("Request for Validate Frames: {} {}", portName, validate);
        return false;
    }

    @Override
    public boolean protectFrames(String portName, boolean status) {
       log.trace("Request for enabling/disabling Protect Frames : {} {}", portName, status);
       return false;
    }

    @Override
    public boolean createTransmitSC(String portName, SCI sci) {
        log.trace("Transmit SC creation request : {}, {}", portName, sci);
        return false;
    }

    @Override
    public boolean deleteTransmitSC(String portName, SCI sci) {
         log.trace("Transmit SC delete request : [{}, {}]", portName, sci);
         return false;
    }

    @Override
    public boolean createTransmitSA(String portName, SCI sci, int an, long pn) {
        log.trace("Transmit SA creation request : [{}, {}, {}, {}]", portName, sci, an, pn);
        return false;
    }

    @Override
    public boolean deleteTransmitSA(String portName, SCI sci, int an) {
         log.trace("Transmit SA deletion request : [{},{},{},{}]", portName, sci, an);
         return false;
    }

    @Override
    public boolean enableTransmitSA(String portName, SCI sci, int an) {
        log.trace("Transmit SA enable request : [{},{},{},{}]", portName, sci, an);
        return false;
    }

    @Override
    public boolean createReceiveSC(String portName, SCI sci) {
        log.trace("Receive SC creation request : [{}, {}]", portName, sci);
        return false;
    }

    @Override
    public boolean deleteReceiveSC(String portName, SCI sci) {
         log.trace("Receive SC deletion request : [{}, {}]", portName, sci);
         return false;
    }

    @Override
    public boolean createReceiveSA(String portName, SCI sci,
                                   int an, long pn, long lowestPn) {
        log.trace("Receive SA creation request : [{}, {}, {}, {}, {}]", portName, sci, an, pn,
                 lowestPn);
        return false;
    }

    @Override
    public boolean deleteReceiveSA(String portName, SCI sci, int an) {
        log.trace("Receive SA deletion request : [{},{},{},{}]", portName, sci, an);
        return false;
    }

    @Override
    public boolean enableReceiveSA(String portName, SCI sci, int an) {
         log.trace("Receive SA enable request : [{},{},{},{}]", portName, sci, an);
         return false;
    }

    @Override
    public boolean installKey(String portName, int index, byte[] key, byte[] keyIdentifier,
                              boolean transmits, boolean receives) {
        return false;
    }

    @Override
    public boolean removeKey(String portName, int index) {
        return false;
    }

    @Override
    public boolean addCipherSuite(int cipherSuitID, boolean enable, boolean confidentiality) {
        return false;
    }

    @Override
    public boolean setCurrentCipherSuit(String portName, long cipherSuitID) {
        return false;
    }

    @Override
    public List<MacSecCipherSuit> getCipherSuites() {
        return null;
    }

    @Override
    public boolean enablePort(String portName, boolean status) {
        return false;
    }

    @Override
    public boolean replayProtect(String portName, boolean status, int window) {
        return false;
    }
}
