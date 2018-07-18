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
import java.util.List;

/**
 * Created by stack on 25/7/18.
 */
public abstract class MacSecSecY {

    public abstract boolean validateFrames(String portName, CpStateMachine.MacSecValidate validate);

    public abstract boolean protectFrames(String portName, boolean status);

    public abstract boolean createTransmitSC(String portName, SCI sci);

    public abstract boolean deleteTransmitSC(String portName, SCI sci);

    public abstract boolean createTransmitSA(String portName, SCI sci, int an, long pn);

    public abstract boolean deleteTransmitSA(String portName, SCI sci, int an);

    public abstract boolean enableTransmitSA(String portName, SCI sci, int an);

    public abstract boolean createReceiveSC(String portName, SCI sci);

    public abstract boolean deleteReceiveSC(String portName, SCI sci);

    public abstract boolean createReceiveSA(String portName, SCI sci,
                                   int an, long pn, long lowestPn);

    public abstract boolean deleteReceiveSA(String portName, SCI sci, int an);

    public abstract boolean enableReceiveSA(String portName, SCI sci, int an);

    public abstract boolean installKey(String portName, int index, byte[] key, byte[] keyIdentifier,
                              boolean transmits, boolean receives);

    public abstract boolean removeKey(String portName, int index);

    public abstract boolean addCipherSuite(int cipherSuitID, boolean enable,
                                  boolean confidentiality);

    public abstract boolean setCurrentCipherSuit(String portName, long cipherSuitID);

    public abstract List<MacSecCipherSuit> getCipherSuites();

    public abstract boolean enablePort(String portName, boolean status);

    public abstract boolean replayProtect(String portName, boolean status, int window);
}
