/*
 * Copyright 2017-present.* Open Networking Foundation.
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


import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MKA KaY( MAC Key Agreement Protocol Entity) per device information.
 * IEEE 802.1X-2010 Clause 9.16, Figure 12-3.
 */
public class MacSecKaY {
    /* KaY activation  */
    boolean enable;

    /* MKA Version */
    private byte mkaVersion = 0x01;

    /* SecY interface */
    MacSecSecY secY = null;

    /* Algorithm Agility. IEEE 802.1X 2010; Table 9.1.
     * Currently standard supports only one. List is used considering future additions. */
    private List<MacSecAlgorithmAgility> agilities = new ArrayList<>();
    private static int defaultAlgorithmAgility = 0;

    /* CipherSuits supported by device. */
    private List<MacSecCipherSuit> cipherSuits = new ArrayList<>();
    private static int defaultCipherSuitOffset = 0;

    /* Participants & CP state machine store.  */
    private Map<String, Map.Entry<MkaParticipant, CpStateMachine>> portStoreMap =
            new ConcurrentHashMap<>();

    /* Load all SecY supporting CipherSuits */
    private void loadCipherSuits() {
        /* TODO : Load CipherSuits using SecY. */
    }

    MacSecKaY(MacSecSecY secY) {
        /* Initialize default algorithm agility. IEEE 802.1X; Table 9.1*/
        agilities.add(defaultAlgorithmAgility, new MacSecDefaultAlgorithmAgility());

        /* Initialize CipherSuits.
         * All devices should support default CipherSuit GCM–AES–128. IEEE 802.1AE 14.5
         */
        this.secY = secY;
        cipherSuits.add(defaultCipherSuitOffset, new MacSecCipherSuit());
        loadCipherSuits();
    }

    /**
     * Adding participants & CP state machine to KaY.
     *
     * @param id             value in <Device ID><Port ID> format
     * @param participant    details
     * @param cpStateMachine details
     */
    public void addPortDetails(String id, MkaParticipant participant, CpStateMachine cpStateMachine) {
        portStoreMap.put(id, new AbstractMap.SimpleEntry<>(participant, cpStateMachine));
    }

    /* Retrieve Participant using CAK */
    public MkaParticipant participant(byte[] ckn) {
        Optional<Map.Entry<String, Map.Entry<MkaParticipant, CpStateMachine>>> participant =
                portStoreMap.entrySet().stream()
                        .filter(entry -> entry.getValue().getKey().cak().equals(ckn))
                        .findFirst();
        return participant.isPresent() ? participant.get().getValue().getKey() : null;
    }

    /* Participant by ID. */
    public MkaParticipant lookupParticipantByID(String id) {
        Map.Entry<MkaParticipant, CpStateMachine> portDetails = portStoreMap.getOrDefault(id, null);
        return (portDetails != null) ? portDetails.getKey() : null;
    }

    /* CP state machine by ID */
    public CpStateMachine lookupCPStateMachineByID(String id) {
        Map.Entry<MkaParticipant, CpStateMachine> portDetails = portStoreMap.getOrDefault(id, null);
        return (portDetails != null) ? portDetails.getValue() : null;
    }

    /* Default algorithm agility. */
    public MacSecAlgorithmAgility defaultAlgorithmAgility() {
        return agilities.get(defaultAlgorithmAgility);
    }

    /* Default cipher suit. */
    public MacSecCipherSuit defaultCipherSuit() {
        return cipherSuits.get(defaultCipherSuitOffset);
    }

    /* Version */
    public byte mkaVersion() {
        return mkaVersion;
    }
 }
