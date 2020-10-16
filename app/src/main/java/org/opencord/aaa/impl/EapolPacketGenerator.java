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

import org.onlab.packet.EAP;

/**
 * Class that is responsible to generate fake EAPOL packets in case that
 * FORGE_EAPOL_PACKETS is set to true in the config.
 */
public final class EapolPacketGenerator {

    private EapolPacketGenerator() {}

    public static EAP forgeEapolChallengeAuth() {
        EAP eapPayload = new EAP(
                new Integer(1).byteValue(), new Integer(1).byteValue(),
                new Integer(4).byteValue(),
                hexStringToByteArray("108b4eb55f859c501b3e14a594c4997bed"));
        return eapPayload;
    }

    public static EAP forgeEapolSuccess() {
        EAP eapPayload = new EAP(
                new Integer(3).byteValue(),
                new Integer(2).byteValue(),
                new Integer(0).byteValue(),
                hexStringToByteArray("")
        );
        return eapPayload;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
