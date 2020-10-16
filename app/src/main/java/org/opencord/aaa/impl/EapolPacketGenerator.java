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
                EapolPacketGenerator.hexStringToByteArray("108b4eb55f859c501b3e14a594c4997bed"));
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

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
