/*
 * Copyright 2017-present .* Open Networking Foundation.
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

import java.util.Arrays;
import java.nio.ByteBuffer;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

/**
 * Default algorithm agility implementation. IEEE Std. 802.1X-2009
 */
public class MacSecDefaultAlgorithmAgility implements MacSecAlgorithmAgility {

    /* IEEE 802.1X, Table 9-1 */
    private byte[] parameter = {(byte) 0x00, (byte) 0x80, (byte) 0xC2, (byte) 0x01};

    /* 128 bits for CAK, KEK, ICK, ICV */
    private int defaultKeyLength = 16;

    /* KDF Parameters */
    private int kdfContextLength = 16;

    /* Default agility initialization. */
    MacSecDefaultAlgorithmAgility() {
    }

    @Override
    public byte[] getParameter() {
        return parameter;
    }

    @Override
    public int getCakLength() {
        return defaultKeyLength * 8;
    }

    @Override
    public int getKekLength() {
        return defaultKeyLength * 8;
    }

    @Override
    public int getIckLength() {
        return defaultKeyLength * 8;
    }

    @Override
    public int getIcvLength() {
        return defaultKeyLength * 8;
    }

    @Override
    public int getSakLength() {
        return defaultKeyLength * 8;
    }

    @Override
    public byte[] generateCak(byte[] msk, byte[] mac1, byte[] mac2) {
        /* IEEE 802.1X 2010, Clause 6.2.2. */
        byte[] cak = null;
        byte[] label = "IEEE8021 EAP CAK".getBytes();
        byte[] context = new byte[mac1.length + mac2.length];
        ByteBuffer contextBuffer = ByteBuffer.wrap(context);
        contextBuffer.put(mac1);
        contextBuffer.put(mac2);
        cak = deriveKey(msk, label, context, (short) getCakLength());
        return cak;
    }

    @Override
    public byte[] generateCkn(byte[] msk, byte[] mac1, byte[] mac2, byte[] sid) {
        /* IEEE 802.1X 2010, Clause 6.2.2. */
        byte[] ckn = null;
        byte[] label = "IEEE8021 EAP CKN".getBytes();
        byte[] context = new byte[sid.length + mac1.length + mac2.length];
        ByteBuffer contextBuffer = ByteBuffer.wrap(context);
        contextBuffer.put(sid);
        contextBuffer.put(mac1);
        contextBuffer.put(mac2);
        ckn = deriveKey(msk, label, context, (short) (defaultKeyLength * 8));
        return ckn;
    }

    @Override
    public byte[] generateKek(byte[] cak, byte[] ckn) {
        /* IEEE 802.1X 2010, Clause 9.3.3. */
        byte[] kek = null;
        byte[] label = "IEEE8021 KEK".getBytes();
        byte[] keyID = Arrays.copyOfRange(ckn, 0, kdfContextLength);
        kek = deriveKey(cak, label, keyID, (short) getKekLength());
        return kek;
    }

    @Override
    public byte[] generateIck(byte[] cak, byte[] ckn) {
        /* IEEE 802.1X 2010, Clause 9.3.3. */
        byte[] ick = null;
        byte[] label = "IEEE8021 ICK".getBytes();
        byte[] keyID = Arrays.copyOfRange(ckn, 0, kdfContextLength);
        ick = deriveKey(cak, label, keyID, (short) getIckLength());
        return ick;
    }

    @Override
    public byte[] generateIcv(byte[] ick, byte[] msg) {
        /* IEEE 802.1X-2010 9.4.1
         * ICV = AES-CMAC(ICK, M, 128) */
        byte[] icv = null;
        // icv = prf(ick, msg, 128);
        icv = prf(ick, msg, msg.length);
        return icv;

        //return MkaKeyUtils.hexStringToByteArray("045205925831ae59c14550ed59cc003d");
    }

    @Override
    public byte[] generateSak(byte[] cak, byte[] ksNonce, byte[] memberIDs, int keyNumber) {
        byte[] sak = null;
        byte[] label = "IEEE8021 SAK".getBytes();
        byte[] kn = ByteBuffer.allocate(4).putInt(keyNumber).array();
        byte[] context = new byte[ksNonce.length + memberIDs.length + kn.length];
        ByteBuffer contextBuffer = ByteBuffer.wrap(context);
        contextBuffer.put(ksNonce);
        contextBuffer.put(memberIDs);
        contextBuffer.put(kn);
        sak = deriveKey(cak, label, context, (short) getSakLength());
        return sak;
    }

    /**
     * Key Derivation Function(KDF). IEEE 802.1X-2010, 6.2.1
     *
     * @param key       - Key derivation key either 128 or 256 bits
     * @param label     - String identifying the purpose of keys derived using KDF
     * @param context   - Bit string that provides context to identify derived key
     * @param keyLength - Length of output key in bits encoded in two octets with the most significant octet first
     * @return Derived Key
     */
    private byte[] deriveKey(byte[] key, byte[] label, byte[] context, short keyLength) {

        byte[] length = ByteBuffer.allocate(2).putShort(keyLength).array();
        int iterations, h;
        double r = 32;

        // Convert key length into bytes
        h = key.length;

        // Number of iterations to perform
        iterations = (key.length * 8 + (h - 1)) / h;

        // Check if iterations exceeds limit of integer capacity
        if (iterations > (Math.pow(2, r) - 1)) {
            return null;
        }

        // Perform key generation
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        ByteArrayOutputStream catStream = new ByteArrayOutputStream();
        try {
            for (short i = 1; i < iterations; i++) {
                message.write(i);
                message.write(label);
                message.write(0x00);
                message.write(context);
                message.write(length);
                byte[] cat = message.toByteArray();
                catStream.write(prf(key, cat, cat.length));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


        byte[] result = catStream.toByteArray();

        /* Perform shift operation to get the first Length-bits of the result */
        int bitsToShift = (result.length * 8) - key.length * 8;
        BigInteger shiftInt = new BigInteger(result).shiftRight(bitsToShift);
        return shiftInt.toByteArray();
    }


    /**
     * Pseudo Random Function - Currently AES_CMAC.
     *
     * @param key     - Input key.
     * @param message - Message to be hashed/authenticated.
     * @param length  - Length of message.
     * @return Message Authentication Code (MAC).
     */
    private static byte[] prf(byte[] key, byte[] message, int length) {
        return (new AescMac()).generateAescMac(key, message, length);
    }

}
