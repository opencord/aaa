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

package org.opencord.aaa;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;

import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * AES-CMAC Algorithm. RFC 4493.
 * Cipher-based Message Authentication Code(CMAC),
 * a keyed hash function based on a symmetric key block cipher: Advanced Encryption Standard(AES).
 * Reference: https://github.com/E3V3A/androsmex/blob/master/src/de/tsenger/androsmex/tools/AESCMac.java
 */
public class AescMac {

    private static byte[] constZero = MkaKeyUtils.hexStringToByteArray("00000000000000000000000000000000");
    private static byte[] constRb = MkaKeyUtils.hexStringToByteArray("00000000000000000000000000000087");
    private byte[] key;
    private ByteArrayOutputStream catInput;


    /**
     * AES 128-bit encryption using JDK built-in classes.
     */
    private static class AesCrypto {
        private static final Logger log = getLogger(AesCrypto.class);
        static Cipher aesEcb = null;

        static {
            try {
                aesEcb = Cipher.getInstance("AES/ECB/NOPADDING");
            } catch (Exception e) {
                log.error("Error in AES 128-bit encryption ", e);
            }
        }

        /**
         * Encrypt AES 128 bit key.
         *
         * @param zeroConst - Zero-constant
         * @param key       - Input key value
         * @return Encrypted Key
         */
        private static byte[] encryptAES128(byte[] zeroConst, byte[] key) {
            SecretKey aesKey = new SecretKeySpec(key, 0, 16, "AES");
            try {
                synchronized (aesEcb) {
                    aesEcb.init(Cipher.ENCRYPT_MODE, aesKey);
                    return aesEcb.doFinal(zeroConst);
                }
            } catch (Exception e) {
                log.error("Error in encrypting AES 128 bit key ", e);
            }
            return null;
        }

        static Cipher aesKeyWrapper = null;

        static {
            try {
                aesKeyWrapper = Cipher.getInstance("AESWrap");
            } catch (Exception e) {
                log.error("Error in AES 128-bit encryption ", e);
            }
        }

        /**
         * AES Key Wrapper.
         *
         * @param message - Message to be wrapped
         * @param key     - Key-Encryption Key
         * @return Wrapped key
         */
        private static byte[] keyWrap(byte[] key, byte[] message) {
            SecretKey aesKey = new SecretKeySpec(key, 0, 16, "AES");
            SecretKey messageKey = new SecretKeySpec(message, 0, 16, "AES");
            try {
                synchronized (aesKeyWrapper) {
                    aesKeyWrapper.init(Cipher.WRAP_MODE, aesKey);
                    byte[] wrappedKey = aesKeyWrapper.wrap(messageKey);

                    /* Unwrap the key */
                    aesKeyWrapper.init(Cipher.UNWRAP_MODE, aesKey);
                    messageKey = (SecretKey) aesKeyWrapper.unwrap(wrappedKey, "AES/CTR/NOPADDING", Cipher.SECRET_KEY);

                    return wrappedKey;
                }
            } catch (Exception e) {
                log.error("Error in key wrapping ", e);
            }
            return null;
        }

    }

    /**
     * Wrap a message.
     *
     * @param message - Message to be wrapped
     * @param key     - Key-Encryption Key
     * @return Wrapped key
     */
    public byte[] wrap(byte[] key, byte[] message) {
        return AesCrypto.keyWrap(key, message);
    }

    /**
     * Generate AES message authentication code.
     *
     * @param key - Key derivation key
     * @param m   - Message to be authenticated
     * @param len - Length of message in octets
     * @return Message Authentication Code
     */
    public byte[] generateAescMac(byte[] key, byte[] m, int len) {

        initialize(key);
        update(m, 0, len);
        return generateMac();
    }

    /**
     * Initialize data members.
     *
     * @param key Key derivation key
     */
    private void initialize(byte[] key) {
        this.key = key;
        catInput = new ByteArrayOutputStream();
    }

    /**
     * Update the message byte array with offset and length.
     *
     * @param msg    - Message to be authenticated
     * @param offset - Offset to be added
     * @param len    - Length of the message
     */
    private void update(byte[] msg, int offset, int len) {
        catInput.write(msg, offset, len);
    }

    /**
     * Generate MAC.
     *
     * @return Message authentication code
     */
    private byte[] generateMac() {
        // Step 1
        Object[] keys = generateSubKey(key);
        byte[] k1 = (byte[]) keys[0];
        byte[] k2 = (byte[]) keys[1];
        byte[] input = catInput.toByteArray();

        // Step 2
        int numberOfRounds = (input.length + 15) / 16;
        boolean lastBlockComplete;

        // Step 3
        if (numberOfRounds == 0) {
            numberOfRounds = 1;
            lastBlockComplete = false;
        } else {
            lastBlockComplete = (input.length % 16 == 0);
        }

        byte[] mLast;
        int srcPos = 16 * (numberOfRounds - 1);

        // Step 4
        if (lastBlockComplete) {
            byte[] partInput = new byte[16];

            System.arraycopy(input, srcPos, partInput, 0, 16);
            mLast = xor128(partInput, k1);
        } else {
            byte[] partInput = new byte[input.length % 16];

            System.arraycopy(input, srcPos, partInput, 0, input.length % 16);
            byte[] padded = padTo16(partInput);
            mLast = xor128(padded, k2);
        }

        // Step 5
        byte[] x = constZero.clone();
        byte[] partInput = new byte[16];
        byte[] y;

        // Step 6
        for (int i = 0; i < numberOfRounds - 1; i++) {
            srcPos = 16 * i;
            System.arraycopy(input, srcPos, partInput, 0, 16);

            y = xor128(partInput, x); // Y := Mi (+) X
            x = AesCrypto.encryptAES128(y, key);
        }

        y = xor128(x, mLast);
        x = AesCrypto.encryptAES128(y, key);

        // Step 7
        return x;
    }

    /**
     * Pad to 16 bytes.
     *
     * @param input - Value to be padded
     * @return Padded byte array
     */
    private byte[] padTo16(byte[] input) {
        byte[] padded = new byte[16];

        for (int j = 0; j < 16; j++) {
            if (j < input.length) {
                padded[j] = input[j];
            } else if (j == input.length) {
                padded[j] = (byte) 0x80;
            } else {
                padded[j] = (byte) 0x00;
            }
        }
        return padded;
    }

    /**
     * Generate Subkey.
     *
     * @param key - Input key to generate the subkeys
     * @return Array of two subkeys
     */
    private static Object[] generateSubKey(byte[] key) {
        // Step 1
        byte[] l = AesCrypto.encryptAES128(constZero, key);

        // Step 2
        byte[] k1;
        if ((l[0] & 0x80) == 0) { // If MSB(L) = 0, then K1 = L << 1
            k1 = leftShiftBit(l);
        } else {    //Else K1 = ( L << 1 ) (+) Rb
            byte[] tmp = leftShiftBit(l);
            k1 = xor128(tmp, constRb);
        }

        // Step 3
        byte[] k2;
        if ((k1[0] & 0x80) == 0) {
            k2 = leftShiftBit(k1);
        } else {
            byte[] tmp = leftShiftBit(k1);
            k2 = xor128(tmp, constRb);
        }

        // Step 4
        Object[] result = new Object[2];
        result[0] = k1;
        result[1] = k2;
        return result;
    }

    /**
     * XOR two values.
     *
     * @param input1 - java.util.byte[]
     * @param input2 - java.util.byte[]
     * @return XORed byte array
     */
    private static byte[] xor128(byte[] input1, byte[] input2) {
        byte[] output = new byte[input1.length];
        for (int i = 0; i < input1.length; i++) {
            output[i] = (byte) (((int) input1[i] ^ (int) input2[i]) & 0xFF);
        }
        return output;
    }

    /**
     * Shift left by one bit.
     *
     * @param input - Value to be shifted
     * @return Shifted result
     */
    private static byte[] leftShiftBit(byte[] input) {
        byte[] output = new byte[input.length];
        byte overflow = 0;
        for (int i = (input.length - 1); i >= 0; i--) {
            output[i] = (byte) ((int) input[i] << 1 & 0xFF);
            output[i] |= overflow;
            overflow = ((input[i] & 0x80) != 0) ? (byte) 1 : (byte) 0;
        }

        return output;
    }
}

