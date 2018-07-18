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

/**
 * Misc. MKA key utility.
 */
public final class MkaKeyUtils {

    static final char[] HEX_DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    private MkaKeyUtils(){

    }
    /**
     * Convert hex string to byte array.
     *
     * @param s - Hex string to be converted to byte array
     * @return byte array formed from the string
     */
    public static byte[] hexStringToByteArray(String s) {
        int len;
        byte[] data;
        if (s == null) {
            return null;
        }

        len = s.length();
        data = new byte[len / 2]; /* Two characters forms one byte. */
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Utility to convert byte to hex string.
     *
     * @param data - Byte array to be converted to hex string
     * @return - String representing ASCII hex string of given data.
     */
    public static String byteArrayToHexString(byte[] data) {
        final char[] hexString = new char[data.length << 1];
        if (data == null) {
            return null;
        }

        for (int i = 0, j = 0; i < data.length; i++) {
            hexString[j++] = HEX_DIGITS[(data[i] & 0xF0) >>> 4];
            hexString[j++] = HEX_DIGITS[data[i] & 0x0F];
        }
        return new String(hexString);
    }

}
