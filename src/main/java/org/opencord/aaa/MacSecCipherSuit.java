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

/*
 * Cipher Suit representation. IEEE 802.1AE 2006; Clause 14
 */
class MacSecCipherSuit {
    private Long id;
    private String name;
    private MacSecCapabilities capabilities;
    private MacSecConfidentialityOffset confidentialityOffset;
    private int keyLength;

    /*
    * MACSec Capabalities. IEEE 802.1x; Table 11-6
    */
    public enum MacSecCapabilities {
        /* Not implemented */
        NOT_IMPLEMENTED,

        /* 'Integrity without confidentiality' */
        INTEGRITY,

        /* 'Integrity without confidentiality' and
           'Integrity and confidentiality' with a confidentiality offset of 0*/
        INTEGRITY_AND_CONFIDENTIALITY,

        /* 'Integrity without confidentiality' and
           'Integrity and confidentiality' with a confidentiality offset of 0, 30, 50 */
        INTEGRITY_AND_CONFIDENTIALITY_0_30_50
    }

    /* Confidentiality Offset. */
    public enum MacSecConfidentialityOffset {
        /* No confidentiality. */
        CONFIDENTIALITY_NONE,
        CONFIDENTIALITY_OFFSET_0,
        CONFIDENTIALITY_OFFSET_30,
        CONFIDENTIALITY_OFFSET_50,
    }

    MacSecCipherSuit() {

        /* Default Cipher Suit. GCM-AES-128. Clause 14.4 */
        this.id = Long.parseLong("800200"); //Long.parseLong("0080020001000001");
        this.name = "GCM-AES-128";
        this.capabilities = MacSecCapabilities.INTEGRITY_AND_CONFIDENTIALITY_0_30_50;
        keyLength = 16; /* Unit: bytes. ie. 128bits = 16 bytes */
        confidentialityOffset = MacSecConfidentialityOffset.CONFIDENTIALITY_OFFSET_0;
    }

    MacSecCipherSuit(Long id, String name, MacSecCapabilities capabilities,
                     MacSecConfidentialityOffset confidentialityOffset, int keyLength) {
        this.id = id;
        this.name = name;
        this.capabilities = capabilities;
        this.keyLength = keyLength;
        this.confidentialityOffset = confidentialityOffset;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public MacSecConfidentialityOffset getConfidentialityOffset() {
        return confidentialityOffset;
    }

    public long id() {
        return id.longValue();
    }
}
