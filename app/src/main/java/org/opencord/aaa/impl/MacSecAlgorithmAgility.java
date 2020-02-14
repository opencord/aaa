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

package org.opencord.aaa.impl;

/**
 * Algorithm Agility.
 */
public interface MacSecAlgorithmAgility {

    /* Misc information */
    public byte[] getParameter();

    /* Various Key Lengths */
    public int getCakLength();
    public int getKekLength();
    public int getIckLength();
    public int getIcvLength();
    public int getSakLength();

    /* Transformation Functions */
    public byte[] generateCak(byte[] msk, byte[] mac1, byte[] mac2);
    public byte[] generateCkn(byte[] msk, byte[] mac1, byte[] mac2, byte[] sid);
    public byte[] generateKek(byte[] cak, byte[] ckn);
    public byte[] generateIck(byte[] cak, byte[] ckn);
    public byte[] generateIcv(byte[] ick, byte[] msg);

    public byte[] generateSak(byte[] cak, byte[] ksNonce, byte[] memberIDs, int keyNumber);

}
