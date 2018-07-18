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
