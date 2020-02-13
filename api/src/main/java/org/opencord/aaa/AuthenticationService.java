/*
 * Copyright 2018-present Open Networking Foundation
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

import org.onlab.packet.MacAddress;
import org.onosproject.event.ListenerService;

/**
 * Service for interacting with authentication state.
 */
public interface AuthenticationService extends
        ListenerService<AuthenticationEvent, AuthenticationEventListener> {

    /**
     * Gets records of authentications that are completed or in progress.
     *
     * @return list of authentication records
     */
    Iterable<AuthenticationRecord> getAuthenticationRecords();

    /**
     * Removes an authentication record.
     *
     * @param mac MAC address of record to remove
     * @return true if a record was removed, otherwise false
     */
    boolean removeAuthenticationStateByMac(MacAddress mac);

    /**
     * Gets the machine stats based on machine session id.
     *
     * @param sessionID SessionID of machine
     * @return AaaSupplicantMachineStats object
     */
    AaaSupplicantMachineStats getSupplicantMachineStats(String sessionID);

}
