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
package org.opencord.aaa.api;

import java.util.List;

/**
 * Service API for interacting with the AAA application.
 */
public interface AaaService {

    /**
     * Adds the specified listener for authentication events.
     *
     * @param listener the listener
     */
    void addListener(AaaListener listener);

    /**
     * Removes the specified listener for authentication events.
     *
     * @param listener the listener
     */
    void removeListener(AaaListener listener);

    /**
     * Returns a list of session descriptors for the currently active sessions.
     *
     * @return a list of current sessions
     */
    List<AaaSession> currentSessions();

    /**
     * Resets (removes internal records) of authentication sessions that
     * originate from the device(s) with the given MAC(s).
     *
     * @param macs one or more device MAC addresses
     */
    void resetAuthenticationSessionsByDeviceMac(String... macs);

    /**
     * Registers a packet customizer with AAA, to be used to customize
     * packets issued to and from the RADIUS server.
     *
     * @param customizer the customizer to register
     */
    void registerPacketCustomizer(PacketCustomizer customizer);

    /**
     * Unregisters the given packet customizer from AAA.
     * <p>
     * Note: AAA will revert to a default customizer, that does no
     * customization of the packets.
     *
     * @param customizer the customizer to unregister
     */
    void unregisterPacketCustomizer(PacketCustomizer customizer);
}
