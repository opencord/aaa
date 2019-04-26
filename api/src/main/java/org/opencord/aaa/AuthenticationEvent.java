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

import org.onosproject.event.AbstractEvent;
import org.onosproject.net.ConnectPoint;

/**
 * Event indicating the authentication state of a port has changed.
 */
public class AuthenticationEvent extends
        AbstractEvent<AuthenticationEvent.Type, ConnectPoint> {

    /**
     * Authentication event type.
     */
    public enum Type {
        /**
         * Supplicant has started authentication on a port.
         */
        STARTED,

        /**
         * Supplicant has requested authentication on a port.
         */
        REQUESTED,

        /**
         * Authentication request was approved.
         */
        APPROVED,

        /**
         * Authentication request was denied.
         */
        DENIED
    }

    /**
     * Creates a new authentication event.
     *
     * @param type event type
     * @param connectPoint port
     */
    public AuthenticationEvent(Type type, ConnectPoint connectPoint) {
        super(type, connectPoint);
    }

}
