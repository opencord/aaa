/*
 * Copyright 2020-present Open Networking Foundation
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

import java.util.Objects;

/**
 * An identifier for an authentication request.
 */
public final class RequestIdentifier {

    private byte identifier;

    /**
     * Creates a new request identifier.
     *
     * @param identifier id number
     */
    private RequestIdentifier(byte identifier) {
        this.identifier = identifier;
    }

    /**
     * Returns the id number.
     *
     * @return id
     */
    public byte identifier() {
        return this.identifier;
    }

    /**
     * Creates a new request identifier.
     *
     * @param identifier id number
     * @return identifier
     */
    public static RequestIdentifier of(byte identifier) {
        return new RequestIdentifier(identifier);
    }

    public boolean equals(Object other) {
        if (!(other instanceof RequestIdentifier)) {
            return false;
        }

        RequestIdentifier that = (RequestIdentifier) other;

        return identifier == that.identifier;
    }

    public int hashCode() {
        return Objects.hashCode(identifier);
    }
}
