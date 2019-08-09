/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.opencord.aaa.impl;

import org.apache.karaf.shell.commands.Command;
import org.onlab.packet.MacAddress;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Removes the AAA state machine of all devices.
 */
@Command(scope = "onos", name = "aaa-reset-all-devices",
        description = "Resets the authentication state machine for all devices")
public class AaaResetAllDevicesCommand extends AbstractShellCommand {
    @Override
    protected void execute() {
        for (StateMachine stateMachine : StateMachine.sessionIdMap().values()) {
            String mac = "UNKNOWN";
            if (stateMachine.supplicantAddress() != null) {
                mac = stateMachine.supplicantAddress().toString();
                StateMachine.deleteByMac(MacAddress.valueOf(mac));
            }
        }
    }
}
