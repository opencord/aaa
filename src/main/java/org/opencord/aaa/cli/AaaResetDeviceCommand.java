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
package org.opencord.aaa.cli;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;
import org.opencord.aaa.api.AaaService;

@Command(scope = "onos", name = "aaa-reset-device",
        description = "Resets authentication sessions for a given device")
public class AaaResetDeviceCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "mac",
            description = "MAC of device to reset authentication sessions",
            required = true, multiValued = true)
    private String[] macs = null;

    @Override
    protected void execute() {
        AaaService aaaService = get(AaaService.class);

        // FIXME: access needs to be through AaaService - Proposal...
//        aaaService.resetAuthenticationSessionsByDeviceMac(macs);

        // We shouldn't have visibility to StateMachine.
        /*
        for (String mac : macs) {
            StateMachine.deleteByMac(MacAddress.valueOf(mac));
        }
        */
    }
}
