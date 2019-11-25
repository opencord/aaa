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

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.MacAddress;
import org.onosproject.cli.AbstractShellCommand;
import org.opencord.aaa.AuthenticationService;

/**
 * Removes a AAA state machine.
 */
@Service
@Command(scope = "onos", name = "aaa-reset-device",
         description = "Resets the authentication state machine for a given device")
public class AaaResetDeviceCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "mac", description = "MAC of device to reset authention state",
              required = true, multiValued = true)
    private String[] macs = null;

    @Override
    protected void doExecute() {
        AuthenticationService service = get(AuthenticationService.class);

        for (String mac : macs) {
            service.removeAuthenticationStateByMac(MacAddress.valueOf(mac));
        }
    }
}
