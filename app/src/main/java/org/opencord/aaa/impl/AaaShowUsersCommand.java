/*
 * Copyright 2016-present Open Networking Foundation
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

import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.device.DeviceService;

import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;

/**
 * Shows the users in the aaa.
 */
@Command(scope = "onos", name = "aaa-users",
        description = "Shows the aaa users")
public class AaaShowUsersCommand extends AbstractShellCommand {
    @Override
    protected void execute() {
        String[] state = {
                "IDLE",
                "STARTED",
                "PENDING",
                "AUTHORIZED",
                "UNAUTHORIZED"
        };

        DeviceService devService = AbstractShellCommand.get(DeviceService.class);
        SadisService sadisService =
                AbstractShellCommand.get(SadisService.class);

        for (StateMachine stateMachine : StateMachine.sessionIdMap().values()) {
            String deviceId = stateMachine.supplicantConnectpoint().deviceId().toString();
            String portNum = stateMachine.supplicantConnectpoint().port().toString();

            String username = "UNKNOWN";
            if (stateMachine.username() != null) {
                username = new String(stateMachine.username());
            }
            String mac = "UNKNOWN";
            if (stateMachine.supplicantAddress() != null) {
                mac = stateMachine.supplicantAddress().toString();
            }

            String nasPortId = devService.getPort(stateMachine.supplicantConnectpoint()).
                    annotations().value(AnnotationKeys.PORT_NAME);

            String subsId = "UNKNOWN";
            SubscriberAndDeviceInformation subscriber = sadisService.getSubscriberInfoService().get(nasPortId);
            if (subscriber != null) {
                subsId = subscriber.nasPortId();
            }

            print("UserName=%s,CurrentState=%s,DeviceId=%s,MAC=%s,PortNumber=%s,SubscriberId=%s",
                  username, state[stateMachine.state()], deviceId, mac, portNum, subsId);
        }
    }
}
