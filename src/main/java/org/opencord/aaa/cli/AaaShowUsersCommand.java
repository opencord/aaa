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
package org.opencord.aaa.cli;

import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Port;
import org.onosproject.net.device.DeviceService;
import org.opencord.aaa.api.AaaService;
import org.opencord.aaa.api.AaaSession;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.SubscriberAndDeviceInformationService;

import java.util.ArrayList;
import java.util.List;

/**
 * Shows the users in the aaa.
 */
@Command(scope = "onos", name = "aaa-users",
        description = "Displays the users with current AAA sessions")
public class AaaShowUsersCommand extends AbstractShellCommand {

    private static final String UNKNOWN = "UNKNOWN";

    @Override
    protected void execute() {
        DeviceService devService = get(DeviceService.class);
        SubscriberAndDeviceInformationService subsService =
                get(SubscriberAndDeviceInformationService.class);
        AaaService aaaService = get(AaaService.class);

// TODO: add currentSessions() to AaaService API
//        List<AaaSession> sessionList = aaaService.currentSessions();
        List<AaaSession> sessionList = new ArrayList<>();

        for (AaaSession s : sessionList) {
            String subsId = getSubscriberId(devService, subsService, s.getConnectPoint());
            print("UserName=%s,CurrentState=%s,DeviceId=%s,MAC=%s,PortNumber=%s,SubscriberId=%s",
                  s.username(), s.state(), s.deviceId(), s.macAddress(), s.portNumber(), subsId);
        }
    }

    private String getSubscriberId(DeviceService devService,
                                   SubscriberAndDeviceInformationService sadis,
                                   ConnectPoint cp) {
        Port p = devService.getPort(cp);
        String nasPortId = p.annotations().value(AnnotationKeys.PORT_NAME);
        SubscriberAndDeviceInformation subscriber = sadis.get(nasPortId);
        return (subscriber == null) ? UNKNOWN : subscriber.nasPortId();
    }
}
