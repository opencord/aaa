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
package org.opencord.aaa.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.device.DeviceService;
import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.AuthenticationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;

/**
 * Shows the users in the aaa.
 */
@Service
@Command(scope = "onos", name = "aaa-users",
        description = "Shows the aaa users")
public class AaaShowUsersCommand extends AbstractShellCommand {
    @Override
    protected void doExecute() {

        DeviceService devService = get(DeviceService.class);
        SadisService sadisService = get(SadisService.class);
        AuthenticationService authService = get(AuthenticationService.class);

        for (AuthenticationRecord auth : authService.getAuthenticationRecords()) {
            String deviceId = auth.supplicantConnectPoint().deviceId().toString();
            String portNum = auth.supplicantConnectPoint().port().toString();

            String username = "UNKNOWN";
            if (auth.username() != null) {
                username = new String(auth.username());
            }
            String mac = "UNKNOWN";
            if (auth.supplicantAddress() != null) {
                mac = auth.supplicantAddress().toString();
            }

            String nasPortId = devService.getPort(auth.supplicantConnectPoint()).
                    annotations().value(AnnotationKeys.PORT_NAME);

            String subsId = "UNKNOWN";
            SubscriberAndDeviceInformation subscriber = sadisService.getSubscriberInfoService().get(nasPortId);
            if (subscriber != null) {
                subsId = subscriber.nasPortId();
            }

            print("UserName=%s,CurrentState=%s,DeviceId=%s,MAC=%s,PortNumber=%s,SubscriberId=%s",
                  username, auth.state(), deviceId, mac, portNum, subsId);
        }
    }
}
