/*
 * Copyright 2016-2023 Open Networking Foundation (ONF) and the ONF Contributors
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

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.util.Tools;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.device.DeviceService;
import org.onosproject.utils.Comparators;
import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.AuthenticationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

/**
 * Shows the users in the aaa.
 */
@Service
@Command(scope = "onos", name = "aaa-users",
        description = "Shows the aaa users")
public class AaaShowUsersCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId", description = "Access device ID")
    @Completion(DeviceIdCompleter.class)
    private String strDeviceId = null;

    static final String UNKNOWN = "UNKNOWN";

    @Override
    protected void doExecute() {

        final Comparator<AuthenticationRecord> authenticationRecordComparator =
                (a1, a2) -> Comparators.CONNECT_POINT_COMPARATOR.
                        compare(a1.supplicantConnectPoint(), a2.supplicantConnectPoint());

        DeviceService devService = get(DeviceService.class);
        SadisService sadisService = get(SadisService.class);
        AuthenticationService authService = get(AuthenticationService.class);

        List<AuthenticationRecord> authentications = newArrayList(authService.getAuthenticationRecords());

        authentications.sort(authenticationRecordComparator);

        if (strDeviceId != null && !strDeviceId.isEmpty()) {
            DeviceId deviceId = DeviceId.deviceId(strDeviceId);
            authentications = authentications.stream()
                    .filter(a -> a.supplicantConnectPoint().deviceId().equals(deviceId))
                    .collect(Collectors.toList());
        }

        for (AuthenticationRecord auth : authentications) {
            String username = UNKNOWN;
            if (auth.username() != null) {
                username = new String(auth.username());
            }
            String mac = UNKNOWN;
            if (auth.supplicantAddress() != null) {
                mac = auth.supplicantAddress().toString();
            }

            Port port = devService.getPort(auth.supplicantConnectPoint());

            String nasPortId = UNKNOWN;

            if (port != null) {
                nasPortId = devService.getPort(auth.supplicantConnectPoint()).
                        annotations().value(AnnotationKeys.PORT_NAME);
            }

            String subsId = UNKNOWN;
            SubscriberAndDeviceInformation subscriber = sadisService.getSubscriberInfoService().get(nasPortId);
            if (subscriber != null) {
                subsId = subscriber.nasPortId();
            }

            print("%s: %s, last-changed=%s, mac=%s, subid=%s, username=%s",
                    auth.supplicantConnectPoint(), auth.state(), Tools.timeAgo(auth.lastChanged()),
                    mac, subsId, username);
        }
    }
}
