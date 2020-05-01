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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.AuthenticationService;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

/**
 * Removes a AAA state machine.
 */
@Service
@Command(scope = "onos", name = "aaa-reset-all-devices",
         description = "Resets the authentication state machine for a all known entries")
public class AaaResetAllCommand extends AbstractShellCommand {

    @Override
    protected void doExecute() {

        AuthenticationService authService = get(AuthenticationService.class);
        List<AuthenticationRecord> authentications = newArrayList(authService.getAuthenticationRecords());

        for (AuthenticationRecord auth : authentications) {
            authService.removeAuthenticationStateByMac(auth.supplicantAddress());
        }
    }
}
