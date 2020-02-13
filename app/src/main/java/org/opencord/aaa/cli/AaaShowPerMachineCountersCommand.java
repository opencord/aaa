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

import org.apache.karaf.shell.api.action.lifecycle.Service;

import org.apache.karaf.shell.api.action.Argument;
import org.onosproject.cli.AbstractShellCommand;
import org.apache.karaf.shell.api.action.Command;
import org.opencord.aaa.AaaMachineStatisticsService;
import org.opencord.aaa.AaaSupplicantMachineStats;
import org.opencord.aaa.impl.StateMachine;

/**
 * CLI command for displaying all the AaaMachine Counters.
 */
@Service
@Command(scope = "onos", name = "show-aaa-machine-counters",
description = "Display current value of all aaa statistics counters")
public class AaaShowPerMachineCountersCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId",
              description = "DeviceId of device from which packet is received",
              required = true, multiValued = false)
    private String deviceId;

    @Argument(index = 1, name = "portNumber",
             description = "Port no of device from which packet is received",
             required = true, multiValued = false)
    private String portNumber;

    @Override
    protected void doExecute() {

        String sessionId = deviceId + portNumber;
        AaaMachineStatisticsService aaaMachineStatsManager = get(AaaMachineStatisticsService.class);

        if (StateMachine.getStateMachineSessionIdMap().containsKey(sessionId)) {
            StateMachine aaaSupplicantMachine = StateMachine.getStateMachineSessionIdMap().get(sessionId);
            AaaSupplicantMachineStats aaaSupplicantMachineStats =
                                          aaaMachineStatsManager.getSupplicantStats(aaaSupplicantMachine);
            aaaSupplicantMachineStats.showMachineCounters();
        } else {
            System.out.print("No such Device Found");
        }
    }

}
