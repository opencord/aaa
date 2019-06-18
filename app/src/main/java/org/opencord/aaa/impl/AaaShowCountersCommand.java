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
import org.opencord.aaa.AaaStatistics;
import org.opencord.aaa.AuthenticationStatisticsService;

/**
 * Display current value of all aaa statistics counters.
 */
@Command(scope = "onos", name = "show-aaa-counters",
description = "Display current value of all aaa statistics counters")
public class AaaShowCountersCommand extends AbstractShellCommand {
    @Override
    protected void execute() {

        AaaStatistics aaaStats = new AaaStatistics();

        AuthenticationStatisticsService aaaStatisticsManager =
                AbstractShellCommand.get(AuthenticationStatisticsService.class);
        aaaStats = aaaStatisticsManager.getAaaStats();

        System.out.format("%30s %10d\n", "AccessRequestsTx", aaaStats.getAccessRequestsTx());
        System.out.format("%30s %10d\n", "ChallengeResponsesRx", aaaStats.getChallengeResponsesRx());
        System.out.format("%30s %10d\n", "RequestReTx", aaaStats.getRequestReTx());
        System.out.format("%30s %10d\n", "AcceptResponsesRx", aaaStats.getAcceptResponsesRx());
        System.out.format("%30s %10d\n", "RejectResponsesRx", aaaStats.getRejectResponsesRx());
        System.out.format("%30s %10d\n", "PendingRequests", aaaStats.getPendingRequests());
        System.out.format("%30s %10d\n", "DroppedResponsesRx", aaaStats.getDroppedResponsesRx());
        System.out.format("%30s %10d\n", "InvalidValidatorsRx", aaaStats.getInvalidValidatorsRx());
        System.out.format("%30s %10d\n", "MalformedResponsesRx", aaaStats.getMalformedResponsesRx());
        System.out.format("%30s %10d\n", "UnknownServerRx", aaaStats.getUnknownServerRx());
        System.out.format("%30s %10d\n", "UnknownTypeRx", aaaStats.getUnknownTypeRx());
        System.out.format("%30s %10d\n", "RequestRttMillis", aaaStats.getRequestRttMilis());

  }
}
