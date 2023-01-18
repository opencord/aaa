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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.opencord.aaa.AaaStatistics;
import org.opencord.aaa.AaaStatisticsSnapshot;
import org.opencord.aaa.AuthenticationStatisticsService;

/**
 * Display current value of all aaa statistics counters.
 */
@Service
@Command(scope = "onos", name = "aaa-statistics",
description = "Display current value of all aaa statistics counters")
public class AaaShowCountersCommand extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        AuthenticationStatisticsService aaaStatisticsManager =
                AbstractShellCommand.get(AuthenticationStatisticsService.class);

        AaaStatisticsSnapshot stats = aaaStatisticsManager.getClusterStatistics();

        print("-------------------------- Expected transitions ----------------------------");
        for (String name : AaaStatistics.EAPOL_SM_NAMES) {
            print("%30s %10d", name, stats.get(name));
        }

        print("-------------------------------- Other stats ----------------------------------");
        for (String name : AaaStatistics.EAPOL_STATS_NAMES) {
            print("%30s %10d", name, stats.get(name));
        }

    }
}