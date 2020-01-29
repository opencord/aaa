/*
 * Copyright 2019-present Open Networking Foundation
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

/**
 * Constants for default values of configurable properties.
 */
public final class OsgiPropertyConstants {

    private OsgiPropertyConstants() {
    }

    public static final String STATISTICS_GENERATION_PERIOD = "statisticsGenerationPeriodInSeconds";
    public static final int STATISTICS_GENERATION_PERIOD_DEFAULT = 20;

    public static final String STATISTICS_SYNC_PERIOD = "statisticsSyncPeriodInSeconds";
    public static final int STATISTICS_SYNC_PERIOD_DEFAULT = 5;

    public static final String OPERATIONAL_STATUS_SERVER_EVENT_GENERATION =
            "operationalStatusEventGenerationPeriodInSeconds";
    public static final int OPERATIONAL_STATUS_SERVER_EVENT_GENERATION_DEFAULT = 30;

    public static final String OPERATIONAL_STATUS_SERVER_TIMEOUT = "operationalStatusServerTimeoutInSeconds";
    public static final int OPERATIONAL_STATUS_SERVER_TIMEOUT_DEFAULT = 10;

    public static final String STATUS_SERVER_MODE = "operationalStatusEvaluationMode";
    public static final String STATUS_SERVER_MODE_DEFAULT = "AUTO";
}
