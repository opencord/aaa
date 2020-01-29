/*
 * Copyright 2018-present Open Networking Foundation
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

package org.opencord.aaa;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * Immutable snapshot of AAA statistics.
 */
public class AaaStatisticsSnapshot {

    private final ImmutableMap<String, Long> counters;

    /**
     * Gets the value of a counter.
     *
     * @param counterName name of the counter
     * @return counter value, or 0 if it doesn't exist
     */
    public long get(String counterName) {
        return counters.getOrDefault(counterName, 0L);
    }

    /**
     * Creates a new empty snapshot with all counters initialized to 0.
     */
    public AaaStatisticsSnapshot() {
        ImmutableMap.Builder<String, Long> builder = ImmutableMap.builder();

        for (String name : AaaStatistics.COUNTER_NAMES) {
            builder.put(name, 0L);
        }

        counters = builder.build();
    }

    /**
     * Creates a new snapshot with the given counter values.
     *
     * @param counters counter values
     */
    public AaaStatisticsSnapshot(ImmutableMap<String, Long> counters) {
        this.counters = counters;
    }

    /**
     * Adds the given snapshot to this snapshot and returns a new snapshot with the aggregate values.
     *
     * @param other other snapshot to add to this one
     * @return new aggregate snapshot
     */
    public AaaStatisticsSnapshot add(AaaStatisticsSnapshot other) {
        ImmutableMap.Builder<String, Long> builder = ImmutableMap.builder();

        counters.forEach((name, value) -> builder.put(name, value + other.counters.get(name)));

        return new AaaStatisticsSnapshot(builder.build());
    }

    public String toString() {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this.getClass());
        counters.forEach(helper::add);
        return helper.toString();
    }

}
