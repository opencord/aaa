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

package org.opencord.aaa.impl;

import static org.slf4j.LoggerFactory.getLogger;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.event.AbstractListenerManager;
import org.opencord.aaa.AaaStatistics;
import org.opencord.aaa.AuthenticationStatisticsDelegate;
import org.opencord.aaa.AuthenticationStatisticsEvent;
import org.opencord.aaa.AuthenticationStatisticsEventListener;
import org.opencord.aaa.AuthenticationStatisticsService;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Deactivate;
import org.slf4j.Logger;


@Service
@Component(immediate = true)
public class AaaStatisticsManager
extends AbstractListenerManager<AuthenticationStatisticsEvent, AuthenticationStatisticsEventListener>
implements AuthenticationStatisticsService {

    private AuthenticationStatisticsDelegate statsDelegate;

    @Override
    public AuthenticationStatisticsDelegate getStatsDelegate() {
        return statsDelegate;
    }

    private final Logger log = getLogger(getClass());
    private AaaStatistics aaaStats;
    public Map<Byte, Long> outgoingPacketMap = new HashMap<Byte, Long>();
    private static final int PACKET_COUNT_FOR_AVERAGE_RTT_CALCULATION = 5;

    @Override
    public AaaStatistics getAaaStats() {
        return aaaStats;
    }

    @Activate
    public void activate() {
        log.info("Activate aaaStatisticsManager");
        aaaStats = new AaaStatistics();
        statsDelegate = new InternalAuthenticationDelegateForStatistics();
        eventDispatcher.addSink(AuthenticationStatisticsEvent.class, listenerRegistry);
    }

    @Deactivate
    public void deactivate() {
        eventDispatcher.removeSink(AuthenticationStatisticsEvent.class);
    }

    @Override
    public void handleRoundtripTime(byte inPacketIdentifier) {
        long inTimeInMilis = System.currentTimeMillis();
        if (outgoingPacketMap.containsKey(inPacketIdentifier)) {
            if (aaaStats.getPacketRoundTripTimeListSize() > PACKET_COUNT_FOR_AVERAGE_RTT_CALCULATION) {
                aaaStats.getPacketRoundTripTimeListRemoveFirst();
            }
            aaaStats.getPacketRoundTripTimeListAdd(inTimeInMilis - outgoingPacketMap.get(inPacketIdentifier));
        }
    }

    @Override
    public void resetAllCounters() {
        aaaStats.resetAllCounters();
    }

    @Override
    public void calculatePacketRoundtripTime() {
        if (aaaStats.getPacketRoundTripTimeListSize() > 0) {
            long avg = (long) aaaStats.getPacketRoundTripTimeList().stream().mapToLong(i -> i).average().getAsDouble();
            aaaStats.setRequestRttMilis(new AtomicLong(avg));
        }
    }

    @Override
    public void putOutgoingIdentifierToMap(byte outPacketIdentifier) {
        outgoingPacketMap.put(outPacketIdentifier, System.currentTimeMillis());
    }

    /**
     *Delegate allowing the StateMachine to notify us of events.
     */
    private class InternalAuthenticationDelegateForStatistics implements AuthenticationStatisticsDelegate {
        @Override
        public void notify(AuthenticationStatisticsEvent authenticationStatisticsEvent) {
            log.debug("Authentication Statistics event {} for {}", authenticationStatisticsEvent.type(),
                    authenticationStatisticsEvent.subject());
            post(authenticationStatisticsEvent);
        }
    }
}
