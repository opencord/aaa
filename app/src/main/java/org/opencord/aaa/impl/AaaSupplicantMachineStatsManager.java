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

import org.onosproject.event.AbstractListenerManager;
import org.opencord.aaa.AaaMachineStatisticsDelegate;
import org.opencord.aaa.AaaMachineStatisticsEvent;
import org.opencord.aaa.AaaMachineStatisticsEventListener;
import org.opencord.aaa.AaaMachineStatisticsService;
import org.opencord.aaa.AaaSupplicantMachineStats;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
public class AaaSupplicantMachineStatsManager
        extends AbstractListenerManager<AaaMachineStatisticsEvent, AaaMachineStatisticsEventListener>
        implements AaaMachineStatisticsService {

    private final Logger log = getLogger(getClass());

    private AaaMachineStatisticsDelegate machineStatDelegate;

    @Activate
    public void activate() {
        log.info("Activate aaaStatisticsManager");
        machineStatDelegate = new InternalMachineStatDelegate();
        eventDispatcher.addSink(AaaMachineStatisticsEvent.class, listenerRegistry);
    }

    @Deactivate
    public void deactivate() {
        eventDispatcher.removeSink(AaaMachineStatisticsEvent.class);
    }

    @Override
    public AaaSupplicantMachineStats getSupplicantStats(Object obj) {
        StateMachine stateMachine = null;
        AaaSupplicantMachineStats stats = new AaaSupplicantMachineStats();
        try {
            stateMachine = (StateMachine) obj;
        } catch (ClassCastException e) {
            log.debug("casting exception detected for StateMachine.");
            return null;
        }
        log.debug("capturing supplicant machine stat from authentication session");
        stats.setTotalPacketsSent(stateMachine.totalPacketsSent());
        stats.setTotalPacketsRecieved(stateMachine.totalPacketsReceived());
        stats.setTotalFramesSent(stateMachine.totalPacketsSent());
        stats.setTotalFramesReceived(stateMachine.totalPacketsReceived());
        stats.setSrcMacAddress(stateMachine.supplicantAddress() == null ? ""
                : stateMachine.supplicantAddress().toString());
        stats.setSessionName(stateMachine.username() == null ? ""
                : new String(stateMachine.username()));
        stats.setSessionId(stateMachine.sessionId());
        stats.setSessionDuration(System.currentTimeMillis() - stateMachine.sessionStartTime());
        stats.setEapolType(stateMachine.eapolType());
        stats.setSessionTerminateReason(stateMachine.getSessionTerminateReason());

        log.trace("EapolType" + " - " + stats.getEapolType());
        log.trace("SessionDuration" + " - " + stats.getSessionDuration());
        log.trace("SessionId" + " - " + stats.getSessionId());
        log.trace("SessionName" + " - " + stats.getSessionName());
        log.trace("SessionTerminateReason" + " - " + stats.getSessionTerminateReason());
        log.trace("SrcMacAddress" + " - " + stats.getSrcMacAddress());
        log.trace("TotalFramesReceived" + " - " + stats.getTotalFramesReceived());
        log.trace("TotalFramesSent" + " - " + stats.getTotalFramesSent());
        log.trace("TotalOctetRecieved" + " - " + stats.getTotalOctetRecieved());
        log.trace("TotalOctetSent" + " - " + stats.getTotalOctetSent());
        log.trace("TotalPacketsSent" + " - " + stats.getTotalPacketsSent());
        log.trace("TotalOctetRecieved" + " - " + stats.getTotalOctetRecieved());
        return stats;
    }

    @Override
    public void logAaaSupplicantMachineStats(AaaSupplicantMachineStats obj) {
        log.trace("EapolType" + " - " + obj.getEapolType());
        log.trace("SessionDuration" + " - " + obj.getSessionDuration());
        log.trace("SessionId" + " - " + obj.getSessionId());
        log.trace("SessionName" + " - " + obj.getSessionName());
        log.trace("SessionTerminateReason" + " - " + obj.getSessionTerminateReason());
        log.trace("SrcMacAddress" + " - " + obj.getSrcMacAddress());
        log.trace("TotalFramesReceived" + " - " + obj.getTotalFramesReceived());
        log.trace("TotalFramesSent" + " - " + obj.getTotalFramesSent());
        log.trace("TotalOctetRecieved" + " - " + obj.getTotalOctetRecieved());
        log.trace("TotalOctetSent" + " - " + obj.getTotalOctetSent());
        log.trace("TotalPacketsSent" + " - " + obj.getTotalPacketsSent());
        log.trace("TotalOctetRecieved" + " - " + obj.getTotalOctetRecieved());
    }

    @Override
    public AaaMachineStatisticsDelegate getMachineStatsDelegate() {
        return machineStatDelegate;
    }

    private class InternalMachineStatDelegate implements AaaMachineStatisticsDelegate {
        @Override
        public void notify(AaaMachineStatisticsEvent aaaMachineStatisticsEvent) {
            log.debug("Supplicant Statistics event {} for {}", aaaMachineStatisticsEvent.type(),
                    aaaMachineStatisticsEvent.subject());
            post(aaaMachineStatisticsEvent);
        }
    }

}
