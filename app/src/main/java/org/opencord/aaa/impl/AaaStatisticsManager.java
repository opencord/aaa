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

import com.google.common.base.Strings;
import org.onlab.util.KryoNamespace;
import org.onlab.util.SafeRecurringTask;
import org.onlab.util.Tools;
import org.onosproject.cluster.ClusterService;
import org.onosproject.cluster.LeadershipService;
import org.onosproject.cluster.NodeId;
import org.onosproject.event.AbstractListenerManager;
import org.onosproject.store.cluster.messaging.ClusterCommunicationService;
import org.onosproject.store.cluster.messaging.ClusterMessage;
import org.onosproject.store.cluster.messaging.MessageSubject;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.WallClockTimestamp;
import org.opencord.aaa.AaaStatistics;
import org.opencord.aaa.AaaStatisticsSnapshot;
import org.opencord.aaa.AuthenticationStatisticsEvent;
import org.opencord.aaa.AuthenticationStatisticsEventListener;
import org.opencord.aaa.AuthenticationStatisticsService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.opencord.aaa.impl.OsgiPropertyConstants.STATISTICS_GENERATION_PERIOD;
import static org.opencord.aaa.impl.OsgiPropertyConstants.STATISTICS_GENERATION_PERIOD_DEFAULT;
import static org.opencord.aaa.impl.OsgiPropertyConstants.STATISTICS_SYNC_PERIOD;
import static org.opencord.aaa.impl.OsgiPropertyConstants.STATISTICS_SYNC_PERIOD_DEFAULT;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Manages collection and publishing of statistics for the AAA application.
 */
@Component(immediate = true, property = {
        STATISTICS_GENERATION_PERIOD + ":Integer=" + STATISTICS_GENERATION_PERIOD_DEFAULT,
        STATISTICS_SYNC_PERIOD + ":Integer=" + STATISTICS_SYNC_PERIOD_DEFAULT,
})
public class AaaStatisticsManager
        extends AbstractListenerManager<AuthenticationStatisticsEvent, AuthenticationStatisticsEventListener>
        implements AuthenticationStatisticsService {

    private static final String AAA_STATISTICS_LEADERSHIP = "aaa-statistics";

    private static final MessageSubject RESET_SUBJECT = new MessageSubject("aaa-statistics-reset");

    private int statisticsGenerationPeriodInSeconds = STATISTICS_GENERATION_PERIOD_DEFAULT;
    private int statisticsSyncPeriodInSeconds = STATISTICS_SYNC_PERIOD_DEFAULT;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ClusterService clusterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LeadershipService leadershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ClusterCommunicationService clusterCommunicationService;

    private ScheduledExecutorService executor;

    private ScheduledFuture<?> publisherTask;
    private ScheduledFuture<?> syncTask;

    private EventuallyConsistentMap<NodeId, AaaStatisticsSnapshot> statistics;

    private final Logger log = getLogger(getClass());
    private AaaStatistics aaaStats;
    private Map<Byte, Long> outgoingPacketMap = new HashMap<>();
    private static final int PACKET_COUNT_FOR_AVERAGE_RTT_CALCULATION = 5;

    KryoNamespace serializer = KryoNamespace.newBuilder()
            .register(KryoNamespaces.API)
            .register(AaaStatisticsSnapshot.class)
            .register(ClusterMessage.class)
            .register(MessageSubject.class)
            .build();

    @Override
    public AaaStatistics getAaaStats() {
        return aaaStats;
    }

    @Override
    public AaaStatisticsSnapshot getClusterStatistics() {
        return aggregate();
    }

    @Activate
    public void activate(ComponentContext context) {
        log.info("Activate aaaStatisticsManager");
        modified(context);

        statistics = storageService.<NodeId, AaaStatisticsSnapshot>eventuallyConsistentMapBuilder()
                        .withName("aaa-statistics")
                        .withSerializer(serializer)
                        .withTimestampProvider((k, v) -> new WallClockTimestamp())
                        .build();

        AaaStatisticsSnapshot snapshot = statistics.get(clusterService.getLocalNode().id());
        if (snapshot == null) {
            aaaStats = new AaaStatistics();
        } else {
            aaaStats = AaaStatistics.fromSnapshot(snapshot);
        }

        leadershipService.runForLeadership(AAA_STATISTICS_LEADERSHIP);

        eventDispatcher.addSink(AuthenticationStatisticsEvent.class, listenerRegistry);

        executor = Executors.newScheduledThreadPool(1);

        clusterCommunicationService.addSubscriber(RESET_SUBJECT, Serializer.using(serializer)::decode,
                this::resetLocal, executor);

        syncTask = executor.scheduleAtFixedRate(SafeRecurringTask.wrap(this::syncStats),
                0, statisticsSyncPeriodInSeconds, TimeUnit.SECONDS);

        publisherTask = executor.scheduleAtFixedRate(SafeRecurringTask.wrap(this::publishStats),
                0, statisticsGenerationPeriodInSeconds, TimeUnit.SECONDS);
    }

    @Deactivate
    public void deactivate() {
        clusterCommunicationService.removeSubscriber(RESET_SUBJECT);

        publisherTask.cancel(true);
        syncTask.cancel(true);
        executor.shutdownNow();

        leadershipService.withdraw(AAA_STATISTICS_LEADERSHIP);

        eventDispatcher.removeSink(AuthenticationStatisticsEvent.class);
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<String, Object> properties = context.getProperties();

        String s = Tools.get(properties, "statisticsGenerationPeriodInSeconds");
        statisticsGenerationPeriodInSeconds = Strings.isNullOrEmpty(s) ? STATISTICS_GENERATION_PERIOD_DEFAULT
                : Integer.parseInt(s.trim());

        s = Tools.get(properties, "statisticsSyncPeriodInSeconds");
        statisticsSyncPeriodInSeconds = Strings.isNullOrEmpty(s) ? STATISTICS_SYNC_PERIOD_DEFAULT
                : Integer.parseInt(s.trim());
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
        ClusterMessage reset = new ClusterMessage(clusterService.getLocalNode().id(), RESET_SUBJECT, new byte[]{});
        clusterCommunicationService.broadcastIncludeSelf(reset, RESET_SUBJECT, Serializer.using(serializer)::encode);
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
     * Pushes in-memory stats into the eventually-consistent map for cluster-wide retention.
     */
    private void syncStats() {
        calculatePacketRoundtripTime();

        statistics.put(clusterService.getLocalNode().id(), aaaStats.snapshot());
    }

    /**
     * Aggregates cluster-wise stats from the ec-map.
     *
     * @return aggregate stats
     */
    private AaaStatisticsSnapshot aggregate() {
        return statistics.values().stream()
                .reduce(new AaaStatisticsSnapshot(), AaaStatisticsSnapshot::add);
    }

    /**
     * Publishes cluster-wide stats.
     */
    private void publishStats() {
        // only publish if we are the leader
        if (!Objects.equals(leadershipService.getLeader(AAA_STATISTICS_LEADERSHIP),
                clusterService.getLocalNode().id())) {
            return;
        }

        AaaStatisticsSnapshot clusterStats = aggregate();

        if (log.isDebugEnabled()) {
            log.debug("Notifying stats: {}", clusterStats);
        }

        post(new AuthenticationStatisticsEvent(AuthenticationStatisticsEvent.Type.STATS_UPDATE,
                AaaStatistics.fromSnapshot(clusterStats)));
    }

    private void resetLocal(ClusterMessage m) {
        aaaStats.resetAllCounters();
        syncStats();
    }
}
