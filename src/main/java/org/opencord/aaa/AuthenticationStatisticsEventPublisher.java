/*
 * Copyright 2017-present Open Networking Foundation
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

import static org.slf4j.LoggerFactory.getLogger;

import org.slf4j.Logger;

public class AuthenticationStatisticsEventPublisher implements Runnable  {
	
	// for verbose output
    private final Logger log = getLogger(getClass());
	
	public static AuthenticationStatisticsEventPublisher instance;
	
	public static AuthenticationStatisticsEventPublisher getInstance() {
		
		if(instance == null) 
			instance = new AuthenticationStatisticsEventPublisher();
		return instance;
	}
	private static AuthenticationStatisticsDelegate delegate;
	AuthenticationStatisticsEvent authenticationStatisticsEvent;

	static void setDelegate(AuthenticationStatisticsDelegate delegate) {
		AuthenticationStatisticsEventPublisher.delegate = delegate;
	}

	public void run() {
		AaaStatistics instance = AaaStatistics.getInstance();
		log.info("Inside AuthenticationPublisher---Calling notify----stats getting published now------");
		log.info("Event value published---Accept_packets_counter::::"+instance.getAccept_packets_counter());
		log.info("Event value published---Reject_packets_counter::::"+instance.getReject_packets_counter());
		log.info("Event value published---Challenge_packets_counter::::"+instance.getChallenege_packets_counter());
		log.info("Event value published---ACCESS_PACKET_COUNTER::::"+instance.getAccess_packets_counter());
		log.info("Event value published---INVALID_VALIDATOR_COUNTER::::"+instance.getInvalid_validator_counter());
		log.info("Event value published---UNKNOWN_TYPE_COUNTER::::"+instance.getUnknown_packet_counter());
		log.info("Event value published---PENDING_REQUEST_COUNTER::::"+instance.getPending_request_counter());
		log.info("Event value published---NUMBER_OF_DROPPED_PACKETS::::"+instance.getNumberOfDroppedPackets());
		log.info("Event value published---MALFORMED_PACKET_COUNTERS::::"+instance.getMalformed_packet_counter());
		log.info("Event value published---NUMBER_OF_PACKET_FROM_UNKNOWN_SERVER::::"+instance.getNumberOfPacketFromUnknownServer());
		log.info("Event value published---PACKET_ROUND_TRIP_TIME_IN_MILLS::::"+instance.getPacketRoundtripTimeInMilis());
			   delegate.notify(new AuthenticationStatisticsEvent(
	    			AuthenticationStatisticsEvent.Type.STATS_UPDATE, instance));
			   
		}
}

