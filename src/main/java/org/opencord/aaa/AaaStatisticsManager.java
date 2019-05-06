package org.opencord.aaa;

import static org.slf4j.LoggerFactory.getLogger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.onlab.packet.RADIUS;
import org.onosproject.event.AbstractListenerManager;
import org.slf4j.Logger;

public class AaaStatisticsManager 
	extends AbstractListenerManager<AuthenticationStatisticsEvent, AuthenticationStatisticsEventListener>
		implements AuthenticationStatisticsService {
	
	private AaaStatisticsManager() {}
	
	private final Logger log = getLogger(getClass());
	
	ArrayList<Long> packetTimeList = new ArrayList<Long>();
	static Map<Byte, Long> outgoingPacketMap = new HashMap<Byte, Long>();
	
	/* Moved to AaaStats.java
	 * 
	 * protected static final int DEFAULT_COUNTER = 0; protected int
	 * accept_packets_counter = DEFAULT_COUNTER; protected int
	 * reject_packets_counter = DEFAULT_COUNTER; protected int
	 * challenege_packets_counter = DEFAULT_COUNTER; protected int
	 * access_packets_counter = DEFAULT_COUNTER; protected int
	 * pending_request_counter = DEFAULT_COUNTER; protected int
	 * unknown_packet_counter = DEFAULT_COUNTER;
	 */
	
	
	//TODO - decide where to use delegate and call delegate.notify for statisticsEvent
	
	
	private StateMachineDelegateForStatistics delegate = new InternalStateMachineDelegate();
	
	private static AaaStatisticsManager instance;
	AaaManager aaaManager;
//	AaaConfig aaaConfig;
	
	public static AaaStatisticsManager getInstance() {
		if(instance == null) 
			return new AaaStatisticsManager();
		return instance;
	}
	
	/*
	 * protected void init(AaaManager aaaManager) { this.aaaManager = aaaManager; //
	 * this.aaaConfig = aaaManager.newCfg; }
	 */
	
	AaaStatistics aaaStatisticsInstance = AaaStatistics.getInstance();
	
	
	public void increaseAcceptPacketsCounter() {
		log.info("Inside increaseAcceptPacketsCounter()");
		aaaStatisticsInstance.accept_packets_counter.incrementAndGet();
		log.info("aaaStatisticsInstance.accept_packets_counter::"+aaaStatisticsInstance.accept_packets_counter);
	}
	
	public void increaseRejectPacketsCounter() {
		log.info("Inside increaseRejectPacketsCounter()");
		aaaStatisticsInstance.reject_packets_counter.incrementAndGet();
		log.info("aaaStatisticsInstance.reject_packets_counter::"+aaaStatisticsInstance.reject_packets_counter);
	}
	
	public void increaseChallengePacketsCounter() {
		log.info("Inside increaseChallengePacketsCounter()");
		aaaStatisticsInstance.challenege_packets_counter.incrementAndGet();
		log.info("aaaStatisticsInstance.challenege_packets_counter::"+aaaStatisticsInstance.challenege_packets_counter);
	}
	
	public void increaseAccessRequestPacketsCounter() {
		log.info("Inside increaseAccessRequestPacketsCounter()");
		aaaStatisticsInstance.access_packets_counter.incrementAndGet();
		log.info("aaaStatisticsInstance.access_packets_counter::"+aaaStatisticsInstance.access_packets_counter);
	}
	
	public void increaseOrDecreasePendingCounter(boolean isIncrement) {
		log.info("Inside increaseOrDecreasePendingCounter()");
		if(isIncrement) {
			log.info("increasing PendingCounter---");
			aaaStatisticsInstance.pending_request_counter.incrementAndGet();
		}else {
			log.info("decreasing PendingCounter---");
			aaaStatisticsInstance.pending_request_counter.decrementAndGet();
		}
		log.info("aaaStatisticsInstance.pending_request_counter::::"+aaaStatisticsInstance.pending_request_counter);
	}
	
	public void increaseUnknownPacketsCounter() {
		log.info("Inside increaseUnknownPacketsCounter()");
		aaaStatisticsInstance.unknown_packet_counter.incrementAndGet();
		log.info("aaaStatisticsInstance.unknown_packet_counter::::"+aaaStatisticsInstance.unknown_packet_counter);
	}
	
	public void increaseMalformedPacketCounter() {
		log.info("Inside increaseMalformedPacketCounter()");
		aaaStatisticsInstance.malformed_packet_counter.incrementAndGet();
		log.info("aaaStatisticsInstance.malformed_packet_counter:::"+aaaStatisticsInstance.malformed_packet_counter);
	}
	
	/*
	 * public void checkForInvalidValidator(RADIUS radiusPacket) {//TODO: check for
	 * this logic existence boolean isValid =
	 * radiusPacket.checkMessageAuthenticator(aaaManager.radiusSecret); if(!isValid)
	 * { increaseInvalidValidatorCounter(); }
	 * 
	 * }
	 */
	
	public void increaseInvalidValidatorCounter() {
		log.info("Inside increaseInvalidValidatorCounter()");
		aaaStatisticsInstance.invalid_validator_counter.incrementAndGet();
		log.info("aaaStatisticsInstance.invalid_validator_counter:::"+aaaStatisticsInstance.invalid_validator_counter);
	}
	
	/*
	 * public void checkForPacketFromUnknownServer(String hostAddress) {
	 * if(!hostAddress.equals(aaaManager.newCfg.radiusIp().getHostAddress())) {
	 * aaaStatisticsInstance.numberOfPacketFromUnknownServer.incrementAndGet(); } }
	 */
	
	public void incrementNumberOfPacketFromUnknownServer() {
		log.info("Inside incrementNumberOfPacketFromUnknownServer()");
		aaaStatisticsInstance.numberOfPacketFromUnknownServer.incrementAndGet();
		log.info("aaaStatisticsInstance.numberOfPacketFromUnknownServer::"+aaaStatisticsInstance.numberOfPacketFromUnknownServer);
	}
	
	public void countNumberOfDroppedPackets() {
		log.info("Inside countNumberOfDroppedPackets()");
		AtomicLong numberOfDroppedPackets = new AtomicLong();
		numberOfDroppedPackets = aaaStatisticsInstance.invalid_validator_counter;
		numberOfDroppedPackets.addAndGet(aaaStatisticsInstance.unknown_packet_counter.get());
		numberOfDroppedPackets.addAndGet(aaaStatisticsInstance.malformed_packet_counter.get());
		//TODO : add Number of packets not satisfying any logic into the code
		aaaStatisticsInstance.numberOfDroppedPackets = numberOfDroppedPackets;
		log.info("numberOfDroppedPackets::"+numberOfDroppedPackets);
	}
	
	public void handleRoundtripTime(long inTimeInMilis, byte inPacketIdentifier) {
		log.info("Inside handleRoundtripTime()");
		if(outgoingPacketMap.containsKey(inPacketIdentifier)) {//add roundtrip for this packet in list
			packetTimeList.add(inTimeInMilis-outgoingPacketMap.get(inPacketIdentifier));
		}//ignore if identifier is different
		calculatePacketRoundtripTime();
	}
	
	/*
	 * public void handleRoundtripTimeForSocket(long inTimeInMilis, byte
	 * inPacketIdentifier) { if(outgoingPacketMap.containsKey(inPacketIdentifier))
	 * {//add roundtrip for this packet in list
	 * packetTimeList.add(inTimeInMilis-outgoingPacketMap.get(inPacketIdentifier));
	 * } calculatePacketRoundtripTime(); }
	 * 
	 * public void handleRoundtripTimeForPort(long inTimeInMilis, byte
	 * inPacketIdentifier) {
	 * 
	 * }
	 */
	
	public void calculatePacketRoundtripTime() {
		log.info("Inside calculatePacketRoundtripTime()");
		//calculate the average round trip time for last 5 packets
		long sum = 0;
		long avg = 0;
		if(packetTimeList.size()<=5) {
			for(int i=0;i<packetTimeList.size();i++) {
				sum=sum+packetTimeList.get(i);
			}
			avg = sum/packetTimeList.size();
			aaaStatisticsInstance.packetRoundtripTimeInMilis=new AtomicLong(avg);
		}
		else {
			int dividend=packetTimeList.size()-1;
			for(int i=packetTimeList.size()-1;i>=packetTimeList.size()-5;i--) {
				sum = sum + packetTimeList.get(i);
				dividend--;
			}
			avg = sum/dividend;
			aaaStatisticsInstance.packetRoundtripTimeInMilis=new AtomicLong(avg);
		}
		log.info("aaaStatisticsInstance.packetRoundtripTimeInMilis::"+aaaStatisticsInstance.packetRoundtripTimeInMilis);
	}
	//TODO: publish counters to event. trigger event whenever any var value changes
	//reset counter on restart(This should be taken care)
	//TODO : check if onos provides scheduler.
	
	/**
     * Delegate allowing the StateMachine to notify us of events.
     */
    private class InternalStateMachineDelegate implements StateMachineDelegateForStatistics {

        @Override
        public void notify(AuthenticationStatisticsEvent authenticationStatisticsEvent) {
            log.info("Auth event {} for {}",
            		authenticationStatisticsEvent.type(), authenticationStatisticsEvent.subject());
            post(authenticationStatisticsEvent);
        }
    }

	
}
