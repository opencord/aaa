package org.opencord.aaa;

import java.util.concurrent.atomic.AtomicLong;

//Acts like pojo. Passed as subject to AuthenticationMetrix
//TODO- change naME FROM STATS TO STATISTICS. AuthenticationMetrix TO AaaStatisticsEvent
public class AaaStatistics {

	private AaaStatistics() {
		
	}
	
	private static AaaStatistics aaaStatisticsInstance;
	
	public static AaaStatistics getInstance() {
		if(aaaStatisticsInstance == null) 
			return new AaaStatistics();
		return aaaStatisticsInstance;
	}
	
	//protected static final AtomicLong DEFAULT_COUNTER = 0;
	AtomicLong accept_packets_counter = new AtomicLong();// = DEFAULT_COUNTER; 
	AtomicLong reject_packets_counter = new AtomicLong(); 
	AtomicLong challenege_packets_counter = new AtomicLong(); 
	AtomicLong access_packets_counter = new AtomicLong(); 
	AtomicLong pending_request_counter = new AtomicLong();
	AtomicLong unknown_packet_counter = new AtomicLong();
	AtomicLong invalid_validator_counter = new AtomicLong();
	AtomicLong numberOfDroppedPackets = new AtomicLong();
	AtomicLong malformed_packet_counter = new AtomicLong();
	AtomicLong numberOfPacketFromUnknownServer = new AtomicLong();
	AtomicLong packetRoundtripTimeInMilis = new AtomicLong();
	
	public AtomicLong getMalformed_packet_counter() {
		return malformed_packet_counter;
	}
	public void setMalformed_packet_counter(AtomicLong malformed_packet_counter) {
		this.malformed_packet_counter = malformed_packet_counter;
	}
	public AtomicLong getNumberOfDroppedPackets() {
		return numberOfDroppedPackets;
	}
	public void setNumberOfDroppedPackets(AtomicLong numberOfDroppedPackets) {
		this.numberOfDroppedPackets = numberOfDroppedPackets;
	}
	public AtomicLong getInvalid_validator_counter() {
		return invalid_validator_counter;
	}
	public void setInvalid_validator_counter(AtomicLong invalid_validator_counter) {
		this.invalid_validator_counter = invalid_validator_counter;
	}
	public AtomicLong getAccept_packets_counter() {
		return accept_packets_counter;
	}
	public void setAccept_packets_counter(AtomicLong accept_packets_counter) {
		this.accept_packets_counter = accept_packets_counter;
	}
	public AtomicLong getReject_packets_counter() {
		return reject_packets_counter;
	}
	public void setReject_packets_counter(AtomicLong reject_packets_counter) {
		this.reject_packets_counter = reject_packets_counter;
	}
	public AtomicLong getChallenege_packets_counter() {
		return challenege_packets_counter;
	}
	public void setChallenege_packets_counter(AtomicLong challenege_packets_counter) {
		this.challenege_packets_counter = challenege_packets_counter;
	}
	public AtomicLong getAccess_packets_counter() {
		return access_packets_counter;
	}
	public void setAccess_packets_counter(AtomicLong access_packets_counter) {
		this.access_packets_counter = access_packets_counter;
	}
	public AtomicLong getPending_request_counter() {
		return pending_request_counter;
	}
	public void setPending_request_counter(AtomicLong pending_request_counter) {
		this.pending_request_counter = pending_request_counter;
	}
	public AtomicLong getUnknown_packet_counter() {
		return unknown_packet_counter;
	}
	public void setUnknown_packet_counter(AtomicLong unknown_packet_counter) {
		this.unknown_packet_counter = unknown_packet_counter;
	}
	
}
