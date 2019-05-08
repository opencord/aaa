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
			aaaStatisticsInstance = new AaaStatistics();
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
	
	public long getNumberOfPacketFromUnknownServer() {
		return numberOfPacketFromUnknownServer.get();
	}
	public long getPacketRoundtripTimeInMilis() {
		return packetRoundtripTimeInMilis.get();
	}
	public void setNumberOfPacketFromUnknownServer(AtomicLong numberOfPacketFromUnknownServer) {
		this.numberOfPacketFromUnknownServer = numberOfPacketFromUnknownServer;
	}
	public void setPacketRoundtripTimeInMilis(AtomicLong packetRoundtripTimeInMilis) {
		this.packetRoundtripTimeInMilis = packetRoundtripTimeInMilis;
	}
	public long getMalformed_packet_counter() {
		return malformed_packet_counter.get();
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
	public long getInvalid_validator_counter() {
		return invalid_validator_counter.get();
	}
	public void setInvalid_validator_counter(AtomicLong invalid_validator_counter) {
		this.invalid_validator_counter = invalid_validator_counter;
	}
	public long getAccept_packets_counter() {
		return accept_packets_counter.get();
	}
	public void setAccept_packets_counter(AtomicLong accept_packets_counter) {
		this.accept_packets_counter = accept_packets_counter;
	}
	public long getReject_packets_counter() {
		return reject_packets_counter.get();
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
	public long getAccess_packets_counter() {
		return access_packets_counter.get();
	}
	public void setAccess_packets_counter(AtomicLong access_packets_counter) {
		this.access_packets_counter = access_packets_counter;
	}
	public long getPending_request_counter() {
		return pending_request_counter.get();
	}
	public void setPending_request_counter(AtomicLong pending_request_counter) {
		this.pending_request_counter = pending_request_counter;
	}
	public long getUnknown_packet_counter() {
		return unknown_packet_counter.get();
	}
	public void setUnknown_packet_counter(AtomicLong unknown_packet_counter) {
		this.unknown_packet_counter = unknown_packet_counter;
	}
	
}
