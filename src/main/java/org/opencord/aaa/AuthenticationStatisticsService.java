package org.opencord.aaa;

import org.onosproject.event.ListenerService;

/**
 * Service for interacting with accounting module.
 */

public interface AuthenticationStatisticsService extends
		ListenerService<AuthenticationStatisticsEvent, AuthenticationStatisticsEventListener>{

	public void increaseInvalidValidatorCounter();

	public void incrementNumberOfPacketFromUnknownServer();

	public void increaseOrDecreasePendingCounter(boolean b);

	public void increaseAccessRequestPacketsCounter();

	public void increaseChallengePacketsCounter();

	public void increaseAcceptPacketsCounter();

	public void increaseRejectPacketsCounter();

	public void countNumberOfDroppedPackets();

	public void increaseUnknownPacketsCounter();

	public void handleRoundtripTime(long currentTimeMillis, byte identifier);

	public void increaseMalformedPacketCounter();

}
