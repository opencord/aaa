package org.opencord.aaa;

import java.util.concurrent.atomic.AtomicLong;

import org.onosproject.event.AbstractEvent;
/**
 * Event indicating the Accounting Data of AAA.
 */
public class AuthenticationStatisticsEvent extends
		AbstractEvent<AuthenticationStatisticsEvent.Type, AaaStatistics>{
//	AaaStatistics mgr = AaaStatistics.getInstance();
//	AtomicLong count = mgr.accept_packets_counter;
	/**
     * Accounting data.
     */
	//TODO
	 /**
     * AuthenticationMetrixEvent event type.
     */
    public enum Type {
        /**
         * signifies that the Authentication Metrix Event stats has been updated.
         */
    	STATS_UPDATE
    }
	/**
     * Creates a new Accounting event.
     *
     * @param type event type
     * @param connectPoint port
     */
    public AuthenticationStatisticsEvent(Type type, AaaStatistics stats) {
        super(type, stats);
    }
}
