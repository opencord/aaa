package org.opencord.aaa;

import org.onosproject.event.ListenerService;

/**
 * Service for interacting with accounting module.
 */

public interface AuthenticationStatisticsService extends
		ListenerService<AuthenticationStatisticsEvent, AuthenticationStatisticsEventListener>{

}
