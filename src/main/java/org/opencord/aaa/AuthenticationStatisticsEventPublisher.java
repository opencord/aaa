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

public class AuthenticationStatisticsEventPublisher implements Runnable  {
	
	public static AuthenticationStatisticsEventPublisher instance;
	
	public static AuthenticationStatisticsEventPublisher getInstance() {
		
		if(instance == null) 
			instance = new AuthenticationStatisticsEventPublisher();
		return instance;
	}
	private static AuthenticationStatisticsDelegate delegate;
	AuthenticationStatisticsEvent authenticationStatisticsEvent;
//	ScheduledExecutorService ses = Executors.newScheduledThreadPool(1);
//	private ScheduledFuture<?> scheduledFuture;
	
	static void setDelegate(AuthenticationStatisticsDelegate delegate) {
		AuthenticationStatisticsEventPublisher.delegate = delegate;
	}
//	public ScheduledFuture<?> getScheduledFuture() {
//		return scheduledFuture;
//	}
	/*
	 * public void run() { Runnable task = () -> { delegate.notify(new
	 * AuthenticationStatisticsEvent(
	 * AuthenticationStatisticsEvent.Type.STATS_UPDATE,
	 * AaaStatistics.getInstance())); }; scheduledFuture =
	 * ses.scheduleAtFixedRate(task, 5, 1, TimeUnit.SECONDS); }
	 */
	public void run() {
			   delegate.notify(new AuthenticationStatisticsEvent(
	    			AuthenticationStatisticsEvent.Type.STATS_UPDATE, AaaStatistics.getInstance()));
		}
}

//TODO : create delegate object of InternalAuthenticationDelegateForStatistics
//2. create setter
//3. call setter from aaaStatisticsMgr or aaaMgr.activate()??TODO decide
//4. Inside task, call delegate.notify() instead of post.
