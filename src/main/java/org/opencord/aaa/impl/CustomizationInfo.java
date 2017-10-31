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
package org.opencord.aaa.impl;

import org.onosproject.net.device.DeviceService;
import org.opencord.sadis.SubscriberAndDeviceInformationService;

/**
 * Bindings to Device service and Subscriber and Device Information service
 * (SADIS), required for RADIUS packet customization.
 */
public class CustomizationInfo {

    private final SubscriberAndDeviceInformationService subsService;
    private final DeviceService devService;

    /**
     * Creates a customization info instance, with bindings for the given
     * service instances.
     *
     * @param subsService subscriber service
     * @param devService  device service
     */
    public CustomizationInfo(SubscriberAndDeviceInformationService subsService,
                             DeviceService devService) {
        this.subsService = subsService;
        this.devService = devService;
    }

    /**
     * Returns the reference to the subscriber service.
     *
     * @return the subscriber service
     */
    public SubscriberAndDeviceInformationService subscriberService() {
        return subsService;
    }

    /**
     * Returns the reference to the device service.
     *
     * @return the device service
     */
    public DeviceService deviceService() {
        return devService;
    }
}
