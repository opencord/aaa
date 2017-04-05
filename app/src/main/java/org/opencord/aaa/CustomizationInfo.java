/*
 * Copyright
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

import org.onlab.packet.MacAddress;

import org.onosproject.net.device.DeviceService;

import java.util.Map;

/**
 * Info required to do customization to packets.
 */
public class CustomizationInfo {

    private Map<MacAddress, Info> info;
    private DeviceService devService;

    public CustomizationInfo(Map<MacAddress, Info> info, DeviceService devService) {
        this.info = info;
        this.devService = devService;
    }

    public Map<MacAddress, Info> info() {
        return info;
    }
}
