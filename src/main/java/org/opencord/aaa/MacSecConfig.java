/*
 * Copyright 2018-present. * Open Networking Foundation.
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

import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.basics.BasicElementConfig;

/**
 * MACSec config for the AAA app.
 */
public class MacSecConfig extends Config<ApplicationId> {

    private static final String VERSION = "version";
    private static final String CAPABILITY = "capability";
    private static final String CKN = "ckn";
    private static final String CAK = "cak";
    private static final String DEFAULT_NETCONF_DEVICE_ID = "netconfDeviceId";
     private static final String SECY_DRIVER = "secY-driver";

    //MACSec verion
    protected static final String DEFAULT_VERSION = "1";

    //MACSec capability
    protected static final String DEFAULT_CAPABILITY = "0";

    //secure Connectivity Association Key Name
    protected static final String DEFAULT_CKN = "96437a93ccf10d9dfe347846cce52c7d";

    //secure Connectivity Association Key
    protected static final String DEFAULT_CAK = "135bd758b0ee5c11c55ff6ab19fdb199";

    //Netconf Device Default value
    protected static final String DEFAULT_NETCONF_DEVICE = "netconf:192.168.1.2:2022";

    //SecY Driver Interface
    protected static final String DEFAULT_DRIVER_NAME = "default-driver";


    /**
     * Gets the value of a string property, protecting for an empty JSON object.
     *
     * @param name name of the property
     * @param defaultValue default value if none has been specified
     * @return String value if one os found, default value otherwise
     */
    private String getStringProperty(String name, String defaultValue) {
        if (object == null) {
            return defaultValue;
        }
        return get(name, defaultValue);
    }

    /**
     * Version of MACSEC.
     * @return MACSec version or null if not set.
     */
    public String version() {
        return getStringProperty(VERSION, DEFAULT_VERSION);
    }

    /**
     * Sets the MACSec version.
     *
     * @param ver New version; null to clear
     * @return self
     */
    public BasicElementConfig version(String ver) {
        return (BasicElementConfig) setOrClear(VERSION, ver);
    }

    /**
     * Capability of MACSEC.
     *
     * @return MACSec capability or null if not set
     */
    public String capability() {
        return getStringProperty(CAPABILITY, DEFAULT_CAPABILITY);
    }

    /**
     * Sets the MACSec capability.
     *
     * @param cap New capability; null to clear
     * @return self
     */
    public BasicElementConfig capability(String cap) {
        return (BasicElementConfig) setOrClear(CAPABILITY, cap);
    }

    /**
     * CKN.
     *
     * @return ckn or null if not set
     */
    public String ckn() {
        return getStringProperty(CKN, DEFAULT_CKN);
    }

    /**
     * Sets the CKN.
     *
     * @param keyName New CKN; null to clear
     * @return self
     */
    public BasicElementConfig ckn(String keyName) {
        return (BasicElementConfig) setOrClear(CKN, keyName);
    }

    /**
     * CAK.
     *
     * @return cak or null if not set
     */
    public String cak() {
        return getStringProperty(CAK, DEFAULT_CAK);
    }

    /**
     * Sets the CAK.
     *
     * @param key New CAK; null to clear
     * @return self
     */
    public BasicElementConfig cak(String key) {
        return (BasicElementConfig) setOrClear(CAK, key);
    }

    /*
    * Returns default Netconf device Id for SecY interface.
    * @return Device ID
    * */
    public DeviceId netConfDeviceId() {
        return DeviceId.deviceId(getStringProperty(DEFAULT_NETCONF_DEVICE_ID, DEFAULT_NETCONF_DEVICE));
    }
    public String driverName() {
        return getStringProperty(SECY_DRIVER, DEFAULT_DRIVER_NAME);
    }

}

