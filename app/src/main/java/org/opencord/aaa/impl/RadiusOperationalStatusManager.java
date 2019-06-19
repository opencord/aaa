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

import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onosproject.event.AbstractListenerManager;
import org.opencord.aaa.RadiusCommunicator;
import org.opencord.aaa.RadiusOperationalStatusEvent;
import org.opencord.aaa.RadiusOperationalStatusEventDelegate;
import org.opencord.aaa.RadiusOperationalStatusEventListener;
import org.opencord.aaa.RadiusOperationalStatusService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
public class RadiusOperationalStatusManager
        extends AbstractListenerManager<RadiusOperationalStatusEvent, RadiusOperationalStatusEventListener>
        implements RadiusOperationalStatusService {

    private byte[] address;
    private String secret;
    private RadiusCommunicator impl;
    private RadiusOperationalStatusEventDelegate radiusOprStDelegate;

    private long operationalStatusServerTimeoutInMillis;
    private boolean statusServerReqSent;
    private final Logger log = getLogger(getClass());

    private Boolean fakeAccessRequestPacketRecieved = false;
    private long fakeAccessRequestOutTimeInMillis;

    private Boolean serverStatusPacketRecieved = false;
    private long serverStatusOutTimeInMillis;

    private OperationalStatus radiusServerOperationalStatus;
    public static final byte AAA_REQUEST_ID_STATUS_REQUEST = 0;
    public static final byte AAA_REQUEST_ID_FAKE_ACCESS_REQUEST = 1;

    private RadiusOperationalStatusEvaluationMode radiusOperationalStatusEvaluationMode;

    private static final String DUMMY_USER = new String("dummy-user");
    private static final byte RADIUS_CODE_STATUS_REQUEST = (byte) 12;
    private long lastRadiusPacketInTimeInMillis;

    public void setOperationalStatusServerTimeoutInMillis(long operationalStatusServerTimeoutInMillis) {
        this.operationalStatusServerTimeoutInMillis = operationalStatusServerTimeoutInMillis;
    }

    public void setRadiusOperationalStatusEvaluationMode(
        RadiusOperationalStatusEvaluationMode radiusOperationalStatusEvaluationMode) {
        this.radiusOperationalStatusEvaluationMode = radiusOperationalStatusEvaluationMode;
    }

    public RadiusOperationalStatusEventDelegate getRadiusOprStDelegate() {
        return radiusOprStDelegate;
    }

    @Override
    public void setOutTimeInMillis(byte identifier) {
        if (identifier == AAA_REQUEST_ID_STATUS_REQUEST) {
            serverStatusOutTimeInMillis = System.currentTimeMillis();
        } else {
            fakeAccessRequestOutTimeInMillis = System.currentTimeMillis();
        }
    }

    @Override
    public String getRadiusServerOperationalStatus() {
        return radiusServerOperationalStatus.toString();
    }

    @Activate
    public void activate() {
        radiusOprStDelegate = new InternalRadiusOperationalStatusDelegate();
        eventDispatcher.addSink(RadiusOperationalStatusEvent.class, listenerRegistry);
        radiusServerOperationalStatus = OperationalStatus.UNKNOWN;
    }

    public void setStatusServerReqSent(boolean statusServerReqSent) {
        this.statusServerReqSent = statusServerReqSent;
    }

    @Deactivate
    public void deactivate() {
        eventDispatcher.removeSink(RadiusOperationalStatusEvent.class);
    }

    public void initialize(byte[] address, String secret, RadiusCommunicator impl) {
        this.address = address;
        this.secret = secret;
        this.impl = impl;
    }

    public boolean isRadiusResponseForOperationalStatus(byte identifier) {
        if (identifier == AAA_REQUEST_ID_STATUS_REQUEST || identifier == AAA_REQUEST_ID_FAKE_ACCESS_REQUEST) {
            return true;
        } else {
            lastRadiusPacketInTimeInMillis = System.currentTimeMillis();
            return false;
        }
    }

    public void handleRadiusPacketForOperationalStatus(RADIUS radiusPacket) {
        byte radiusPktIdentifier = radiusPacket.getIdentifier();

        if (radiusPktIdentifier == AAA_REQUEST_ID_STATUS_REQUEST) {
            long serverStatusRttInMillis = System.currentTimeMillis() - serverStatusOutTimeInMillis;
            if (serverStatusRttInMillis < operationalStatusServerTimeoutInMillis) {
                serverStatusPacketRecieved = true;
            }
        } else {
            long fakeAccessRttInMillis = System.currentTimeMillis() - fakeAccessRequestOutTimeInMillis;
            if (fakeAccessRttInMillis < operationalStatusServerTimeoutInMillis) {
                fakeAccessRequestPacketRecieved = true;
            }
        }

        switch (radiusPacket.getCode()) {
            case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                synchronized (serverStatusPacketRecieved) {
                    serverStatusPacketRecieved.notify();
                }
                break;
            case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                synchronized (fakeAccessRequestPacketRecieved) {
                    fakeAccessRequestPacketRecieved.notify();
                }
                break;
            default:
                log.warn("Unexpected Radius message for operational status recieved "
                        + "with code: {}", radiusPacket.getCode());
        }
    }

    public void checkServerStatusUsingStatusServerRequest() throws InterruptedException {
        RADIUS radiusStatusServerRequest;
        // identifier = 0 for status server
        radiusStatusServerRequest = new RADIUS(RADIUS_CODE_STATUS_REQUEST, AAA_REQUEST_ID_STATUS_REQUEST);

        radiusStatusServerRequest.setIdentifier(AAA_REQUEST_ID_STATUS_REQUEST);
        radiusStatusServerRequest.setAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME, DUMMY_USER.getBytes());

        radiusStatusServerRequest.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_IP, address);
        radiusStatusServerRequest.addMessageAuthenticator(secret);
        setOutTimeInMillis(radiusStatusServerRequest.getIdentifier());
        impl.sendRadiusPacket(radiusStatusServerRequest, null);
        synchronized (serverStatusPacketRecieved) {
            serverStatusPacketRecieved.wait(operationalStatusServerTimeoutInMillis);
        }
    }

    public void checkServerStatusUsingFakeAccessRequest() throws InterruptedException {
        RADIUS radiusDummyAccessRequest;
        // identifier = 1 for fake accessRequest
        radiusDummyAccessRequest = new RADIUS(RADIUS.RADIUS_CODE_ACCESS_REQUEST, AAA_REQUEST_ID_FAKE_ACCESS_REQUEST);

        radiusDummyAccessRequest.setIdentifier(AAA_REQUEST_ID_FAKE_ACCESS_REQUEST);
        radiusDummyAccessRequest.setAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME, DUMMY_USER.getBytes());

        radiusDummyAccessRequest.setAttribute(RADIUSAttribute.RADIUS_ATTR_NAS_IP, address);
        radiusDummyAccessRequest.addMessageAuthenticator(secret);
        setOutTimeInMillis(radiusDummyAccessRequest.getIdentifier());
        impl.sendRadiusPacket(radiusDummyAccessRequest, null);
        synchronized (fakeAccessRequestPacketRecieved) {
            fakeAccessRequestPacketRecieved.wait(operationalStatusServerTimeoutInMillis);
        }
    }

    public void checkStatusServerForAccessRequestMode() throws InterruptedException {
        long radiusResponseRecievedTimeDifference = System.currentTimeMillis() - lastRadiusPacketInTimeInMillis;
        if (radiusResponseRecievedTimeDifference > operationalStatusServerTimeoutInMillis) {
            checkServerStatusUsingFakeAccessRequest();
            if (statusServerReqSent && fakeAccessRequestPacketRecieved) {
                radiusServerOperationalStatus = OperationalStatus.IN_USE;
            } else if (statusServerReqSent && !fakeAccessRequestPacketRecieved) {
                radiusServerOperationalStatus = OperationalStatus.UNAVAILABLE;
            } else {
                radiusServerOperationalStatus = OperationalStatus.UNKNOWN;
            }
        } else {
            radiusServerOperationalStatus = OperationalStatus.IN_USE;
        }
    }

    public void checkServerOperationalStatus() {

        try {
            if (radiusOperationalStatusEvaluationMode == RadiusOperationalStatusEvaluationMode.STATUS_REQUEST) {
                // determine operational status by statusServerRequest
                checkServerStatusUsingStatusServerRequest();
                if (statusServerReqSent && serverStatusPacketRecieved) {
                    // if req sent and response recieved
                    radiusServerOperationalStatus = OperationalStatus.IN_USE;
                } else if (statusServerReqSent && !serverStatusPacketRecieved) {
                    radiusServerOperationalStatus = OperationalStatus.UNAVAILABLE;
                } else {
                radiusServerOperationalStatus = OperationalStatus.UNKNOWN;
                }
            } else {
                if (radiusOperationalStatusEvaluationMode == RadiusOperationalStatusEvaluationMode.AUTO) {
                    checkServerStatusUsingStatusServerRequest();
                    if (statusServerReqSent && serverStatusPacketRecieved) {
                        radiusServerOperationalStatus = OperationalStatus.IN_USE;
                    } else {
                        checkStatusServerForAccessRequestMode();
                    }
                } else {
                    checkStatusServerForAccessRequestMode();
                }
            }
            fakeAccessRequestPacketRecieved = false;
            serverStatusPacketRecieved = false;
        } catch (Exception e) {
            log.error("Caught exception while checking radius server status::" + e);
        }
    }

    /**
     * Delegate allowing the RadiusOperationalStatus to notify us of events.
     */
     private class InternalRadiusOperationalStatusDelegate implements RadiusOperationalStatusEventDelegate {
        @Override
        public void notify(RadiusOperationalStatusEvent radiusOperationalStatusEvent) {
            log.debug("Radius Operational Status event {} for {}", radiusOperationalStatusEvent.type(),
                radiusOperationalStatusEvent.subject());
            post(radiusOperationalStatusEvent);
        }
     }

}
