/*
 * Copyright 2022-2023 Open Networking Foundation (ONF) and the ONF Contributors
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
package org.opencord.aaa.rest;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.onlab.util.Tools;

import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.device.DeviceService;
import org.onosproject.rest.AbstractWebResource;
import org.onosproject.utils.Comparators;

import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.AuthenticationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;

/**
 * AAA app web resource.
 */
@Path("app")
public class AaaWebResource extends AbstractWebResource {
    private final ObjectNode root = mapper().createObjectNode();
    private final ArrayNode node = root.putArray("entries");
    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String UNKNOWN = "UNKNOWN";
    private static final String CONNECT_POINT = "connectPoint";
    private static final String STATE = "authState";
    private static final String LAST_CHANGED = "lastChanged";
    private static final String MAC_ADDRESS = "macAddress";
    private static final String SUBSCRIBER_ID = "subscriberId";
    private static final String USERNAME = "username";

    /**
     * Gets the AAA users.
     *
     * @return 200 OK
     */
    @GET
    @Path("/users")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUsers() {
        return getUsers(null);
    }

    /**
     * Gets the AAA users by device access id.
     *
     * @param deviceId Access device ID.
     *
     * @return 200 OK
     */
    @GET
    @Path("/users/{deviceId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUsersByDeviceId(@PathParam("deviceId") String deviceId) {
        return getUsers(deviceId);
    }

    private Response getUsers(String strDeviceId) {
        AuthenticationService authService = get(AuthenticationService.class);

        try {
            final Comparator<AuthenticationRecord> authenticationRecordComparator =
                    (a1, a2) -> Comparators.CONNECT_POINT_COMPARATOR.
                            compare(a1.supplicantConnectPoint(), a2.supplicantConnectPoint());
            List<AuthenticationRecord> authentications = newArrayList(authService.getAuthenticationRecords());
            authentications.sort(authenticationRecordComparator);

            if (strDeviceId != null && !strDeviceId.isEmpty()) {
                DeviceId deviceId = DeviceId.deviceId(strDeviceId);
                authentications = authentications.stream()
                        .filter(a -> a.supplicantConnectPoint().deviceId().equals(deviceId))
                        .collect(Collectors.toList());
            }

            for (AuthenticationRecord auth : authentications) {
                node.add(encodeAaaUser(auth));
            }
            return ok(mapper().writeValueAsString(root)).build();
        } catch (Exception e) {
            log.error("Error while fetching AAA users info through REST API: {}", e.getMessage());
            return Response.status(INTERNAL_SERVER_ERROR).build();
        }
    }

    private ObjectNode encodeAaaUser(AuthenticationRecord auth) {
        SadisService sadisService = get(SadisService.class);
        DeviceService devService = get(DeviceService.class);

        String username = UNKNOWN;
        if (auth.username() != null) {
            username = new String(auth.username());
        }
        String mac = UNKNOWN;
        if (auth.supplicantAddress() != null) {
            mac = auth.supplicantAddress().toString();
        }

        Port port = devService.getPort(auth.supplicantConnectPoint());
        String nasPortId = UNKNOWN;
        if (port != null) {
            nasPortId = devService.getPort(auth.supplicantConnectPoint()).
                    annotations().value(AnnotationKeys.PORT_NAME);
        }

        String subsId = UNKNOWN;
        SubscriberAndDeviceInformation subscriber = sadisService.getSubscriberInfoService().get(nasPortId);
        if (subscriber != null) {
            subsId = subscriber.nasPortId();
        }

        return mapper().createObjectNode()
                .put(CONNECT_POINT, auth.supplicantConnectPoint().toString())
                .put(STATE, auth.state())
                .put(LAST_CHANGED, Tools.timeAgo(auth.lastChanged()))
                .put(MAC_ADDRESS, mac)
                .put(SUBSCRIBER_ID, subsId)
                .put(USERNAME, username);
    }
}
