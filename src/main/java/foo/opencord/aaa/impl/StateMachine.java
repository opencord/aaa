package foo.opencord.aaa.impl;

import com.google.common.collect.Maps;
import foo.opencord.aaa.api.AaaEvent;
import foo.opencord.aaa.api.StateMachineException;
import foo.opencord.aaa.api.StateMachineInvalidTransitionException;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.ConnectPoint;
import org.slf4j.Logger;

import java.util.Map;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * AAA Finite State Machine.
 */
// TODO: consider renaming this to something like AuthSession or AuthSessionInfo
//  "StateMachine" is too generic
//  also, the implementation is less than clear and should probably be rewritten
class StateMachine {
    //INDEX to identify the state in the transition table
    static final int STATE_IDLE = 0;
    static final int STATE_STARTED = 1;
    static final int STATE_PENDING = 2;
    static final int STATE_AUTHORIZED = 3;
    static final int STATE_UNAUTHORIZED = 4;

    //INDEX to identify the transition in the transition table
    static final int TRANSITION_START = 0; // --> started
    static final int TRANSITION_REQUEST_ACCESS = 1;
    static final int TRANSITION_AUTHORIZE_ACCESS = 2;
    static final int TRANSITION_DENY_ACCESS = 3;
    static final int TRANSITION_LOGOFF = 4;

    private static int identifier = -1;

    // TODO: FIX DEPENDENCY -- done, with posting event through AaaManager...
//    private static AccessDeviceService accessDeviceService;
    private final AaaManager aaa;

    private byte challengeId;
    private byte[] challengeState;
    private byte[] username;
    private byte[] requestAuthenticator;

    // Supplicant connectivity info
    private ConnectPoint supplicantConnectpoint;
    private MacAddress supplicantAddress;
    private short vlanId;
    private VlanId ctag;
    private byte priorityCode;

    private String sessionId = null;

    private final Logger log = getLogger(getClass());


    private State[] states = {
            new Idle(), new Started(), new Pending(), new Authorized(), new Unauthorized()
    };


    //State transition table
    /*

                state       IDLE    |   STARTED         |   PENDING         |   AUTHORIZED  |   UNAUTHORIZED
             ////
       input
       ----------------------------------------------------------------------------------------------------

       START                STARTED |   _               |   _               |   STARTED     |   STARTED

       REQUEST_ACCESS       _       |   PENDING         |   _               |   _           |   _

       AUTHORIZE_ACCESS     _       |   _               |   AUTHORIZED      |   _           |   _

       DENY_ACCESS          _       |   -               |   UNAUTHORIZED    |   _           |   _

       LOGOFF               _       |   _               |   _               |   IDLE        |   IDLE
     */

    private int[] idleTransition =
            {STATE_STARTED, STATE_IDLE, STATE_IDLE, STATE_IDLE, STATE_IDLE};
    private int[] startedTransition =
            {STATE_STARTED, STATE_PENDING, STATE_STARTED, STATE_STARTED, STATE_STARTED};
    private int[] pendingTransition =
            {STATE_PENDING, STATE_PENDING, STATE_AUTHORIZED, STATE_UNAUTHORIZED, STATE_PENDING};
    private int[] authorizedTransition =
            {STATE_STARTED, STATE_AUTHORIZED, STATE_AUTHORIZED, STATE_AUTHORIZED, STATE_IDLE};
    private int[] unauthorizedTransition =
            {STATE_STARTED, STATE_UNAUTHORIZED, STATE_UNAUTHORIZED, STATE_UNAUTHORIZED, STATE_IDLE};

    //THE TRANSITION TABLE
    private int[][] transition =
            {idleTransition, startedTransition, pendingTransition, authorizedTransition,
                    unauthorizedTransition};

    private int currentState = STATE_IDLE;

    // Maps of state machines. Each state machine is represented by an
    // unique identifier on the switch: dpid + port number
    private static Map<String, StateMachine> sessionIdMap;
    private static Map<Integer, StateMachine> identifierMap;

    public static void initializeMaps() {
        sessionIdMap = Maps.newConcurrentMap();
        identifierMap = Maps.newConcurrentMap();
        identifier = -1;
    }

    public static void destroyMaps() {
        sessionIdMap = null;
        identifierMap = null;
    }

    // TODO:  FIX DEPENDENCY -- done; now posting events through AaaManager
//    public static void setAccessDeviceService(AccessDeviceService service) {
//        accessDeviceService = service;
//    }

    public static Map<String, StateMachine> sessionIdMap() {
        return sessionIdMap;
    }

    public static StateMachine lookupStateMachineById(byte identifier) {
        return identifierMap.get((int) identifier);
    }

    public static StateMachine lookupStateMachineBySessionId(String sessionId) {
        return sessionIdMap.get(sessionId);
    }

    public static void deleteStateMachineMapping(StateMachine machine) {
        identifierMap.entrySet().removeIf(e -> e.getValue().equals(machine));
    }

    private static boolean matchesMac(MacAddress mac, StateMachine machine) {
        return machine != null && machine.supplicantAddress != null &&
                machine.supplicantAddress.equals(mac);
    }

    /**
     * Deletes authentication state machine records for a given MAC address.
     *
     * @param mac MAC address of the suppliant whose records should be removed
     */
    public static void deleteByMac(MacAddress mac) {
        // Walk the map from session IDs to state machines looking for a MAC match
        for (Map.Entry<String, StateMachine> e : sessionIdMap.entrySet()) {

            // If a MAC match is found then delete the entry from the session ID
            // and identifier map as well as call delete identifier to clean up
            // the identifier bit set.
            StateMachine machine = e.getValue();

            if (matchesMac(mac, machine)) {
                sessionIdMap.remove(machine.sessionId);
                // TODO: review: machine.identifier is static context
                //        but is accessed via instance reference
                if (machine.identifier != -1) {
                    deleteStateMachineMapping(machine);
                }
                break;
            }
        }
    }

    /**
     * State Machine Constructor.
     *
     * @param aaa       reference to AaaManager
     * @param sessionId session ID represented by the switch dpid + port number
     * @param ctag      C-TAG for this subscriber
     */
    public StateMachine(AaaManager aaa, String sessionId, VlanId ctag) {
        log.info("Creating a new state machine for {} C-TAG {}", sessionId, ctag);
        this.aaa = aaa;
        this.sessionId = sessionId;
        this.ctag = ctag;
        sessionIdMap.put(sessionId, this);
    }

    /**
     * Returns the connect point for the supplicant side.
     *
     * @return supplicant connect point
     */
    public ConnectPoint supplicantConnectpoint() {
        return supplicantConnectpoint;
    }

    /**
     * Returns the C-TAG.
     *
     * @return the C-TAG
     */
    public VlanId ctag() {
        return ctag;
    }

    /**
     * Sets the supplicant side connect point.
     *
     * @param supplicantConnectpoint supplicant connect point
     */
    public void setSupplicantConnectpoint(ConnectPoint supplicantConnectpoint) {
        this.supplicantConnectpoint = supplicantConnectpoint;
    }

    /**
     * Returns the MAC address of the supplicant.
     *
     * @return supplicant MAC address
     */
    public MacAddress supplicantAddress() {
        return supplicantAddress;
    }

    /**
     * Sets the supplicant MAC address.
     *
     * @param supplicantAddress new supplicant MAC address
     */
    public void setSupplicantAddress(MacAddress supplicantAddress) {
        this.supplicantAddress = supplicantAddress;
    }

    /**
     * Returns the client's vlan ID.
     *
     * @return client vlan ID
     */
    public short vlanId() {
        return vlanId;
    }

    /**
     * Sets the client's vlan ID.
     *
     * @param vlanId new client vlan ID
     */
    public void setVlanId(short vlanId) {
        this.vlanId = vlanId;
    }

    /**
     * Returns the client's priority code.
     *
     * @return client priority code
     */
    public byte priorityCode() {
        return priorityCode;
    }

    /**
     * Sets the client's priority code.
     *
     * @param priorityCode new client priority code
     */
    public void setPriorityCode(byte priorityCode) {
        this.priorityCode = priorityCode;
    }

    /**
     * Returns the identifier of the client requesting access.
     *
     * @return the client id
     */
    public String sessionId() {
        return this.sessionId;
    }

    /**
     * Sets the challenge identifier and the state issued by RADIUS.
     *
     * @param challengeId    the challenge identifier set into the
     *                       EAP packet from the RADIUS message
     * @param challengeState the challenge state from the RADIUS
     */
    protected void setChallengeInfo(byte challengeId, byte[] challengeState) {
        this.challengeId = challengeId;
        this.challengeState = challengeState;
    }

    /**
     * Sets the challenge identifier issued by RADIUS on the access
     * challenge request.
     *
     * @param challengeId the challenge identifier set into the EAP packet
     *                    from the RADIUS message.
     */
    protected void setChallengeIdentifier(byte challengeId) {
        log.info("Set Challenge Identifier to {}", challengeId);
        this.challengeId = challengeId;
    }

    /**
     * Returns the challenge EAP identifier set by RADIUS.
     *
     * @return the challenge EAP identifier
     */
    protected byte challengeIdentifier() {
        return this.challengeId;
    }


    /**
     * Set the challenge state info issued by RADIUS.
     *
     * @param challengeState the challenge state from RADIUS
     */
    protected void setChallengeState(byte[] challengeState) {
        log.info("Set Challenge State");
        this.challengeState = challengeState;
    }

    /**
     * Returns the challenge state set by the RADIUS.
     *
     * @return the challenge state
     */
    protected byte[] challengeState() {
        return this.challengeState;
    }

    /**
     * Sets the username.
     *
     * @param username the username sent to RADIUS upon access request
     */
    protected void setUsername(byte[] username) {
        this.username = username;
    }

    /**
     * Returns the username.
     *
     * @return the username
     */
    protected byte[] username() {
        return this.username;
    }

    /**
     * Sets the request authenticator.
     *
     * @param authenticator the request authenticator
     */
    protected void setRequestAuthenticator(byte[] authenticator) {
        this.requestAuthenticator = authenticator;
    }

    /**
     * Returns the request authenticator.
     *
     * @return the request authenticator
     */
    protected byte[] requestAuthenticator() {
        return this.requestAuthenticator;
    }


    /**
     * Returns the identifier of the state machine.
     *
     * @return the state machine identifier
     */
    public synchronized byte identifier() {
        identifier = (identifier + 1) % 255;
        identifierMap.put(identifier, this);
        return (byte) identifier;
    }

    /**
     * Moves the state machine to the next state.
     *
     * @param msg message
     */
    private void next(int msg) {
        currentState = transition[currentState][msg];
        log.info("Current State " + currentState);
    }

    /**
     * Client has requested the start action to allow network access.
     *
     * @throws StateMachineException if authentication protocol is violated
     */
    public void start() throws StateMachineException {
        states[currentState].start();
        //move to the next state
        next(TRANSITION_START);
        identifier = this.identifier();
        aaa.postEvent(AaaEvent.Type.AUTH_START, this);
    }

    /**
     * An Identification information has been sent by the supplicant.
     * Move to the next state if possible.
     *
     * @throws StateMachineException if authentication protocol is violated
     */
    public void requestAccess() throws StateMachineException {
        states[currentState].requestAccess();
        //move to the next state
        next(TRANSITION_REQUEST_ACCESS);
        aaa.postEvent(AaaEvent.Type.AUTH_REQUEST_ACCESS, this);
    }

    /**
     * RADIUS has accepted the identification.
     * Move to the next state if possible.
     *
     * @throws StateMachineException if authentication protocol is violated
     */
    public void authorizeAccess() throws StateMachineException {
        states[currentState].radiusAccepted();
        //move to the next state
        next(TRANSITION_AUTHORIZE_ACCESS);
        aaa.postEvent(AaaEvent.Type.ACCESS_AUTHORIZED, this);

        // TODO: FIX DEPENDENCY --- This is now done in OLT, triggered by event
//        if (accessDeviceService != null) {
//            log.info("Provisioning subscriber at {} with C-TAG {}",
//                     supplicantConnectpoint(), ctag);
//            accessDeviceService.provisionSubscriber(supplicantConnectpoint(),
//                                                    ctag);
//        }

        // Clear mapping
        deleteStateMachineMapping(this);
    }

    /**
     * RADIUS has denied the identification.
     * Move to the next state if possible.
     *
     * @throws StateMachineException if authentication protocol is violated
     */
    public void denyAccess() throws StateMachineException {
        states[currentState].radiusDenied();
        //move to the next state
        next(TRANSITION_DENY_ACCESS);

        aaa.postEvent(AaaEvent.Type.ACCESS_DENIED, this);
        // Clear mappings
        deleteStateMachineMapping(this);
    }

    /**
     * Logoff request has been requested.
     * Move to the next state if possible.
     *
     * @throws StateMachineException if authentication protocol is violated
     */
    public void logoff() throws StateMachineException {
        states[currentState].logoff();
        //move to the next state
        next(TRANSITION_LOGOFF);

        aaa.postEvent(AaaEvent.Type.AUTH_LOGOFF, this);
    }

    /**
     * Returns the current state. One of:
     * <ul>
     * <li> STATE_IDLE </li>
     * <li> STATE_STARTED </li>
     * <li> STATE_PENDING </li>
     * <li> STATE_AUTHORIZED </li>
     * <li> STATE_UNAUTHORIZED </li>
     * </ul>
     *
     * @return the current state
     */
    public int state() {
        return currentState;
    }

//    @Override
//    public String toString() {
//        return ("sessionId: " + sessionId) + "\t" +
//                ("identifier: " + this.identifier) + "\t" +
//                ("state: " + currentState);
//    }

    @Override
    public String toString() {
        // TODO: review -- this.identifier: static context
        return "StateMachine{" + "sessionId='" + sessionId + '\'' +
                ", identifier=" + this.identifier +
                ", currentState=" + currentState +
                '}';
    }

    abstract class State {
        private final Logger log = getLogger(getClass());

        private String name = "State";

        public void start() throws StateMachineInvalidTransitionException {
            log.warn("START transition from this state is not allowed.");
        }

        public void requestAccess() throws StateMachineInvalidTransitionException {
            log.warn("REQUEST ACCESS transition from this state is not allowed.");
        }

        public void radiusAccepted() throws StateMachineInvalidTransitionException {
            log.warn("AUTHORIZE ACCESS transition from this state is not allowed.");
        }

        public void radiusDenied() throws StateMachineInvalidTransitionException {
            log.warn("DENY ACCESS transition from this state is not allowed.");
        }

        public void logoff() throws StateMachineInvalidTransitionException {
            log.warn("LOGOFF transition from this state is not allowed.");
        }
    }

    /**
     * Idle state: supplicant is logged of from the network.
     */
    class Idle extends State {
        private final Logger log = getLogger(getClass());
        private String name = "IDLE_STATE";

        public void start() {
            log.info("Moving from IDLE state to STARTED state.");
        }
    }

    /**
     * Started state: supplicant has entered the network and informed
     * the authenticator.
     */
    class Started extends State {
        private final Logger log = getLogger(getClass());
        private String name = "STARTED_STATE";

        public void requestAccess() {
            log.info("Moving from STARTED state to PENDING state.");
        }
    }

    /**
     * Pending state: supplicant has been identified by the authenticator
     * but has not access yet.
     */
    class Pending extends State {
        private final Logger log = getLogger(getClass());
        private String name = "PENDING_STATE";

        public void radiusAccepted() {
            log.info("Moving from PENDING state to AUTHORIZED state.");
        }

        public void radiusDenied() {
            log.info("Moving from PENDING state to UNAUTHORIZED state.");
        }
    }

    /**
     * Authorized state: supplicant port has been accepted, access is granted.
     */
    class Authorized extends State {
        private final Logger log = getLogger(getClass());
        private String name = "AUTHORIZED_STATE";

        public void start() {
            log.info("Moving from AUTHORIZED state to STARTED state.");
        }

        public void logoff() {

            log.info("Moving from AUTHORIZED state to IDLE state.");
        }
    }

    /**
     * Unauthorized state: supplicant port has been rejected, access is denied.
     */
    class Unauthorized extends State {
        private final Logger log = getLogger(getClass());
        private String name = "UNAUTHORIZED_STATE";

        public void start() {
            log.info("Moving from UNAUTHORIZED state to STARTED state.");
        }

        public void logoff() {
            log.info("Moving from UNAUTHORIZED state to IDLE state.");
        }
    }
}
