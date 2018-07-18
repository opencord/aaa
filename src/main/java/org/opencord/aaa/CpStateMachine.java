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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * CP state machine implementation as per IEEE 802.1X-2010, Clause 12.4 .
 */
public class CpStateMachine {
    private final Logger logger = getLogger(getClass());
    /**
     * State, Transition details. IEEE802.1X-2010. Figure 12-2.
     */
    private boolean portValid, newSak;
    private boolean lrx, ltx, orx, otx;
    private boolean chgdServer, controlledPortEnabled, chgdCipher;
    private boolean usingReceiveSAs;
    private boolean serverTransmitting, usingTransmitSA;
    private boolean electedSelf, allReceiving, newInfo;
    private byte[] lki, oki, distributedKI;
    private byte distributedAN, lan, oan;
    private long transmitWhen, transmitDelay, retireWhen, retireDelay;
    /**
     * MACSec management & control.
     */
    private boolean protectFrames;
    private boolean replayProtect;
    private int replayProtectWindow;

    enum MacSecValidate {
        Disabled, Checked, Strict
    }

    private MacSecValidate validateFrames;
    private final int defaultReplayProtectWindow = 10;
    private final int defaultTransmitDelay = 6000;
    private final int defaultSakRetireTime = 5000;
    /**
     * Ciphersuit management & control.
     */
    private MacSecCipherSuit cipherSuit;

    enum ConnectType { PENDING, UNAUTHENTICATED, AUTHENTICATED, SECURE }

    ConnectType connectType;

    /**
     * Defines StateMachine. Ref. IEEE 802.1X-2010 Clause 12.4 ,figure:12-2 .
     */
    enum StateIndex {
        BEGIN, INIT, CHANGE, ALLOWED, AUTHENTICATED, SECURED,
        RECEIVE, RECEIVING, READY, TRANSMIT, TRANSMITTING, ABANDON, RETIRE, NONE
    }


    Map<StateIndex, State> states = new HashMap<StateIndex, State>() {{
        put(StateIndex.BEGIN, new Begin(logger));
        put(StateIndex.INIT, new Init(logger));
        put(StateIndex.CHANGE, new Change(logger));
        put(StateIndex.ALLOWED, new Allowed(logger));
        put(StateIndex.AUTHENTICATED, new Authenticated(logger));
        put(StateIndex.SECURED, new Secured(logger));
        put(StateIndex.RECEIVE, new Receive(logger));
        put(StateIndex.RECEIVING, new Receiving(logger));
        put(StateIndex.READY, new Ready(logger));
        put(StateIndex.TRANSMIT, new Transmit(logger));
        put(StateIndex.TRANSMITTING, new Transmitting(logger));
        put(StateIndex.ABANDON, new Abandon(logger));
        put(StateIndex.RETIRE, new Retire(logger));
        put(StateIndex.NONE, new Begin(logger));
    }};
    StateIndex currentStateIndex;

    protected boolean changedConnect() {
        return (connectType != ConnectType.SECURE) || chgdServer || chgdCipher;
    }

    abstract class State {
        StateIndex index;
        Logger logger;

        State(StateIndex index, Logger logger) {
            this.index = index;
            this.logger = logger;
        }

        /**
         * State Machine state based action function.
         */
        public void enter() {
            logger.trace("Entering state : {} ", index.name());
        }

        /**
         * State Machine state stepping function.
         * Assumes that before calling "step" atleast once "enter" of the state should be called.
         *
         * @return StateIndex.NONE
         */
        public StateIndex step() {
            logger.trace("Stepping from state : {}", index.name());
            return StateIndex.NONE;
        }
    }

    /**
     * State Machine in Begin state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StateIndex
     */
    class Begin extends State {
        Begin(Logger logger) {
            super(StateIndex.BEGIN, logger);
        }

        @Override
        public void enter() {
            super.enter();
        }


        @Override
        public StateIndex step() {
            super.step();
            return StateIndex.INIT;
        }
    }


    /**
     * State Machine in Init state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Init extends State {
        Init(Logger logger) {
            super(StateIndex.INIT, logger);
        }

        @Override
        public void enter() {
            controlledPortEnabled = false;
            /* TODO : */
            // secY.enablePort(portName, controlledPortEnabled);
            portValid = false;
            lki = null;
            oki = null;
            lrx = false;
            ltx = false;
            orx = false;
            otx = false;
        }

        @Override
        public StateIndex step() {
            return StateIndex.CHANGE;
        }
    }

    /**
     * State Machine in Change state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Change extends State {
        Change(Logger logger) {
            super(StateIndex.CHANGE, logger);
        }

        @Override
        public void enter() {
            super.enter();
            portValid = false;
            controlledPortEnabled = false;
            secY.enablePort(portName, controlledPortEnabled);
            /**
             *  TODO : Delete SAs associated with keys.
             */
            if (lki != null) {
                participant.deleteSAs(lki);
            }
            if (oki != null) {
                participant.deleteSAs(oki);
            }
        }

        @Override
        public StateIndex step() {
            super.step();
            StateIndex index = StateIndex.CHANGE;
            switch (connectType) {
                case UNAUTHENTICATED:
                    index = StateIndex.ALLOWED;
                    break;
                case AUTHENTICATED:
                    index = StateIndex.AUTHENTICATED;
                    break;
                case SECURE:
                    index = StateIndex.SECURED;
                default:
                    break;
            }
            return index;
        }
    }

    /**
     * State Machine in Allowed state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Allowed extends State {
        Allowed(Logger logger) {
            super(StateIndex.ALLOWED, logger);
        }

        @Override
        public void enter() {
            super.enter();
            protectFrames = false;
            replayProtect = false;
            validateFrames = MacSecValidate.Checked;
            portValid = false;
            controlledPortEnabled = true;
            /**
             * Update SecY
             */
            secY.enablePort(portName, controlledPortEnabled);
            secY.protectFrames(portName, protectFrames);
            secY.validateFrames(portName, validateFrames);
            secY.replayProtect(portName, replayProtect, replayProtectWindow);
        }

        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.ALLOWED;
            if (connectType != ConnectType.UNAUTHENTICATED) {
                nextState = StateIndex.CHANGE;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Authenticated state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Authenticated extends State {
        Authenticated(Logger logger) {
            super(StateIndex.AUTHENTICATED, logger);
        }

        @Override
        public void enter() {
            super.enter();
            protectFrames = false;
            replayProtect = false;
            validateFrames = MacSecValidate.Checked;
            portValid = false;
            controlledPortEnabled = true;
            /**
             * Update SecY
             */
            secY.enablePort(portName, controlledPortEnabled);
            secY.protectFrames(portName, protectFrames);
            secY.validateFrames(portName, validateFrames);
            secY.replayProtect(portName, replayProtect, replayProtectWindow);
        }

        @Override
        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.AUTHENTICATED;
            if (connectType != ConnectType.AUTHENTICATED) {
                nextState = StateIndex.CHANGE;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Secured state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Secured extends State {
        Secured(Logger logger) {
            super(StateIndex.SECURED, logger);
        }

        @Override
        public void enter() {
            super.enter();
            chgdServer = false;
            /**
             *  TODO : Load from per port configuration.
             */
            protectFrames = true;
            validateFrames = MacSecValidate.Strict;
            replayProtect = true;
            replayProtectWindow = defaultReplayProtectWindow;
            portValid = true;
            /**
             *  Update SecY.
             */
            secY.setCurrentCipherSuit(portName, cipherSuit.id());
            /**
             * TODO: Update confidentiality offset from ciphersuit.
             */
            secY.protectFrames(portName, protectFrames);
            secY.validateFrames(portName, validateFrames);
            secY.replayProtect(portName, replayProtect, replayProtectWindow);
        }

        @Override
        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.SECURED;
            if (changedConnect()) {
                nextState = StateIndex.CHANGE;
            } else if (newSak) {
                nextState = StateIndex.RECEIVE;
            }
            return nextState;
        }
    }

    /**
     * Receive state slighlty differ from IEEE 802.1X 2010 Figure 12-2.
     * Refer : wpa_supplicant-2.6/src/pae/ieee802_1x_cp.c
     */
    class Receive extends State {
        Receive(Logger logger) {
            super(StateIndex.RECEIVE, logger);
        }

        @Override
        public void enter() {
            super.enter();
            oki = lki;
            orx = lrx;
            otx = ltx;
            oan = lan;
            lki = distributedKI;
            lan = distributedAN;
            newSak = false;
            /**
             * Update SecY
             */
            participant.setOldSAAttributes(oki, oan, orx, otx);
            participant.setLatestSAAttributes(lki, lan, ltx, lrx);
            participant.createSAs(lki);
            participant.enableReceiveSAs(lki);
        }

        @Override
        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.RECEIVE;
            if (usingReceiveSAs) {
                nextState = StateIndex.RECEIVING;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Receiving state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Receiving extends State {
        Receiving(Logger logger) {
            super(StateIndex.RECEIVING, logger);
        }

        @Override
        public void enter() {
            super.enter();
            lrx = true;
            participant.setLatestSAAttributes(lki, lan, ltx, lrx);
            transmitWhen = transmitDelay;
            /**
             * TODO : CP Timout reset.
             */
            usingReceiveSAs = false;
            serverTransmitting = false;
        }

        @Override
        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.RECEIVING;
            if (newSak || changedConnect()) {
                nextState = StateIndex.ABANDON;
            }
            if (!electedSelf) {
                nextState = StateIndex.READY;
            }
            /**
             *  IEEE 802.1X-2010 Figure 12-2 deviation. !controlPortEnabled removed from check.
             */
            if (electedSelf && (allReceiving || (transmitWhen == 0))) {
                nextState = StateIndex.TRANSMIT;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Ready state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Ready extends State {
        Ready(Logger logger) {
            super(StateIndex.READY, logger);
        }

        @Override
        public void enter() {
            super.enter();
            newInfo = true;
            // TODO : participant.enableNewInfo();
        }

        @Override
        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.READY;
            if (newSak || changedConnect()) {
                nextState = StateIndex.ABANDON;
            }
            if (serverTransmitting) {
                nextState = StateIndex.TRANSMIT;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Transmit state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Transmit extends State {
        Transmit(Logger logger) {
            super(StateIndex.TRANSMIT, logger);
        }

        @Override
        public void enter() {
            super.enter();
            controlledPortEnabled = true;
            secY.enablePort(portName, controlledPortEnabled);
            ltx = true;
            participant.setLatestSAAttributes(lki, lan, ltx, lrx);
            participant.enableTransmitSA(lki);
            allReceiving = false;
            serverTransmitting = false;
        }

        @Override
        public StateIndex step() {
            super.enter();
            StateIndex nextState = StateIndex.TRANSMIT;
            if (usingTransmitSA) {
                nextState = StateIndex.TRANSMITTING;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Transmitting state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Transmitting extends State {
        Transmitting(Logger logger) {
            super(StateIndex.TRANSMITTING, logger);
        }

        @Override
        public void enter() {
            super.enter();
            retireWhen = orx ? retireDelay : 0;
            otx = false;
            participant.setOldSAAttributes(oki, oan, otx, orx);
            newInfo = true;
            // TODO: participant.enableNewInfo();
            /* TODO : Reset retire when timeout. */
            usingTransmitSA = false;
        }

        @Override
        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.TRANSMITTING;
            if ((retireWhen == 0) || changedConnect()) {
                nextState = StateIndex.RETIRE;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Abandon state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Abandon extends State {
        Abandon(Logger logger) {
            super(StateIndex.ABANDON, logger);
        }

        @Override
        public void enter() {
            super.enter();
            lrx = false;
            participant.setLatestSAAttributes(lki, lan, ltx, lrx);
            participant.deleteSAs(lki);
            lki = null;
            participant.setLatestSAAttributes(lki, lan, ltx, lrx);
            newSak = false;
        }

        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.ABANDON;
            if (changedConnect()) {
                nextState = StateIndex.RETIRE;
            } else if (newSak) {
                nextState = StateIndex.RECEIVE;
            }
            return nextState;
        }
    }

    /**
     * State Machine in Retire state.
     * Assumes that before calling "step" atleast once "enter" of the state should be called.
     *
     * @return StepIndex
     */
    class Retire extends State {
        Retire(Logger logger) {
            super(StateIndex.RETIRE, logger);
        }

        @Override
        public void enter() {
            super.enter();
            /**
             * IEEE 802.1X-2010 Figure 12-2 deviation. Only clearing old keys.
             */
            oki = null;
            orx = false;
            otx = false;
            participant.setOldSAAttributes(oki, oan, otx, orx);
            /* TODO : deleteSA(oki) ? */
        }

        public StateIndex step() {
            super.step();
            StateIndex nextState = StateIndex.RETIRE;
            if (changedConnect()) {
                nextState = StateIndex.CHANGE;
            } else if (newSak) {
                nextState = StateIndex.RECEIVE;
            }
            return nextState;
        }
    }

    /**
     * Real worker for State Machine.
     */
    private class Worker implements Runnable {
        public int maxSmIterCount = 100;

        @Override
        public void run() {
            while (true) {
                try {
                    /**
                     *  Maximum maxSmIterCount state changes per turn.
                     */
                    int count = maxSmIterCount;
                    StateIndex previousState = null;
                    State currentState = null;
                    while (count-- > 0) {
                        previousState = currentStateIndex;
                        currentState = states.getOrDefault(currentStateIndex, null);
                        if (currentState != null && (currentState.step() != previousState)) {
                            currentState.enter();
                            currentStateIndex = currentState.step();
                        } else {
                            break;
                        }
                    }
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    logger.trace("Interruption in CP SM scheduling. {}", e.getMessage());
                }
            }
        }
    }

    Worker worker = new Worker();
    /**
     * State Machine thread pool related components.
     */
    ScheduledExecutorService executor;
    ScheduledFuture<?> future;
    /**
     * KaY, SecY connections.
     */
    MkaParticipant participant;
    MacSecSecY secY;
    String portName;

    /**
     * Needs participant created properly.
     *
     * @param participant   details.
     * @param secY          SecY interface details.
     * @param cipherSuit    details.
     * @param distributedKI KeyIdentifier
     * @param distributedAN association number
     * @param executor      scheduled service
     */
    public CpStateMachine(MkaParticipant participant, MacSecSecY secY,
                          MacSecCipherSuit cipherSuit,
                          byte[] distributedKI,
                          byte distributedAN,
                          ScheduledExecutorService executor) {
        this.secY = secY;
        this.participant = participant;
        portName = participant.port().number().name();
        this.executor = executor;
        /**
         *  Generation default settings.
         */
        protectFrames = true;
        connectType = ConnectType.SECURE;
        newSak = true;
        usingReceiveSAs = true;
        usingTransmitSA = true;
        /**
         *  Validation default settings.
         */
        validateFrames = MacSecValidate.Strict;
        replayProtect = false;
        replayProtectWindow = defaultReplayProtectWindow;
        /**
         * Other settings
         */
        lrx = true;
        ltx = true;
        lki = null;
        orx = false;
        otx = false;
        oki = null;
        controlledPortEnabled = false;
        chgdServer = false;
        this.distributedAN = distributedAN;
        this.distributedKI = distributedKI;
        electedSelf = true;
        /**
         * Ciphersuit.
         */
        this.cipherSuit = cipherSuit;
        /**
         *  Timers.
         *  TODO : Needs timeout on transmitDelay & retireDelay
         */
        transmitDelay = 0;
        retireDelay = defaultSakRetireTime;
        currentStateIndex = StateIndex.BEGIN;
        /**
         *  Really apply SecY settings.
         */
        secY.setCurrentCipherSuit(portName, cipherSuit.id());
        secY.protectFrames(portName, protectFrames);
        secY.validateFrames(portName, validateFrames);
        secY.replayProtect(portName, replayProtect, replayProtectWindow);
        secY.enablePort(portName, controlledPortEnabled);
    }

    /**
     * To start state machine.
     */
    public void startStateMachine() {
        future = executor.scheduleWithFixedDelay(worker, 1, 1, TimeUnit.MICROSECONDS);
    }

    public void stepStateMachine() {
        future.cancel(false);
        future = executor.scheduleWithFixedDelay(worker, 1, 1, TimeUnit.MICROSECONDS);
    }

    /**
     * To set distributed key identifier.
     *
     * @param ki Key Identifier
     */
    public void setDistributedKI(byte[] ki) {
        distributedKI = ki;
    }

    /**
     * To set distributed association number.
     *
     * @param an Association Number
     */
    public void setDistributedAN(byte an) {
        distributedAN = an;
    }

    /**
     * To set currently using receive SAs.
     *
     * @param status Status
     */
    public void setUsingReceiveSAs(boolean status) {
        usingReceiveSAs = status;
    }

    /**
     * To set currently using transmit SAs.
     *
     * @param status Status
     */
    public void setUsingTransmitSA(boolean status) {
        usingTransmitSA = status;
    }

    /**
     * MACSec cipher suite details.
     *
     * @return ciphersuite MACSecCiphersuite details.
     */
    public MacSecCipherSuit cipherSuit() {
        return cipherSuit;
    }

    /**
     * MACSec replayprotect details.
     *
     * @return replayProtect details.
     */
    public boolean macSecReplayProtect() {
        return replayProtect;
    }

    /**
     * MACSec protectFrames details.
     *
     * @return protectFrames details.
     */
    public boolean macSecProtect() {
        return protectFrames;
    }

    /**
     * MACSec validateFrames details.
     *
     * @return validateFrames details.
     */
    public MacSecValidate macSecValidate() {
        return validateFrames;
    }
}
