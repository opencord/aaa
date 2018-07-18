/*
 * Copyright 2017-present. * Open Networking Foundation .
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

// import com.sun.xml.internal.bind.v2.runtime.reflect.Lister;


import org.onlab.packet.EAPOL;
import org.onlab.packet.EAPOLMkpdu;
import org.onlab.packet.EAPOLMkpduICVIndicatorParameterSet;
import org.onlab.packet.EAPOLMkpduParameterSet;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.EAPOLMkpduBasicParameterSet;
import org.onlab.packet.EAPOLMkpduBasicParameterSet.SCI;
import org.onlab.packet.EAPOLMkpduPeerListParameterSet;
import org.onlab.packet.EAPOLMkpduPeerListParameterSet.MemberDetails;
import org.onlab.packet.EAPOLMkpduMACSecUseParameterSet;
import org.onlab.packet.EAPOLMkpduDistributedSAKParameterSet;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketService;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * MKA KaY( MAC Key Agreement Protocol Entity) participants coming under one CA.
 * IEEE 802.1X-2010 Clause 9.16, Figure 12-3
 */
public class MkaParticipant {

    /* Logger */
    private final Logger log = getLogger(getClass());

    /* KaY(parent), SecY interfaces*/
    MacSecKaY kay;
    MacSecSecY secY;

    /* SCI */
    private SCI actorSci;

    /* Key Details */
    private byte[] cak;
    private byte[] ckn;
    private byte[] kek;
    private byte[] ick;
    private byte[] sak;

    /* Actor Details. ie. myself as Actor. */
    private byte actorPriority;
    private byte[] mi;
    private int mn;

    /* Port specific management, monitor & control */
    private boolean active;

    public enum ActivateType {
        DEFAULT,
        DISABLED,
        ON_OPER_UP,
        ALWAYS
    }

    private ActivateType activate;
    private boolean principal;

    /* MACSec specific management, monitor & control. */
    /* MACSec Capabalities. IEEE 802.1x; Table 11-6 */
    private MacSecCipherSuit.MacSecCapabilities macSecCapability;
    private boolean macSecDesired;

    private List<MkaPeer> livePeers = new ArrayList<>();
    private List<MkaPeer> potentialPeers = new ArrayList<>();

    /* Latest Key Server Details. ie. Details of Key Server for current SAK.  */
    private byte[] latestKI;
    private int latestKN;
    private boolean latestTX;
    private boolean latestRX;
    private byte latestAN;

    /* Old Key Server Details. ie. Details of Key Server for previous SAK. */
    private byte[] oldKI;
    private int oldKN;
    private boolean oldTX;
    private boolean oldRX;
    private byte oldAN;

    private final byte[] emptyKI = new byte[EAPOLMkpduParameterSet.FIELD_MI_LENGTH];

    /* AAA State-Machine; for Device, Supplicant access  */
    private StateMachine sm;

    /* Packet Service for packet transmission. */
    private PacketService ps;
    private DeviceId deviceId;
    private Port port;

    /* Key Store */
    public class KeyStore {
        class Key {
            int keyIndex;
            ByteBuffer keyIdentifier;
            ByteBuffer key;
            long createdTime;
            boolean transmits, receives;

            Key(int keyIndex, byte[] keyIdentifier, byte[] key) {
                this.keyIndex = keyIndex;
                this.keyIdentifier = ByteBuffer.wrap(keyIdentifier);
                this.key = ByteBuffer.wrap(key);
                createdTime = System.currentTimeMillis();
                transmits = true;
                receives = true;
            }

            public byte[] key() {
                return key.array();
            }

            public ByteBuffer keyBuffer() {
                return key;
            }

            public byte[] keyIdentifier() {
                return keyIdentifier.array();
            }

            public int keyIndex() {
                return keyIndex;
            }

            public ByteBuffer keyIdentifierBuffer() {
                return keyIdentifier;
            }


         /*   @Override
            public boolean equals(Object object) {

                if ((object instanceof Key) && ((Key) object).keyBuffer().equals(key))
                    return true;
                else if ((object instanceof ByteBuffer) && ((ByteBuffer) object).equals(keyIdentifier))
                    return true;
                return false;
            }*/

            @Override
            public int hashCode() {
                return keyIdentifier().hashCode();
            }

            public void setTransmits(boolean status) {
                transmits = status;
            }

            public boolean isTransmits() {
                return transmits;
            }

            public void setReceives(boolean status) {
                receives = status;
            }

            public boolean isReceives() {
                return receives;
            }
        }

        class Store {
            Map<Key, List<SecureAssociation>> store = new LinkedHashMap<>();

            public void put(Key key, List<SecureAssociation> value) {
                store.put(key, value);
            }

            public List<SecureAssociation> get(ByteBuffer keyID) {
                Optional<Key> key = store.keySet().stream()
                        .filter(k -> k.keyIdentifierBuffer().equals(keyID))
                        .findFirst();
                List<SecureAssociation> x = key.isPresent() ? store.get(key.get()) : null;
                return x;
//                return (key != null) ? store.get(key) : null;
            }

            public Set<Key> keySet() {
                return store.keySet();
            }

        }

        Store store = null;
        AtomicInteger indexSequence = null;

        KeyStore() {
            store = new Store();
            indexSequence = new AtomicInteger();
        }

        public void storeSA(byte[] keyIdentifier, SecureAssociation sa) {
            ByteBuffer keyIDBuffer = ByteBuffer.wrap(keyIdentifier);
            List<SecureAssociation> saList = store.get(keyIDBuffer);
            if (saList != null) {
                saList.add(sa);
            }
        }

        public List<SecureAssociation> retrieveSAs(byte[] keyIdentifier) {
            ByteBuffer keyIDBuffer = ByteBuffer.wrap(keyIdentifier);
            return store.get(keyIDBuffer);

            //return store.get(keyIDBuffer);
        }

        public void transmits(byte[] keyIdentifier, boolean status) {
            ByteBuffer keyIDBuffer = ByteBuffer.wrap(keyIdentifier);
            Optional<Key> keyEntry = store.keySet().stream()
                    .filter(k -> k.equals(keyIDBuffer))
                    .findFirst();
            keyEntry.ifPresent(k -> k.setTransmits(status));
        }

        public boolean isTransmits(byte[] keyIdentifier) {
            ByteBuffer keyIDBuffer = ByteBuffer.wrap(keyIdentifier);
            Key keyEntry = store.keySet().stream()
                    .filter(k -> k.equals(keyIDBuffer))
                    .findFirst()
                    .get();
            return (keyEntry != null) ? keyEntry.isTransmits() : false;
        }

        public void receives(byte[] keyIdentifier, boolean status) {
            ByteBuffer keyIDBuffer = ByteBuffer.wrap(keyIdentifier);
            Optional<Key> keyEntry = store.keySet().stream()
                    .filter(k -> k.equals(keyIDBuffer))
                    .findFirst();
            keyEntry.ifPresent(k -> k.setReceives(status));
        }

        public boolean isReceives(byte[] keyIdentifier) {
            ByteBuffer keyIDBuffer = ByteBuffer.wrap(keyIdentifier);
            Key keyEntry = store.keySet().stream()
                    .filter(k -> k.equals(keyIDBuffer))
                    .findFirst()
                    .get();
            return (keyEntry != null) ? keyEntry.isReceives() : false;
        }

        public void createKey(byte[] keyIdentifier, byte[] key) {
            ByteBuffer keyIDBuffer = ByteBuffer.wrap(keyIdentifier);
            List<SecureAssociation> saList = store.get(keyIDBuffer);
            if (saList == null) {
                saList = new LinkedList<>();
                Key index = new Key(indexSequence.getAndIncrement() % Byte.MAX_VALUE,
                        keyIdentifier, key);
                store.put(index, saList);
                secY.installKey(port.number().name(), index.keyIndex(), index.key(),
                        index.keyIdentifier(), index.isTransmits(), index.isReceives());
            }
        }
    }

    KeyStore keyStore = null;

    /* General Secure Connection & Secure Associations. IEEE 802.1AE SecY YANG model. */
    enum SCType {
        GENERATION, VERIFICATION
    }

    abstract class SecureConnection {
        SCI sci = null;
        long createdTime;
        SCType type;
        AtomicInteger anIndex = new AtomicInteger();
        List<SecureAssociation> sas = new LinkedList<>();

        SecureConnection(SCI sci, SCType type) {
            this.sci = sci;
            this.type = type;
            createdTime = System.currentTimeMillis();
        }

        public void attachSA(SecureAssociation sa) {
            sas.add(sa);
        }

        public void detachSA(SecureAssociation sa) {
            sas.removeIf(s -> s.equals(sa));
        }

        public byte getNextAvailableAN() {
            return (byte) (anIndex.getAndIncrement() % Byte.MAX_VALUE);
        }

        public SCI sci() {
            return sci;
        }

        public SCType type() {
            return type;
        }
    }

    abstract class SecureAssociation {
        SecureConnection parent;
        byte an;
        long createdTime;
        boolean inUse;

        SecureAssociation(SecureConnection sc, byte an) {
            parent = sc;
            this.an = an;
            createdTime = System.currentTimeMillis();
            inUse = false;
        }

        public SecureConnection parent() {
            return parent;
        }

        public byte an() {
            return an;
        }

        public void setInUse(boolean status) {
            inUse = status;
        }
    }

    /* Transmit SC. */
    class TransmitSC extends SecureConnection {
        byte encodingSA;
        boolean transmitting;

        /* Transmit SAs */
        class TransmitSA extends SecureAssociation {
            long nextPN;
            boolean confidentiality;

            TransmitSA(TransmitSC sc, byte an, long nextPN) {
                super(sc, an);
                this.nextPN = nextPN;

                /* TODO : Confidentiality determine from offset. */
                /* confidentiality = ? */
            }

            public long nextPN() {
                return nextPN;
            }
        }

        TransmitSC(SCI sci) {
            super(sci, SCType.GENERATION);
            encodingSA = (byte) 0x00;
            transmitting = false;
        }

        public SecureAssociation createSA(byte an, long nextPN) {
            TransmitSA sa = new TransmitSA(this, an, nextPN);
            attachSA(sa);
            return sa;
        }
    }

    TransmitSC txSC = null;

    /* Receive SC. IEEE 802.1AE SecY YANG model. */
    class ReceiveSC extends SecureConnection {

        boolean receiving;

        ReceiveSC(SCI sci) {
            super(sci, SCType.VERIFICATION);
            receiving = false;
        }

        class ReceiveSA extends SecureAssociation {
            long nextPN, lowestPN;

            ReceiveSA(ReceiveSC sc, byte an, long pn, long lpn) {
                super(sc, an);
                nextPN = pn;
                lowestPN = lpn;
            }

            public long nextPN() {
                return nextPN;
            }

            public long lowestPN() {
                return lowestPN;
            }

        }

        public SecureAssociation createSA(byte an, long pn, long lpn) {
            ReceiveSA sa = new ReceiveSA(this, an, pn, lpn);
            attachSA(sa);
            return sa;
        }

    }

    LinkedList<ReceiveSC> rxSCList = new LinkedList<>();

    /* EAPOL-MKPDU serialization/de-serialization supporters.
     * ie. ParameterSet Creators & Processors  */
    abstract class ParameterSetCreator {
        MacSecKaY kaY;
        MkaParticipant participant;

        public ParameterSetCreator(MacSecKaY kaY, MkaParticipant participant) {
            this.kaY = kaY;
            this.participant = participant;
        }

        /* Building parameter set. */
        abstract EAPOLMkpduParameterSet buildParameterSet();

        /* Identifying type of parameter set supporting. */
        abstract int parameterSetType();
    }

    /* Basic Parameter Set Creator */
    class BasicParameterSetCreator extends ParameterSetCreator {
        MacSecKaY kaY;
        MkaParticipant participant;

        BasicParameterSetCreator(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        EAPOLMkpduParameterSet buildParameterSet() {
            EAPOLMkpduBasicParameterSet bps = new EAPOLMkpduBasicParameterSet();
            bps.setMkaVersion(kay.mkaVersion());
            bps.setKeyServerPriority(participant.actorPriority());
                /* TODO: KeyServer Election not done.
                 * So setting myself as infrastructure key server.
                 */
            bps.setKeyServer(true);
            bps.setMacSecDesired(participant.macSecDesired);
            bps.setMacSecCapability((byte) participant.macSecCapability.ordinal());
            bps.setSci(participant.actorSci());
            bps.setActorMI(participant.actorMI());
            bps.setActorMN(participant.retrieveAndUpdateMN());
            bps.setAlgAgility(kay.defaultAlgorithmAgility().getParameter());
            bps.setCKN(participant.ckn());
            return (EAPOLMkpduParameterSet) bps;
        }

        @Override
        int parameterSetType() {
            return EAPOLMkpduParameterSet.PARAMETERSET_TYPE_BASIC;
        }
    }

    /* Live Peer List Parameter Set Creator */
    class LivePeerListCreator extends ParameterSetCreator {
        MacSecKaY kaY;
        MkaParticipant participant;

        LivePeerListCreator(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        EAPOLMkpduParameterSet buildParameterSet() {
                /* Ensure Live Peers are existing. */
            List<MkaPeer> peers = participant.allLivePeers();
            if (peers.isEmpty()) {
                return null;
            }
                /* Populate Peer list. */
            EAPOLMkpduPeerListParameterSet lplps =
                    new EAPOLMkpduPeerListParameterSet();
            lplps.setPeerListType(EAPOLMkpduPeerListParameterSet.peerListTypeLive);
            peers.forEach((peer) -> {
                lplps.addMember(peer.mi(), peer.mn());
            });
            return (EAPOLMkpduParameterSet) lplps;
        }

        @Override
        int parameterSetType() {
            return EAPOLMkpduPeerListParameterSet.peerListTypeLive;
        }
    }

    /* Potential Parameter Set Creator */
    class PotentialPeerListCreator extends ParameterSetCreator {
        MacSecKaY kaY;
        MkaParticipant participant;

        PotentialPeerListCreator(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        EAPOLMkpduParameterSet buildParameterSet() {
                /* Ensure Potential Peers are existing. */
            List<MkaPeer> peers = participant.allPotentialPeers();
            if (peers.isEmpty()) {
                return null;
            }
                /* Populate Peer list. */
            EAPOLMkpduPeerListParameterSet pplps =
                    new EAPOLMkpduPeerListParameterSet();
            pplps.setPeerListType(EAPOLMkpduPeerListParameterSet.peerListTypePotential);
            peers.forEach((i) -> {
                pplps.addMember(i.mi(), i.mn());
            });
            return (EAPOLMkpduParameterSet) pplps;
        }

        @Override
        int parameterSetType() {
            return EAPOLMkpduPeerListParameterSet.peerListTypePotential;
        }
    }

    /* MACSec Use Parameter Set Creator */
    class MacSecUseCreator extends ParameterSetCreator {
        MacSecKaY kaY;
        MkaParticipant participant;

        MacSecUseCreator(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        EAPOLMkpduParameterSet buildParameterSet() {
            EAPOLMkpduMACSecUseParameterSet ups =
                    new EAPOLMkpduMACSecUseParameterSet();
            CpStateMachine cpSM = kay.lookupCPStateMachineByID(sm.sessionId());
            ups.setDelayProtect(cpSM.macSecReplayProtect());
            ups.setPlainTX(!cpSM.macSecProtect());
            ups.setPlainRX((cpSM.macSecValidate() == CpStateMachine.MacSecValidate.Disabled) ? true : false);

            // Latest Key Server Details
            ups.setLatestKI(participant.latestKI());
            ups.setLatestKN(participant.latestKN());
            ups.setLatestTX(participant.latestTX());
            ups.setLatestRX(participant.latestRX());
            ups.setLatestAN(participant.latestAN());

            /* TODO: Filling Latest Lowest Acceptable PN. */
            // Retrieve PN for Key Server.
            // int pn = DEVICE-Abstract-Layer.getPN(participant.latestKI())
            // ups.setLatestLAPN(pn)

            // Old Key Server Details.
            /* TODO: Needs rethinking for newly joined actors. */
            ups.setOldKI(participant.oldKI());
            ups.setOldKN(participant.oldKN());
            ups.setOldTX(participant.oldTX());
            ups.setOldRX(participant.oldRX());
            ups.setOldAN(participant.oldAN());

            /* TODO: Filling Old Lowest Acceptable PN. */
            // Retrieve PN for Key Server.
            // int opn = DEVICE-Abstract-Layer.getPN(participant.oldKI())
            // ups.setLatestLAPN(opn)
            return (EAPOLMkpduParameterSet) ups;
        }

        @Override
        int parameterSetType() {
            return EAPOLMkpduParameterSet.PARAMETERSET_TYPE_MACSEC_SAK_USE;
        }
    }

    /* Distributed SAK Parameter Set Creator */
    class DistributedSakCreator extends ParameterSetCreator {
        MacSecKaY kaY;
        MkaParticipant participant;

        DistributedSakCreator(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        EAPOLMkpduParameterSet buildParameterSet() {
            EAPOLMkpduDistributedSAKParameterSet dsps =
                    new EAPOLMkpduDistributedSAKParameterSet();
            dsps.setDistributedAN(participant.latestAN());
            CpStateMachine cpSM = kay.lookupCPStateMachineByID(sm.sessionId());
            dsps.setConfidentialityOffset((byte) cpSM.cipherSuit()
                    .getConfidentialityOffset().ordinal());
            dsps.setKeyNumber(participant.latestKN());
            dsps.setSAK(participant.sak());
            dsps.setKeyWrapper((byte[] key) -> {
                byte[] wrappedKey = new AescMac().wrap(participant.kek(), key);
                return wrappedKey;
            });
            return (EAPOLMkpduParameterSet) dsps;
        }

        @Override
        int parameterSetType() {
            return EAPOLMkpduParameterSet.PARAMETERSET_TYPE_DISTRIBUTED_SAK;
        }
    }

    /* ICV Parameter Set Creator */
    class IcvCreator extends ParameterSetCreator {

        MacSecKaY kaY;
        MkaParticipant participant;

        IcvCreator(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        EAPOLMkpduParameterSet buildParameterSet() {
            EAPOLMkpduICVIndicatorParameterSet icvps = new EAPOLMkpduICVIndicatorParameterSet();
                /* Populate PS fields. */
//                icvps.setKey(participant.ick());
//                 class AESCMAC_128_HashCreator implements EAPOLMkpduICVIndicatorParameterSet.HashGenerator<byte[]> {
//                     @Override
//                     public byte[] generateHash(byte[] key, byte[] msg) {
//                         return participant.kay.defaultAlgorithmAgility().generateICV(key, msg);
//                     }
//                 }
//                 icvps.setHashCreator(new AESCMAC_128_HashCreator());
//                icvps.setHashCreator((byte[] key, byte[] msg)
//                                      -> (kay.defaultAlgorithmAgility().generateICV(key, msg)));
            return (EAPOLMkpduParameterSet) icvps;
        }

        @Override
        int parameterSetType() {
            return EAPOLMkpduParameterSet.PARAMETERSET_TYPE_ICV_INDICATOR;
        }
    }

    Map<Byte, ParameterSetCreator> psCreators = new LinkedHashMap<>();

    /* Parameter Set Processors */
    abstract class ParameterSetProcessor {
        MacSecKaY kaY;
        MkaParticipant participant;

        public ParameterSetProcessor(MacSecKaY kaY, MkaParticipant participant) {
            this.kaY = kaY;
            this.participant = participant;
        }

        /* Process Parameter Set */
        abstract boolean process(EAPOLMkpdu mkpdu, EAPOLMkpduParameterSet parameterSet);
    }

    /* Basic Parameter Set Processor */
    class BasicParameterSetProcessor extends ParameterSetProcessor {

        MacSecKaY kaY;
        MkaParticipant participant;

        BasicParameterSetProcessor(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        public boolean process(EAPOLMkpdu mkpdu, EAPOLMkpduParameterSet parameterSet) {
            EAPOLMkpduBasicParameterSet bps = (EAPOLMkpduBasicParameterSet) parameterSet;
            byte[] mi = bps.getActorMI();
            int mn = bps.getActorMN();

            /* MKPDU received from new participant then populate in Potential Peer List */
            MkaPeer livePeer = participant.isLivePeer(mi);
            MkaPeer potentialPeer = participant.isPotentialPeer(mi);
            if ((livePeer == null) && (potentialPeer == null)) {
                MkaPeer peer = new MkaPeer(bps.getSci(), mi, mn);
                peer.setKeyServer(bps.getKeyServer());
                peer.setKeyServerPriority(bps.getKeyServerPriority());
                peer.setMacSecDesired(bps.getMacSecDesired());
                peer.setMacSecCapability(bps.getMacSecCapacity());
                peer.setTimestamp(System.currentTimeMillis());
                participant.addPotentialPeer(peer);
            } else {
                /* Already exiting actor, update details.*/
                MkaPeer currentPeer = (livePeer != null) ? livePeer : potentialPeer;
                if (currentPeer.mn() < mn) {
                    currentPeer.setMN(mn);
                    currentPeer.setKeyServer(bps.getKeyServer());
                    currentPeer.setKeyServerPriority(bps.getKeyServerPriority());
                    currentPeer.setMacSecDesired(bps.getMacSecDesired());
                    currentPeer.setMacSecCapability(bps.getMacSecCapacity());
                    currentPeer.setTimestamp(System.currentTimeMillis());
                    /* (livePeer != null) ? participant.updateLivePeer(currentPeer)
                                : participant.updatePotentialPeer(currentPeer); */
                }
            }
            /* Myself in peer's peer list and peer is in Potential Peer List */
            // if ((potentialPeer != null) &&
            //         (participant.myselfPeerOfRemotePeer(eapolMkpdu.getPeerListParameterSet()) == true)) {
            //     /* Update Live Peer list : */
            //     participant.addLivePeer(participant.removePotentialPeer(mi));
            // }
            return true;
        }
    }

    /* Live Peer List Parameter Set Processor. */
    class LivePeerListProcessor extends ParameterSetProcessor {

        MacSecKaY kaY;
        MkaParticipant participant;

        LivePeerListProcessor(MacSecKaY kaY, MkaParticipant participant) {
            super(kaY, participant);
            this.kaY = kay;
            this.participant = participant;
        }

        @Override
        boolean process(EAPOLMkpdu mkpdu, EAPOLMkpduParameterSet parameterSet) {
                /* Actor basic details. */
            EAPOLMkpduBasicParameterSet bps = mkpdu.getBasicParameterSet();
            final byte[] actorMI = bps.getActorMI();
            int actorMN = bps.getActorMN();
                /* Process each peer details in Live Parameter Set */
            EAPOLMkpduPeerListParameterSet lplPS = (EAPOLMkpduPeerListParameterSet) parameterSet;
            List<MemberDetails> lplMembers = lplPS.getMembers();
            lplMembers.forEach(m -> {
                byte[] mID = m.getMemberID();
                int mn = m.getMessageNo();
                    /* Live peer is myself. */
                if (Arrays.equals(mID, participant.mi)) {
                        /* Check peer is in Potential Peer list, if so update to Live Peers list.  */
                    if (participant.isPotentialPeer(actorMI) != null) {
                        MkaPeer peer = participant.removePotentialPeer(actorMI);
                        participant.addLivePeer(peer);
                        participant.createReceiveSC(peer.getSci());
                        secY.createReceiveSA(port.number().name(), peer.getSci(), txSC.getNextAvailableAN(),
                                1, 1);
                    }
                    return;
                }
                    /* Update if peer is in live list, otherwise add new in potential list. */
                MkaPeer peer = participant.isLivePeer(mID);
                if (peer != null) {
                    peer.setMN(mn);
                    peer.setTimestamp(System.currentTimeMillis());
                } else {
                    MkaPeer potentialPeer = new MkaPeer(peer.getSci(), mID, mn);
                    potentialPeer.setTimestamp(System.currentTimeMillis());
                    participant.addPotentialPeer(potentialPeer);
                }
            });
            return false;
        }
    }

    Map<Byte, ParameterSetProcessor> psProcessors = new LinkedHashMap<>();

    /* Hello Timer Executor */
    ScheduledExecutorService executorService;

    /* PAE Group Address. */
    public static final byte[] HELLO_MKPDU_SEND_ADDRESS = {(byte) 0x01, (byte) 0x80, (byte) 0xC2,
            (byte) 0x00, (byte) 0x00, (byte) 0x03};

    /* Constructor using Key & KeyName */
    MkaParticipant(StateMachine sm, PacketService ps,
                   ScheduledExecutorService executerService, MacSecKaY kay, MacSecSecY secY, byte[] key,
                   byte[] keyName, SCI actorSci, DeviceId deviceId, Port port) {

        /* Sanitize. Evaluate CAK & CKN */
        if ((key == null) || (keyName == null)) {
            /* TODO : */
        }
        if ((kay.defaultAlgorithmAgility().getCakLength() != key.length)) {
            /* TODO : */
        }

        /* Initialize KaY, SM, Packet Service etc. */
        this.kay = kay;
        this.secY = secY;
        this.sm = sm;
        this.ps = ps;
        this.executorService = executerService;

        /* Default MACSec RX/TX Protection Features. */
        macSecCapability = MacSecCipherSuit.MacSecCapabilities.INTEGRITY_AND_CONFIDENTIALITY;
        macSecDesired = true;

        /* KeyStore, SC & SA details */
        keyStore = new KeyStore();
        this.actorSci = actorSci;
        this.port = port;
        txSC = new TransmitSC(actorSci);
        secY.createTransmitSC(port.number().name(), actorSci);

        /* Key details update. */
        cak = key;
        ckn = keyName;

        /* Clear Member ID */
        resetMI();

        /* Initialize Key Server Details. */
        this.deviceId = deviceId;
        latestKI = mi;
        latestKN = 1; /* TODO: Starting KeyNumber Configurable. */
        latestTX = true;
        latestRX = true;
        latestAN = 0x01; /* TODO: Association Number should be initialized using standard method. */
        oldKI = emptyKI; /* Cleared old Member ID. */
        oldKN = 0;
        oldTX = latestTX;
        oldRX = latestRX;
        oldAN = 0X00; /* Cleared old AN. */

        /* Derive KEK, ICK from CAK, CKN */
        MacSecAlgorithmAgility algorithmAgility = kay.defaultAlgorithmAgility();
        kek = algorithmAgility.generateKek(cak, ckn);
        ick = algorithmAgility.generateIck(cak, ckn);

        /* Derive SAK from CAK */
        byte[] ksNonce = new byte[16];
        SecureRandom randomGenerator = new SecureRandom();
        randomGenerator.nextBytes(ksNonce);
        sak = algorithmAgility.generateSak(cak, ksNonce, mi, 1);
        keyStore.createKey(latestKI, sak);

        /* Initialize Parameter Creators. */
        psCreators.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_BASIC,
                new BasicParameterSetCreator(kay, this));
        psCreators.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_LIVE_PEER_LIST,
                new LivePeerListCreator(kay, this));
        psCreators.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_POTENTIAL_PEER_LIST,
                new PotentialPeerListCreator(kay, this));
        psCreators.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_MACSEC_SAK_USE,
                new MacSecUseCreator(kay, this));
        psCreators.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_DISTRIBUTED_SAK,
                new DistributedSakCreator(kay, this));
        /* TODO: Other parameter sets filling. */
        psCreators.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_ICV_INDICATOR,
                new IcvCreator(kay, this));

        /* Initialize Parameter Processors. */
        psProcessors.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_BASIC,
                new BasicParameterSetProcessor(kay, this));
        psProcessors.put(EAPOLMkpduParameterSet.PARAMETERSET_TYPE_LIVE_PEER_LIST,
                new LivePeerListProcessor(kay, this));
        /* TODO : Other parameter set processing. */
    }

    /* Actor SCI */
    public SCI actorSci() {
        return actorSci;
    }

    public void setActorSci(SCI sci) {
        this.actorSci = sci;
    }

    /* Outbound device details for packet transmission. */
    public DeviceId deviceId() {
        return deviceId;
    }

    public void setDeviceId(DeviceId deviceId) {
        this.deviceId = deviceId;
    }

    /* Outbound port details for packet transmission. */
    public Port port() {
        return port;
    }

    public void setPort(Port port) {
        this.port = port;
    }

    /* Process received EAPOL-MKPDU */
    public void receive(EAPOLMkpdu mkpdu) {
        /* Process Various Parameter Sets */
        ((LinkedHashMap<Byte, ParameterSetProcessor>) psProcessors).forEach((key, psp) -> {
            EAPOLMkpduParameterSet ps = mkpdu.getParameterSet(key);
            if ((ps != null) && (psp != null)) {
                psp.process(mkpdu, ps);
            }
        });
        return;
    }

    /* Start ticking heartbeat. ie enables Timers. */
    public void startTicking() {
        /* Initialize Hello Timer.  */
        class WorkerThread implements Runnable {
            MkaParticipant participant;

            WorkerThread(MkaParticipant participant) {
                this.participant = participant;
            }

            public void run() {
                /* TODO: Make sure my lifespan exists. */
                /* TODO: Clear expired Live Peers. */
                /* TODO : Clear expired Potential Peers. */
                /* TODO: Regenerate SAK if needed snd send it. */
                /* Build & Send MKPDU */
                log.info("Hello-Timer : Transmitting EAPOL-MKPDU....");
                participant.transmitMkpdu();
                log.info("Done.");
            }
        }
        executorService.scheduleAtFixedRate(new WorkerThread(this), 5, 5, TimeUnit.SECONDS);
    }

    /* Building & Sending EAPOL-MKPDU. Hello Timer's routine. */
    public void transmitMkpdu() {

        /* EAPOL-MKA packet building & populating Parameter Sets*/
        EAPOLMkpdu mkpdu = new EAPOLMkpdu();
        for (Map.Entry<Byte, ParameterSetCreator> entry : psCreators.entrySet()) {
            ParameterSetCreator c = entry.getValue();
            mkpdu.addParameterSet(entry.getKey(), c.buildParameterSet());
        }

        /* EAPOL Header Filling */
        EAPOL eapol = new EAPOL();
        eapol.setEapolType(EAPOL.EAPOL_MKA);
        eapol.setPacketLength(mkpdu.packetLength());
        eapol.setPayload(mkpdu);

        /* Ethernet Header Filling. */
        Ethernet ethernet = new Ethernet();
        ethernet.setDestinationMACAddress(HELLO_MKPDU_SEND_ADDRESS);
        ethernet.setSourceMACAddress(this.actorSci().address());
        ethernet.setEtherType(EthType.EtherType.EAPOL.ethType().toShort());
        ethernet.setVlanID(Ethernet.VLAN_UNTAGGED);
        ethernet.setPayload(eapol);
        ethernet.setPad(false);

        /* ICV Calculation and Populating */
        ByteBuffer frame = ByteBuffer.wrap(ethernet.serialize());
        byte[] frameWoIcv = new byte[frame.capacity() -
                kay.defaultAlgorithmAgility().getIcvLength() / 8];
        frame.get(frameWoIcv);
        byte[] icv = kay.defaultAlgorithmAgility().generateIcv(ick, frameWoIcv);
        frame.position(frame.capacity() -
                kay.defaultAlgorithmAgility().getIcvLength() / 8);
        frame.put(icv);

        /* Send packet to supplicant.  */
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(port.number()).build();
        OutboundPacket packet = new DefaultOutboundPacket(deviceId, treatment, frame);
        ps.emit(packet);
        log.info("Flushed out Hello-Timer EAPOL-MKA PDU.");
    }

    /* CP state machine KaY interactions. IEEE 802.1X 2010 Figure 12-2. */
    public void createReceiveSC(SCI sci) {
        if (sci == null) {
            log.info("Invalid SCI provided for SC creation.");
            return;
        }
        rxSCList.add(new ReceiveSC(sci));
        secY.createReceiveSC(port.number().name(), sci);
    }

    /* Creating Receive & Transmit SAs /*/
    public void createSAs(byte[] keyIdentifier) {
        List<SecureAssociation> sas = keyStore.retrieveSAs(keyIdentifier);
        if (sas != null && sas.size() > 0) {
            log.error("Improper keystore stage : {}", keyIdentifier);
            return;
        }

        /* Create Transmit SAs */
        SecureAssociation sa = txSC.createSA(txSC.getNextAvailableAN(), 1);
        keyStore.storeSA(keyIdentifier, sa);
        secY.createTransmitSA(port.number().name(), txSC.sci(), sa.an(), 1);
        keyStore.transmits(keyIdentifier, true);

        /* Create Receive SAs */
        rxSCList.stream().forEach(sc -> {
            SecureAssociation rxSA = sc.createSA(sc.getNextAvailableAN(), 1, 1);
            keyStore.storeSA(keyIdentifier, rxSA);
            secY.createReceiveSA(port.number().name(), sc.sci(), rxSA.an(), 1, 1);
        });
        keyStore.receives(keyIdentifier, true);
    }

    /* Deleting SAs associated with certain key. */
    public void deleteSAs(byte[] keyIdentifier) {
        List<SecureAssociation> saList = keyStore.retrieveSAs(keyIdentifier);
        if (saList == null) {
            log.error("Failed looking up key store. Key ID : {}", keyIdentifier);
            return;
        }
        saList.stream().forEach(sa -> {
            SecureConnection sc = sa.parent();
            if (sc.type() == SCType.GENERATION) {
                secY.deleteTransmitSA(port.number().name(), sc.sci(), sa.an());
            } else {
                secY.deleteReceiveSA(port.number().name(), sc.sci(), sa.an());
            }
            sc.detachSA(sa);
        });
        keyStore.transmits(keyIdentifier, false);
        keyStore.receives(keyIdentifier, false);
    }

    public void enableReceiveSAs(byte[] keyIdentifier) {
        List<SecureAssociation> saList = keyStore.retrieveSAs(keyIdentifier);
        if (saList == null) {
            log.error("Failed looking up key store. Key ID : {}", keyIdentifier);
            return;
        }

        // Iterate by filtering receive SAs in store and enable it
        CpStateMachine cpSM = kay.lookupCPStateMachineByID(sm.sessionId());
        saList.stream().filter(sa -> sa.parent().type() == SCType.GENERATION)
                .forEach(sa -> {
                    SecureConnection sc = sa.parent();
                    sa.setInUse(true);
                    secY.enableReceiveSA(port.number().name(), sc.sci(), sa.an());
                    cpSM.setUsingReceiveSAs(true);
                    cpSM.stepStateMachine();
                });
        return;
    }

    public void enableTransmitSA(byte[] keyIdentifier) {
        List<SecureAssociation> saList = keyStore.retrieveSAs(keyIdentifier);
        if (saList == null) {
            log.error("Failed looking up key store. Key ID : {}", keyIdentifier);
            return;
        }

        // Iterate by filtering receive SAs in store and enable it
        CpStateMachine cpSM = kay.lookupCPStateMachineByID(sm.sessionId());
        saList.stream().filter(sa -> sa.parent().type() == SCType.GENERATION)
                .forEach(sa -> {
                    SecureConnection sc = sa.parent();
                    sa.setInUse(true);
                    secY.enableTransmitSA(port.number().name(), sc.sci(), sa.an());
                    cpSM.setUsingTransmitSA(true);
                    cpSM.stepStateMachine();
                });
        return;
    }

    public void setOldSAAttributes(byte[] ki, byte an, boolean tx, boolean rx) {
        oldKI = (ki == null) ? emptyKI : ki;
        oldAN = an;
        oldTX = tx;
        oldRX = rx;
    }

    public void setLatestSAAttributes(byte[] ki, byte an, boolean tx, boolean rx) {
        latestKI = (ki == null) ? emptyKI : ki;
        latestAN = an;
        latestTX = tx;
        latestRX = rx;
    }

    /* Peer details storing. */
    protected class MkaPeer {
        /* Basic Parameter Set details.*/
        SCI sci;
        private byte[] mi;
        private int mn;
        private boolean isKeyServer;
        private byte keyServerPriority;
        private boolean macSecDesired;
        private byte macSecCapbility;
        /* Expire time details */
        private long expireTimestamp;

        MkaPeer(SCI sci, byte[] mi, int mn) {
            this.sci = sci;
            this.mi = mi;
            this.mn = mn;
        }

        /* Member Identifier */
        public byte[] mi() {
            return mi;
        }

        /* Message Number */
        public int mn() {
            return mn;
        }

        public void setMN(int mn) {
            this.mn = mn;
        }

        /* Key Server Status */
        public boolean keyServer() {
            return isKeyServer;
        }

        public void setKeyServer(boolean keyServer) {
            this.isKeyServer = keyServer;
        }

        /* Key Server Priority */
        public byte keyServerPriority() {
            return keyServerPriority;
        }

        public void setKeyServerPriority(byte keyServerPriority) {
            this.keyServerPriority = keyServerPriority;
        }

        /* MACSec desirability */
        public boolean macSecDesired() {
            return macSecDesired;
        }

        public void setMacSecDesired(boolean macSecDesired) {
            this.macSecDesired = macSecDesired;
        }

        /* MACSec capability */
        public byte macSecCapability() {
            return macSecCapbility;
        }

        public void setMacSecCapability(byte macSecCapbility) {
            this.macSecCapbility = macSecCapbility;
        }

        /* Expire time details. */
        public void setTimestamp(long timestamp) {
            expireTimestamp = timestamp;
        }

        public long getTimestamp() {
            return expireTimestamp;
        }

        public SCI getSci() {
            return sci;
        }
    }

    /* Live peer or not ? */
    protected MkaPeer isLivePeer(byte[] mi) {
        MkaPeer p = livePeers.stream()
                .filter((q) -> Arrays.equals(q.mi(), mi))
                .findAny()
                .orElse(null);
        return p;
    }

    /* Live peers at a time. */
    protected List<MkaPeer> allLivePeers() {
        return livePeers;
    }

    /* Potential peer or not ? */
    protected MkaPeer isPotentialPeer(byte[] mi) {
        MkaPeer p = potentialPeers.stream()
                .filter((q) -> Arrays.equals(q.mi(), mi))
                .findAny()
                .orElse(null);
        // if( p != null ) {
        //     /* Update MN if new. */
        //     if (p.getMN() <  mn) p.setMN(mn);
        // }
        return p;
    }

    /* All Potential Peers at a time. */
    protected List<MkaPeer> allPotentialPeers() {
        return potentialPeers;
    }

    /* Populate Potential Peer */
    protected void addPotentialPeer(MkaPeer p) {
        if (p != null && (isPotentialPeer(p.mi()) == null)) {
            potentialPeers.add(p);
        }
        return;
    }

    /* Remove Potential Peer */
    protected MkaPeer removePotentialPeer(byte[] mi) {
        MkaPeer p = potentialPeers.stream()
                .filter((q) -> Arrays.equals(q.mi(), (mi)))
                .findAny()
                .orElse(null);
        if (p != null) {
            potentialPeers.remove(p);
        }
        return p;
    }

    /* Populate Live Peer */
    protected void addLivePeer(MkaPeer p) {
        if (p != null && (isLivePeer(p.mi()) == null)) {
            livePeers.add(p);
        }
        return;
    }

    /* Check myself present in remote peer's peer list */
    protected boolean myselfPeerOfRemotePeer(EAPOLMkpduPeerListParameterSet peerList) {
        /* Handle Non-Peer List cases. */
        if (peerList == null) {
            return false;
        }
        if (peerList.getParameterSetType() != EAPOLMkpduPeerListParameterSet.peerListTypeLive) {
            return false;
        }
        return peerList.memberExists(mi);
    }

    /* Resets MI & MN */
    protected void resetMI() {
        SecureRandom random = new SecureRandom();
        mi = new byte[EAPOLMkpduParameterSet.FIELD_MI_LENGTH];
        random.nextBytes(mi);
        /* TODO : Check IEEE 802.1X and finalize. */
        mn = 1;
    }

    /* Key Server Priority */
    protected byte actorPriority() {
        return actorPriority;
    }

    /* Key Server MI */
    protected byte[] actorMI() {
        return mi;
    }

    /* Key Server MN */
    protected int actorMN() {
        return mn;
    }

    /* Retrieve and update Key Server MN */
    protected int retrieveAndUpdateMN() {
        int currentMN = mn;
        /* Update MN for each Tx. */
        mn += 1;
        return currentMN;
    }

    /* Various Getters & Setters. */

    /* Various Keys. */
    protected byte[] cak() {
        return cak;
    }

    protected byte[] ckn() {
        return ckn;
    }

    protected byte[] sak() {
        return sak;
    }

    protected byte[] ick() {
        return ick;
    }

    protected byte[] kek() {
        return kek;
    }

    /* Current Key Server Key Number */
    protected int latestKN() {
        return latestKN;
    }

    /* Current Key Server Identifier */
    protected byte[] latestKI() {
        return latestKI;
    }

    /* Current Key Server Association Number */
    protected byte latestAN() {
        return latestAN;
    }

    /* Current Key Server used for TX protection ? */
    protected boolean latestTX() {
        return latestTX;
    }

    /* Current Key Server used for RX protection ? */
    protected boolean latestRX() {
        return latestRX;
    }

    /* Old Key Server Identifier */
    protected byte[] oldKI() {
        return oldKI;
    }

    /* Old Key Server Key Number */
    protected int oldKN() {
        return oldKN;
    }

    /* Old Key Server Association Number */
    protected byte oldAN() {
        return oldAN;
    }

    /* Old Key Server used for TX protection ? */
    protected boolean oldTX() {
        return oldTX;
    }

    /* Old Key Server used for RX protection ? */
    protected boolean oldRX() {
        return oldRX;
    }
}
