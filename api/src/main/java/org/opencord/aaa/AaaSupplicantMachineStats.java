/*
 * Copyright 2018-present Open Networking Foundation
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

public class AaaSupplicantMachineStats {

        private String sessionId;

        private String sessionName;

        private long sessionDuration;

        private long totalFramesReceived;

        private long totalFramesSent;

        private long totalPacketsRecieved;

        private long totalPacketsSent;

        private long totalOctetRecieved;

        private long totalOctetSent;

        private String eapolType;

        private String srcMacAddress;

        private String sessionTerminateReason;

        public String getSessionId() {
                return sessionId;
        }

        public void setSessionId(String sessionId) {
                this.sessionId = sessionId;
        }

        public String getSessionName() {
                return sessionName;
        }

        public void setSessionName(String sessionName) {
                this.sessionName = sessionName;
        }

        public long getSessionDuration() {
                return sessionDuration;
        }

        public void setSessionDuration(long sessionDuration) {
                this.sessionDuration = sessionDuration;
        }

        public long getTotalFramesReceived() {
                return totalFramesReceived;
        }

        public void setTotalFramesReceived(long totalFramesReceived) {
                this.totalFramesReceived = totalFramesReceived;
        }

        public String getEapolType() {
                return eapolType;
        }

        public void setEapolType(String eapolType) {
                this.eapolType = eapolType;
        }

        public String getSrcMacAddress() {
                return srcMacAddress;
        }

        public void setSrcMacAddress(String srcMacAddress) {
                this.srcMacAddress = srcMacAddress;
        }

        public long getTotalFramesSent() {
                return totalFramesSent;
        }

        public void setTotalFramesSent(long totalFramesSent) {
                this.totalFramesSent = totalFramesSent;
        }

        public long getTotalPacketsRecieved() {
                return totalPacketsRecieved;
        }

        public void setTotalPacketsRecieved(long totalPacketsRecieved) {
                this.totalPacketsRecieved = totalPacketsRecieved;
        }

        public long getTotalPacketsSent() {
                return totalPacketsSent;
        }

        public void setTotalPacketsSent(long totalPacketsSent) {
                this.totalPacketsSent = totalPacketsSent;
        }

        public long getTotalOctetRecieved() {
                return totalOctetRecieved;
        }

        public void setTotalOctetRecieved(long totalOctetRecieved) {
                this.totalOctetRecieved = totalOctetRecieved;
        }

        public long getTotalOctetSent() {
                return totalOctetSent;
        }

        public void setTotalOctetSent(long totalOctetSent) {
                this.totalOctetSent = totalOctetSent;
        }

        public String getSessionTerminateReason() {
                return sessionTerminateReason;
        }

        public void setSessionTerminateReason(String sessionTerminateReason) {
                this.sessionTerminateReason = sessionTerminateReason;
        }

}
