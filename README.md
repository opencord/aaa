# ONOS AAA Application

The ONOS AAA application behaves as a NAS Server and does RADIUS authentication of the ports. It maintains state machines for each of the ports from which it receives EAP Start messages to maintain the current status of the authentication procedure.

# Configuration
```sh
 "org.opencord.aaa" : {
      "AAA" : {
         "nasIp": "192.168.1.251",
         "nasMac" : "00:1b:22:34:55:78",
         "radiusSecret": "testing123",
         "radiusIp": "192.168.1.254",
         "radiusServerPort" : "1812",
         "radiusMac" : "00:1e:67:d2:ee:f7",
         "vlanId" : "4000",
         "useSocket" : "false",
         "radiusServerConnectPoints": [ "of:00000000000000b2/2" ],
         "packetCustomizerClassName" : "ATnTPacketCustomizer"
     }
 ```
 ### Configuration Parameters
##### nasIp 
 IP Address of the NAS  which is requesting authentication of the user
##### nasMac
MAC Address of the NAS  which is requesting authentication of the user `(Used only when useSocket is false)`
##### radiusSecret
Shared secret
##### radiusIp
IP Address of the RADIUS Server
##### radiusServerPort
UDP Port Number on which RADIUS Server is listening
##### radiusMac
MAC address of the RADIUS server or next hop router `(Used only when useSocket is false)`
##### vlanId
VLAN on which the RADIUS Server is available `(Used only when useSocket is false)`
##### useSocket
There are two options for communication with the Radius Server
- Communication using a UDP socket
- Communication using directly the port of the SDN switch connected to the Radius Server.

When useSocket is false, the RADIUS packets sent out would carry the IP and MAC address of the device from which the EAP packets were received. That device should be available in the `SubscriberAndDeviceInformationService (Sadis)`. AAA application fetches data from Sadis based on the serial number of the device.

##### radiusServerConnectPoints
Connect point of SDN switch through which the RADIUS Server is reachable `(Used only when useSocket is false)`

##### packetCustomizerClassName
User defined class which can be used to customize the RADIUS packets to be sent to the RADIUS Server. The values of RADIUS attributes expected by the RADIUS Server might be different in different scenarios or in case of different Operators. The PacketCustomizer class can be extended to do that kind of customization and configured in this parameter.

The customizer can fill in Subscriber specific atrributes into the RADIUS attributes/messages by querying data from `Sadis`. The key to get data from Sadis is the PortName of the Port from which EAP messages are received.

