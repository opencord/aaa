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
         "radiusConnectionType" : "socket",
         "radiusServerConnectPoints": [ "of:00000000000000b2/2" ],
         "packetCustomizer" : "sample"
     }
 ```
 ### Configuration Parameters
##### nasIp
 IP Address of the NAS  which is requesting authentication of the user
##### nasMac
MAC Address of the NAS  which is requesting authentication of the user `(Used only when radiusConnectionType is port)`
##### radiusSecret
Shared secret
##### radiusIp
IP Address of the RADIUS Server
##### radiusServerPort
UDP Port Number on which RADIUS Server is listening
##### radiusMac
MAC address of the RADIUS server or next hop router `(Used only when radiusConnectionType is port)`
##### vlanId
VLAN on which the RADIUS Server is available `(Used only when radiusConnectionType is port)`
##### radiusConnectionType
There are two options for communication with the Radius Server
- "socket" : Communication using a UDP socket.
- "port"   : Communication using directly the port of the SDN switch connected to the Radius Server.

When `port` is used, the RADIUS packets sent out would carry the IP and MAC address of the device from which the EAP packets were received. That device should be available in the `SubscriberAndDeviceInformationService (Sadis)`. AAA application fetches data from Sadis based on the serial number of the device.

##### radiusServerConnectPoints
Connect point of SDN switch through which the RADIUS Server is reachable `(Used only when radiusConnectionType is port)`

##### packetCustomizer
The values of RADIUS attributes expected by the RADIUS Server might be different in different scenarios or in case of different Operators.

As of today AAA App provides two different customizers
"default" : When you set the value as this, no customization is done to the RADIUS packets
"sample" : This is a sample customization wherein specific RADIUS attributes and filled with values from `Sadis` Service. The src MAC and src IP of the RADIUS messages are set according to the OLT device (from which the EAP Start message is received) configured in `Sadis`

More customizers might be added to AAA App later which can fill Subscriber specific atrributes into the RADIUS attributes/messages by querying data from `Sadis`. The key to get data from Sadis is the PortName of the Port from which EAP messages are received.

# Example configuration of Sadis
```sh
   "org.opencord.sadis" : {
      "sadis" : {
        "integration" : {
          "cache" : {
            "enabled" : true,
            "maxsize" : 50,
            "ttl" : "PT1m"
          }
        },
        "entries" : [ {
          "id" : "uni-128", # (This is an entry for a subscriber) Same as the portName of the Port as seen in onos ports command
          "cTag" : 2, # C-tag of the subscriber
          "sTag" : 2, # S-tag of the subscriber
          "nasPortId" : "uni-128"  # NAS Port Id of the subscriber, could be different from the id above
        }, {
          "id" : "1d3eafb52e4e44b08818ab9ebaf7c0d4", # (This is an entry for an OLT device) Same as the serial of the OLT logical device as seen in the onos devices command
          "hardwareIdentifier" : "00:1b:22:00:b1:78", # MAC address to be used for this OLT
          "ipAddress" : "192.168.1.252", # IP address to be used for this OLT
          "nasId" : "B100-NASID" # NAS ID to be used for this OLT
        } ]
      }
    }
 ```
