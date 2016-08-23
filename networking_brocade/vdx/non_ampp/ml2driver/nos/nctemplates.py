# Copyright (c) 2016 Brocade Communications Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Authors:
# Varma Bhupatiraju (vbhupati@#brocade.com)
# Shiv Haris (sharis@brocade.com)


"""NOS NETCONF XML Configuration Command Templates.
Interface Configuration Commands
"""

# Get NOS Version
SHOW_FIRMWARE_VERSION = (
    "show-firmware-version xmlns:nc="
    "'urn:brocade.com:mgmt:brocade-firmware-ext'"
)

NOS_VERSION = "./*/{urn:brocade.com:mgmt:brocade-firmware-ext}os-version"

#
# L2 Forwarding Life-cycle Management Configuration Commands
#

CREATE_INTERFACE = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <port-channel>
        <name>{name}</name>
    </port-channel>
    </interface>
    </config>
"""

PORT_CHANNEL_SPEED = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <port-channel>
        <name>{name}</name>
        <po-speed>{po_speed}</po-speed>
    </port-channel>
    </interface>
    </config>
"""
PORT_CHANNEL_LB_MODE = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <port-channel>
        <name>{name}</name>
        <load-balance>{po_lb_mode}</load-balance>
    </port-channel>
    </interface>
    </config>
"""

ACTIVATE_INTERFACE = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <shutdown operation="delete"/>
    </{speed}>
    </interface>
    </config>
"""
REMOVE_CHANNEL_GROUP = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <channel-group  operation="delete">
        </channel-group>
    </{speed}>
    </interface>
    </config>
"""
CONFIGURE_CHANNEL_GROUP = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <channel-group>
            <port-int>{port}</port-int>
            <mode>{po_mode}</mode>
            <type>{po_type}</type>
        </channel-group>
    </{speed}>
    </interface>
    </config>
"""
CONFIGURE_INTERFACE_SWITCHPORT_V1 = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport-basic>
            <basic/>
        </switchport-basic>
    </{speed}>
    </interface>
    </config>
"""
REMOVE_INTERFACE_SWITCHPORT_V1 = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport-basic>
            <basic operation="delete"/>
        </switchport-basic>
    </{speed}>
    </interface>
    </config>
"""

REMOVE_PORT_PROFILE_PORT = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <port-profile-port xmlns="urn:brocade.com:mgmt:brocade-port-profile"
                                                        operation="delete"/>
    </{speed}>
    </interface>
    </config>

"""

CONFIGURE_MTU_ON_INTERFACE = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <mtu>{mtu}</mtu>
    </{speed}>
    </interface>
    </config>
"""

DELETE_MTU_ON_INTERFACE = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <mtu operation="delete"/>
    </{speed}>
    </interface>
    </config>
"""

CONFIGURE_INTERFACE_SWITCHPORT_V2 = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport>
            <basic/>
        </switchport>
    </{speed}>
    </interface>
    </config>
"""

REMOVE_INTERFACE_SWITCHPORT_V2 = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport>
            <basic operation="delete"/>
        </switchport>
    </{speed}>
    </interface>
    </config>
"""

CONFIGURE_INTERFACE_SWITCHPORT_TRUNK = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport>
                <mode>
                    <vlan-mode>trunk</vlan-mode>
                </mode>
        </switchport>
    </{speed}>
    </interface>
    </config>
"""

ADD_OR_REMOVE_VLAN_TO_INTERFACE = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport>
                <trunk>
                   <allowed>
                       <vlan>
                           <{action}>{vlan_id}</{action}>
                       </vlan>
                   </allowed>
                </trunk>
        </switchport>
    </{speed}>
    </interface>
    </config>
"""

ALLOW_UNTAG_TRAF_ON_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport>
                <trunk>
                   <tag>
                       <native-vlan  xc:operation="delete"/>
                   </tag>
                </trunk>
        </switchport>
    </{speed}>
    </interface>
    </config>
"""


ADD_NATIVE_VLAN_TO_INTERFACE = """
    <config>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport>
                <trunk>
                   <native-vlan-classification>
                       <native-vlan-id>{vlan_id}</native-vlan-id>
                   </native-vlan-classification>
                </trunk>
        </switchport>
    </{speed}>
    </interface>
    </config>
"""

REMOVE_NATIVE_VLAN_FROM_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
    <{speed}>
        <name>{name}</name>
        <switchport>
                <trunk>
                   <native-vlan-classification>
                       <native-vlan-id xc:operation="delete"/>
                   </native-vlan-classification>
                </trunk>
        </switchport>
    </{speed}>
    </interface>
    </config>
"""
# Create VLAN (vlan_id)
CREATE_VLAN_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface-vlan xmlns="urn:brocade.com:mgmt:brocade-interface">
            <interface>
                <vlan>
                    <name>{vlan_id}</name>
                </vlan>
            </interface>
        </interface-vlan>
    </config>
"""

# Delete VLAN (vlan_id)
DELETE_VLAN_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface-vlan xmlns="urn:brocade.com:mgmt:brocade-interface">
            <interface>
                <vlan operation="delete">
                    <name>{vlan_id}</name>
                </vlan>
            </interface>
        </interface-vlan>
    </config>
"""

#
# L3 Life-cycle Management Configuration Commands
#

# configure SVI (rbridge_id,vlan_id)
CONFIGURE_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""
# Create IP static routes (rbridge_id,vrf_name,destination_ip,next_hop)
CONFIGURE_VRF_IP_STATIC_ROUTE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <address-family xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <ip xmlns="urn:brocade.com:mgmt:brocade-vrf">
                        <unicast xmlns="urn:brocade.com:mgmt:brocade-vrf">
                            <ip xmlns="urn:brocade.com:mgmt:brocade-rtm">
                                <route>
                                    <static-route-nh>
                                        <static-route-dest>{destination_ip}</static-route-dest>
                                        <static-route-next-hop>{next_hop}</static-route-next-hop>
                                    </static-route-nh>
                                </route>
                            </ip>
                        </unicast>
                    </ip>
                </address-family>
            </vrf>
        </rbridge-id>
    </config>
"""
# Delete IP static routes (rbridge_id,vrf_name,destination_ip,next_hop)
DELETE_VRF_IP_STATIC_ROUTE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <address-family xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <ip xmlns="urn:brocade.com:mgmt:brocade-vrf">
                        <unicast xmlns="urn:brocade.com:mgmt:brocade-vrf">
                            <ip xmlns="urn:brocade.com:mgmt:brocade-rtm">
                                <route
                                     xmlns="urn:brocade.com:mgmt:brocade-rtm">
                                    <static-route-nh operation="delete"
                                         xmlns="urn:brocade.com:mgmt:brocade-rtm">
                                        <static-route-dest>{destination_ip}</static-route-dest>
                                        <static-route-next-hop>{next_hop}</static-route-next-hop>
                                    </static-route-nh>
                                </route>
                            </ip>
                        </unicast>
                    </ip>
                </address-family>
            </vrf>
        </rbridge-id>
    </config>
"""
# Create IP static routes (rbridge_id,destination_ip,next_hop)
CONFIGURE_IP_STATIC_ROUTE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <ip xmlns="urn:brocade.com:mgmt:brocade-rbridge">
                <rtm-config xmlns="urn:brocade.com:mgmt:brocade-rtm">
                    <route xmlns="urn:brocade.com:mgmt:brocade-rtm">
                        <static-route-nh
                             xmlns="urn:brocade.com:mgmt:brocade-rtm">
                            <static-route-dest>{destination_ip}</static-route-dest>
                            <static-route-next-hop>{next_hop}</static-route-next-hop>
                        </static-route-nh>
                    </route>
                </rtm-config>
            </ip>
         </rbridge-id>
    </config>
"""
# Delete IP static routes (rbridge_id,destination_ip,next_hop)
DELETE_IP_STATIC_ROUTE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <ip xmlns="urn:brocade.com:mgmt:brocade-rbridge">
                <rtm-config xmlns="urn:brocade.com:mgmt:brocade-rtm">
                    <route xmlns="urn:brocade.com:mgmt:brocade-rtm">
                        <static-route-nh operation="delete"
                             xmlns="urn:brocade.com:mgmt:brocade-rtm">
                            <static-route-dest>{destination_ip}</static-route-dest>
                            <static-route-next-hop>{next_hop}</static-route-next-hop>
                        </static-route-nh>
                    </route>
                </rtm-config>
            </ip>
         </rbridge-id>
    </config>
"""
# Create SVI and assign ippaddres (rbridge_id,vlan_id,ip_address)
CONFIGURE_SVI_WITH_IP_ADDRESS = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <ip xmlns="urn:brocade.com:mgmt:brocade-ip-config">
                        <ip-config>
                          <address>
                             <address>{ip_address}</address>
                          </address>
                        </ip-config>
                    </ip>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# delete SVI (rbridge_id,vlan_id)
DELETE_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve operation="delete">
                    <name>{vlan_id}</name>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# Activate SVI (rbridge_id,vlan_id)
ACTIVATE_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <shutdown xmlns="urn:brocade.com:mgmt:brocade-ip-config"
                                           xc:operation="delete"></shutdown>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# Remove ipaddress from SVI (rbridge_id,vlan_id)
DECONFIGURE_IP_FROM_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <ip xmlns="urn:brocade.com:mgmt:brocade-ip-config">
                        <ip-config>
                            <address xc:operation="delete">
                                <address>{gw_ip}</address>
                            </address>
                        </ip-config>
                    </ip>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# create vrf (rbridge_id,vrf_name)
CREATE_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
                <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <vrf-name>{vrf_name}</vrf-name>
                </vrf>
         </rbridge-id>
    </config>
"""


# delete vrf (rbridge_id,vrf_name)
DELETE_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
                <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf"
                                       xc:operation="delete">
                    <vrf-name>{vrf_name}</vrf-name>
                </vrf>
         </rbridge-id>
    </config>
"""

# configure route distinguisher for vrf (rbridge_id,vrf_name, rd)
CONFIGURE_RD_FOR_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <route-distiniguisher>{rd}</route-distiniguisher>
            </vrf>
         </rbridge-id>
    </config>
"""

# configure address-family for vrf (rbridge_id,vrf_name)
ADD_ADDRESS_FAMILY_FOR_VRF_V1 = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <address-family xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <ipv4>
                        <max-route>1200</max-route>
                    </ipv4>
                </address-family>
            </vrf>
         </rbridge-id>
    </config>
"""

# configure address-family for vrf (rbridge_id,vrf_name)
ADD_ADDRESS_FAMILY_FOR_VRF = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <vrf xmlns="urn:brocade.com:mgmt:brocade-vrf">
                <vrf-name>{vrf_name}</vrf-name>
                <address-family xmlns="urn:brocade.com:mgmt:brocade-vrf">
                    <ip>
                        <unicast/>
                    </ip>
                </address-family>
            </vrf>
         </rbridge-id>
    </config>
"""

# Bind vrf to SVI (rbridge_id,vlan_idi, vrf)
ADD_VRF_TO_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <vrf xmlns="urn:brocade.com:mgmt:brocade-ip-config">
                        <forwarding>{vrf_name}</forwarding>
                    </vrf>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# unbind  vrf from SVI (rbridge_id,vlan_idi, vrf)
DELETE_VRF_FROM_SVI = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
         <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
            <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
                <ve>
                    <name>{vlan_id}</name>
                    <vrf xmlns="urn:brocade.com:mgmt:brocade-ip-config"
                                                     operation="delete">
                        <forwarding>{vrf_name}</forwarding>
                    </vrf>
                </ve>
            </interface>
         </rbridge-id>
    </config>
"""

# Acl Policy Life cycle Management
REMOVE_ACL_POLICY = """
    <config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <ip-acl xmlns="urn:brocade.com:mgmt:brocade-ip-access-list">
            <ip>
                <access-list>
                    <extended nc:operation="delete">
                        <name>{acl_name}</name>
                    </extended>
                </access-list>
            </ip>
        </ip-acl>
    </config>
"""
IP_ACL_RULE_BULKING_START = """
        <config>
            <ip-acl xmlns="urn:brocade.com:mgmt:brocade-ip-access-list">
                <ip>
                    <access-list>
                        <extended>
                            <name>{name}</name>
                            <hide-ip-acl-ext>
"""
IP_ACL_RULE_BULKING_END = """
                            </hide-ip-acl-ext>
                        </extended>
                    </access-list>
                </ip>
            </ip-acl>
        </config>
"""


IP_ACL_RULE = """
                                <seq>
                                    <seq-id></seq-id>
                                    <action></action>
                                    <protocol-type></protocol-type>
                                    <src-host-any-sip></src-host-any-sip>
                                    <src-mask></src-mask>
                                    <dst-host-any-dip></dst-host-any-dip>
                                    <dst-mask></dst-mask>
                                    <sport></sport>
                                    <sport-number-eq-neq-tcp>
                                    </sport-number-eq-neq-tcp>
                                    <sport-number-eq-neq-udp>
                                    </sport-number-eq-neq-udp>
                                    <sport-number-range-lower-tcp>
                                    </sport-number-range-lower-tcp>
                                    <sport-number-range-higher-tcp>
                                    </sport-number-range-higher-tcp>
                                    <sport-number-range-lower-udp>
                                    </sport-number-range-lower-udp>
                                    <sport-number-range-higher-udp>
                                    </sport-number-range-higher-udp>
                                    <dport></dport>
                                    <dport-number-eq-neq-tcp>
                                    </dport-number-eq-neq-tcp>
                                    <dport-number-eq-neq-udp>
                                    </dport-number-eq-neq-udp>
                                    <dport-number-range-lower-tcp>
                                    </dport-number-range-lower-tcp>
                                    <dport-number-range-higher-tcp>
                                    </dport-number-range-higher-tcp>
                                    <dport-number-range-lower-udp>
                                    </dport-number-range-lower-udp>
                                    <dport-number-range-higher-udp>
                                    </dport-number-range-higher-udp>
                                    <dscp></dscp>
                                    <count></count>
                                    <log></log>
                                </seq>
"""
SVI_IP_ACL = """
    <config>
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
            <ve xmlns="urn:brocade.com:mgmt:brocade-interface">
                <name>{vlan_id}</name>
            <ip-acl-interface
                xmlns="urn:brocade.com:mgmt:brocade-ip-access-list">
                <ip xmlns="urn:brocade.com:mgmt:brocade-ip-access-list">
                    <access-group
                        xmlns="urn:brocade.com:mgmt:brocade-ip-access-list">
                        <ip-access-list>{name}</ip-access-list>
                        <ip-direction>{direction}</ip-direction>
                    </access-group>
                </ip>
            </ip-acl-interface>
            </ve>
        </interface>
        </rbridge-id>
    </config>
"""

REMOVE_SVI_IP_ACL = """
    <config>
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
            <rbridge-id>{rbridge_id}</rbridge-id>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
            <ve xmlns="urn:brocade.com:mgmt:brocade-interface">
                <name>{vlan_id}</name>
            <ip-acl-interface
                xmlns="urn:brocade.com:mgmt:brocade-ip-access-list">
                <ip xmlns="urn:brocade.com:mgmt:brocade-ip-access-list">
                    <access-group
                    xmlns="urn:brocade.com:mgmt:brocade-ip-access-list"
                    operation="delete">
                        <ip-access-list>{name}</ip-access-list>
                        <ip-direction>{direction}</ip-direction>
                    </access-group>
                </ip>
            </ip-acl-interface>
            </ve>
        </interface>
        </rbridge-id>
    </config>
"""

# L3 HA management commands
ENABLE_VRRP = """
    <config  xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
        <rbridge-id>{rbridge_id}</rbridge-id>
            <protocol xmlns="urn:brocade.com:mgmt:brocade-interface">
            <hide-vrrp-holder xmlns="urn:brocade.com:mgmt:brocade-vrrp">
                    <vrrp/>
                </hide-vrrp-holder>
        </protocol>
    </rbridge-id>
    </config>
"""

CONFIGURE_VRRP_GROUP = """
    <config>
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
    <rbridge-id>{rbridge_id}</rbridge-id>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
            <ve>
            <name>{vlan_id}</name>
            <vrrp xmlns="urn:brocade.com:mgmt:brocade-vrrp">
                <vrid>{vrid}</vrid>
                <version>{version}</version>
            </vrrp>
        </ve>
        </interface>
    </rbridge-id>
    </config>
"""


CONFIGURE_VRRP_VIP = """
    <config>
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
    <rbridge-id>{rbridge_id}</rbridge-id>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
            <ve>
            <name>{vlan_id}</name>
                <vrrp xmlns="urn:brocade.com:mgmt:brocade-vrrp">
                    <vrid>{vrid}</vrid>
                    <version>{version}</version>
                    <virtual-ip>
                        <virtual-ipaddr>{vip}</virtual-ipaddr>
                    </virtual-ip>
                </vrrp>
        </ve>
        </interface>
    </rbridge-id>
    </config>
"""

CONFIGURE_VRRP_PRIORITY = """
    <config>
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
    <rbridge-id>{rbridge_id}</rbridge-id>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
            <ve>
            <name>{vlan_id}</name>
            <vrrp xmlns="urn:brocade.com:mgmt:brocade-vrrp">
                <vrid>{vrid}</vrid>
                <version>{version}</version>
                <priority>{priority}</priority>
            </vrrp>
        </ve>
        </interface>
    </rbridge-id>
    </config>
"""

CONFIGURE_VRRP_ADVERTISEMENT_INTERVEL = """
    <config>
        <rbridge-id xmlns="urn:brocade.com:mgmt:brocade-rbridge">
    <rbridge-id>{rbridge_id}</rbridge-id>
        <interface xmlns="urn:brocade.com:mgmt:brocade-interface">
            <ve>
            <name>{vlan_id}</name>
                <vrrp xmlns="urn:brocade.com:mgmt:brocade-vrrp">
                <vrid>{vrid}</vrid>
                <version>{version}</version>
                <advertisement-interval>{advt_int}</advertisement-interval>
            </vrrp>
        </ve>
        </interface>
    </rbridge-id>
    </config>
"""


# Constants
#

# Constants
#
# ip acl naming convention
ROUTER_OBJ_PREFIX = 'openstack-acl-'

# vrf naming convention
OS_VRF_NAME = "openstack-vrf-{id}"

BAD_ELE = "bad-element"
IP_ACL_APPLIED = "SSM_DCM_ERR_IP_ACL_APPLIED"

SEQ_ID_EXISTS = "/ip-acl/ip/access-list/extended[name='{name}']/hide-ip-acl-"\
                "ext/seq [seq-id='{id}']"

IP_ACL_NAME_XPATH_FILTER = "/ip-acl/ip/access-list/extended[name='{name}']/"\
                           "name"

ACL_ON_SVIS_XPATH_FILTER = "/rbridge-id[rbridge-id='{rbridge_id}']/interface/"\
                           "ve/ip-acl-interface/ip/access-group/ip-access-list"

ACL_ON_SVI_XPATH_FILTER = "/rbridge-id[rbridge-id='{rbridge_id}']/interface/"\
                          "ve[name='{svi}']/ip-acl-interface/ip/access-group/"\
                          "ip-access-list"

SVI_STATUS_XPATH_FILTER = "/rbridge-id[rbridge-id='{rbridge_id}']/interface/"\
    "ve[name='{name}']/shutdown"

INTERFACE_XPATH_FILTER = "/interface/{speed}[name='{name}']/name"

SVI_EXISTS_XPATH_FILTER = "/rbridge-id[rbridge-id='{rbridge_id}']/interface/"\
                          "ve[name='{name}']/name"

INTERFACE_STATUS_XPATH_FILTER = "/interface/{speed}[name='{name}']/shutdown"

INTERFACE_PP_STATUS_XPATH_FILTER = "/interface/{speed}[name='{name}']/*"\
    "[local-name()='port-profile-port']"
INTERFACE_CG_STATUS_XPATH_FILTER = "/interface/{speed}[name='{name}']/*"\
    "[local-name()='channnel-group']"
