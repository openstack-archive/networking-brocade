# Copyright 2015 Brocade Communications System, Inc.
# All rights reserved.
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

"""
Constants used by device_connector
"""

ENABLE_TERMINAL_CMD = "en\r"
CONFIGURE_TERMINAL_CMD = "conf t\r"
CONFIGURE_VLAN = "vlan {vlan_id}\r"
CONFIGURE_ETHERNET = "tagged ethe {port_number}\r"
DELETE_CONFIGURED_VLAN = "no vlan {vlan_id}\r"
EXIT = "exit\r"
SHOW_VERSION = "show version\r"
CTRL_C = '\x03'

"""
Constants used by ni_driver
"""
CONFIGURE_ROUTER_INTERFACE = "router-interface ve {vlan_id}\r"
CONFIGURE_INTERFACE = "interface ve {vlan_id}\r"
CONFIGURE_GATEWAY_IP = "ip address {gateway_ip_addr}\r"
DELETE_ROUTER_INTERFACE = "no router-interface ve {vlan_id}\r"
