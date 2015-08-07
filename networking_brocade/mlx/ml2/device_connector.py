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
    Connector class used to connect to device.
    Decides which connector to use - TELNET or SSH, based on
    the argument passed
"""
from networking_brocade.mlx.ml2 import commands
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class DeviceConnector(object):

    """
    Connector class used to connect to device.
    Decides which connector to use - TELNET or SSH, based on
    the argument passed
    """

    def __init__(self, device_info):
        self.host = device_info.get('address')
        self.username = device_info.get('username')
        self.password = device_info.get('password')
        self.enable_username = device_info.get('enable_username')
        self.enable_password = device_info.get('enable_password')
        self.transport = device_info.get('transport')

    def create_vlan(self, vlanid, ports):
        """
        Creates VLAN and tags the ports to the created VLAN
        :param:vlanid: vlan id to be created
        :param:ports: ports to be tagged to the created vlan
        :returns: Response from the device as a list
        """
        LOG.debug("DeviceConnector:create_vlan:Creating vlan %(vlanid)s on "
                  "device %(host)s", {'vlanid': vlanid, 'host': self.host})
        self.enter_configuration_mode()
        self.write(
            commands.CONFIGURE_VLAN.format(
                vlan_id=vlanid))
        LOG.debug(
            "Created VLAN with id %(vlanid)s on device %(host)s", {
                'vlanid': vlanid, 'host': self.host})
        for port in ports:
            self.tag_port(port)
            LOG.debug("tagged port %(port)s", {'port': port})
        return self.read_response()

    def tag_port(self, port):
        """Tag Ports to the vlan

        :param:port: Port to be tagged to the vlan
        """
        LOG.debug("DeviceConnector:tag_port:Tagging port %(portid)s on device"
                  " %(host)s", {'portid': port, 'host': self.host})
        self.write(
            commands.CONFIGURE_ETHERNET.format(
                port_number=port))

    def delete_vlan(self, vlan_id):
        """Deletes the VLAN from the device

        :param:vlan_id: vlan id to be deleted
        :returns: Response from the device as a list
        """
        LOG.debug("DeviceConnector:delete_vlan:Deleting VLAN with id "
                  "%(vlan_id)s on device %(host)s", {'vlan_id': vlan_id,
                                                     'host': self.host})
        self.enter_configuration_mode()
        self.write(
            commands.DELETE_CONFIGURED_VLAN.format(
                vlan_id=vlan_id))
        LOG.debug(
            "Deleted VLAN with id %(vlan_id)s on device %(host)s", {
                'vlan_id': vlan_id, 'host': self.host})
        return self.read_response()

    def get_version(self):
        """Get Firmware Version

        :returns: Response from the device as a string
        """
        LOG.debug("DeviceConnector:get_version:Executing show version for "
                  "device %(host)s", {'host': self.host})
        self.write(commands.SHOW_VERSION)
        self.write(commands.CTRL_C)
        return self.read_response()

    def create_l3_router(self, vlan_id, gateway_ip_cidr):
        """Configures a Router Interface interface

        :param:vlan_id: vlan id to which the created router interface will
            be part of
        :param:gateway_ip_cidr: Gateway IP address with network length.
        :returns: Response from the device as a list
        """

        self.enter_configuration_mode()
        LOG.debug(("DeviceConnector:create_l3_router:Configuring router "
                   "interface with id %(vlanid)s on device %(host)s"),
                  {'vlanid': vlan_id, 'host': self.host})
        self._create_router_interface(vlan_id)
        self._configure_ipaddress(vlan_id, gateway_ip_cidr)
        LOG.debug(("DeviceConnector:create_l3_router:Configured router "
                   "interface with id %(vlanid)s on device %(host)s"),
                  {'vlanid': vlan_id, 'host': self.host})
        return self.read_response()

    def _create_router_interface(self, vlan_id):
        """Create VLAN and Router Interface

        :param:vlan_id: vlan id to which the created router interface will
            be part of
        """
        LOG.debug("DeviceConnector:_create_router_interface:Creating l3 "
                  "router interface %(vlanid)s on device "
                  "%(host)s", {'vlanid': vlan_id,
                               'host': self.host})
        self.write(
            commands.CONFIGURE_VLAN.format(
                vlan_id=vlan_id))
        self.write(
            commands.CONFIGURE_ROUTER_INTERFACE.format(
                vlan_id=vlan_id))
        LOG.debug("DeviceConnector:_create_router_interface:Created l3 "
                  "router interface %(vlanid)s on device "
                  "%(host)s", {'vlanid': vlan_id,
                               'host': self.host})

    def _configure_ipaddress(self, vlan_id, gateway_ip_cidr):
        """Assigns Gateway ip for the configured vlan

        :param:vlan_id: vlan id to which the created router interface will
            be part of
        :param:gateway_ip_cidr: Gateway IP address with network length.
        """
        LOG.debug("DeviceConnector:_configure_ipaddress:Assigning IP address"
                  " %(ipaddr)s to the router interface %(vlanid)s on device"
                  " %(host)s", {'ipaddr': gateway_ip_cidr,
                                'vlanid': vlan_id,
                                'host': self.host})
        self.write(
            commands.CONFIGURE_INTERFACE.format(
                vlan_id=vlan_id))
        self.write(
            commands.CONFIGURE_GATEWAY_IP.format(
                gateway_ip_addr=gateway_ip_cidr))
        LOG.debug("DeviceConnector:_configure_ipaddress:Assigned IP address"
                  " %(ipaddr)s to the router interface %(vlanid)s on device"
                  " %(host)s", {'ipaddr': gateway_ip_cidr,
                                'vlanid': vlan_id,
                                'host': self.host})

    def delete_l3_router(self, vlan_id):
        """
        Deletes Router Interface with the vlan id

        :param:vlan_id: vlan id to which the created router interface will
            be part of
        :returns: Response from the device as a list
        """

        self.enter_configuration_mode()

        LOG.debug(("DeviceConnector:delete_l3_router:Deleting router interface"
                   " %(vlan_id)s from vlan %(vlan_id)s on device %(host)s"),
                  {'vlan_id': vlan_id, 'host': self.host})
        self.write(
            commands.CONFIGURE_VLAN.format(vlan_id=vlan_id))
        self.write(
            commands.DELETE_ROUTER_INTERFACE.format(
                vlan_id=vlan_id))

        LOG.debug(("DeviceConnector:delete_l3_router:Deleted router interface"
                   " %(vlan_id)s from vlan %(vlan_id)s on device %(host)s"),
                  {'vlan_id': vlan_id, 'host': self.host})

        return self.read_response()
