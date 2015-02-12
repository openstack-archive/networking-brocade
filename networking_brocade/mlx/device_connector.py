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

from neutron.openstack.common import log as logging
import neutron.plugins.ml2.drivers.brocade.commands as Commands

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
        self.transport = device_info.get('transport')

    def enter_configuration_mode(self):
        """
        Enter configuration mode. First it enters enable mode
        and then to configuration mode. There should be no
        Enable password.
        """

        self.write(Commands.ENABLE_TERMINAL_CMD)
        self.write(Commands.CONFIGURE_TERMINAL_CMD)

    def exit_configuration_mode(self):
        """
        Exit Configuration mode.
        """
        self.send_exit(2)

    def exit_from_device(self):
        """
        Exit Configuration mode and device.
        """
        self.exit_configuration_mode()
        self.send_exit(1)

    def create_vlan(self, vlanid, ports):
        """
        Creates VLAN and tags the ports to the created VLAN.
        """
        self.enter_configuration_mode()
        self.write(
            Commands.CONFIGURE_VLAN.format(
                vlan_id=vlanid))
        LOG.debug(
            "Created VLAN with id %(vlanid)s on device %(host)s", {
                'vlanid': vlanid, 'host': self.host})
        for port in ports:
            self.tag_port(port)
            LOG.debug("tagged port %(port)s", {'port': port})
        self.send_exit(1)
        self.exit_from_device()
        return self.read_response()

    def tag_port(self, port):
        """Tag Ports."""
        self.write(
            Commands.CONFIGURE_ETHERNET.format(
                port_number=port))

    def delete_vlan(self, vlan_id):
        """
        Deletes the VLAN
        """
        self.enter_configuration_mode()
        self.write(
            Commands.DELETE_CONFIGURED_VLAN.format(
                vlan_id=vlan_id))
        LOG.debug(
            "Deleted VLAN with id %(vlan_id)s on device %(host)s", {
                'vlan_id': vlan_id, 'host': self.host})
        self.exit_from_device()
        return self.read_response()

    def get_version(self):
        """Get Firmware Version."""
        self.write(Commands.SHOW_VERSION)
        self.write(Commands.CTRL_C)
        self.send_exit(1)
        return self.read_response(read_lines=False)
