# Copyright 2015 Brocade Communications Systems, Inc.
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
Common driver for both FI and NI devices
"""

from oslo_log import log as logging
from oslo_utils import importutils

CONNECTION_FACTORY = ("networking_brocade.mlx.ml2.connector_factory."
                      "ConnectorFactory")
INVALID_INPUT = "Invalid input"
RANGE_ERROR = "outside of allowed max"
ERROR = "Error"
DUPLICATE_IP = "Error: Duplicate ip address"

LOG = logging.getLogger(__name__)


class FiNiDriver(object):

    """
    Base driver which handles all common CLI Commands for both FI and NI
    devices
    """

    def __init__(self, device):
        self.device = device

    def create_network(self, vlan_id, ports):
        """
        Invoked when user creates a VLAN network. Triggers creation of
        VLAN on the devices listed in the configuration template

        :param:vlan_id: vlan id to add
        :param:ports: ports to be tagged to the above vlan id
        :raises: Exception
        """

        connector = importutils.import_object(
            CONNECTION_FACTORY).get_connector(self.device)
        connector.connect()
        response = connector.create_vlan(vlan_id, ports)
        msg = self.get_error_msg(response)
        if msg:
            raise Exception(reason=msg)
        connector.close_session()

    def delete_network(self, vlan_id):
        """
        Invoked when user deletes a VLAN network. Triggers deletion of
        VLAN on the devices listed in the configuration template

        :param:vlan_id: vlan id to delete
        """

        connector = importutils.import_object(
            CONNECTION_FACTORY).get_connector(self.device)
        connector.connect()
        connector.delete_vlan(vlan_id)
        connector.close_session()

    def add_router_interface(self, vlan_id, gateway_ip_cidr):
        """
        Invoked when user creates router interface. Triggers creation of
        router interface based on the VLAN ID.

        :param:vlan_id: vlan id to which the created router interface will
            be part of
        :param:gateway_ip_cidr: Gateway IP address with network length.
        :raises: Exception
        """
        connector = importutils.import_object(
            CONNECTION_FACTORY).get_connector(self.device)
        connector.connect()
        response = connector.create_l3_router(vlan_id, gateway_ip_cidr)
        msg = self.get_error_msg(response)
        if msg:
            raise Exception(reason=msg)
        connector.close_session()

    def remove_router_interface(self, vlan_id):
        """
        Invoked when user deletes router interface. Triggers deletion of
        router interface based on the VLAN ID.

        :param:vlan_id: vlan id to which the router interface is part of
        :raises: Exception
        """
        connector = importutils.import_object(
            CONNECTION_FACTORY).get_connector(self.device)
        connector.connect()
        response = connector.delete_l3_router(vlan_id)
        msg = self.get_error_msg(response)
        if msg:
            raise Exception(reason=msg)
        connector.close_session()

    def get_error_msg(self, response_list):
        """
        Checks for error in response

        :param:response_list: List of response from device
        :returns:msg - Message will contain error description in case of an
            error, None otherwise.
        """
        msg = None
        for response in response_list:
            if INVALID_INPUT in response:
                msg = _("Ethernet Driver : Create"
                        "network failed: error= Invalid Input")
                LOG.error(msg)
                break
            elif RANGE_ERROR in response_list:
                msg = _("Configuring router interface failed: "
                        "ve out of range error")
                LOG.error(msg)
                break
            elif ERROR in response_list:
                msg = _("Configuring router interface failed: "
                        "vlan not associated to router interface")
                LOG.error(msg)
                break
        return msg
