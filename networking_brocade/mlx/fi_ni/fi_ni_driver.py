# Copyright 2014 Brocade Communications System, Inc.
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
Ethernet Driver
"""

from oslo_utils import importutils

CONNECTION_FACTORY = ("neutron.plugins.ml2.drivers.brocade.connector_factory."
    "ConnectorFactory")
ERROR = "Invalid input"


class FiNiDriver(object):

    """
    Base Ethernet Driver which handles all common CLI Commands
    """

    def __init__(self, device):
        self.device = device

    def create_network(self, vlan_id, ports):
        """
        Invoked when user creates a VLAN network. Triggers creation of
        VLAN on the devices listed in the configuration template
        """

        connector = importutils.import_object(
                                CONNECTION_FACTORY).get_connector(self.device)
        connector.connect()
        response = connector.create_vlan(vlan_id, ports)
        if is_error(response):
            raise Exception("Ethernet Driver : Invalid Input - "
                            "Create network failed")
        connector.close_session()

    def delete_network(self, vlan_id):
        """
        Invoked when user deletes a VLAN network. Triggers deletion of
        VLAN on the devices listed in the configuration template
        """

        connector = importutils.import_object(
                                CONNECTION_FACTORY).get_connector(self.device)
        connector.connect()
        connector.delete_vlan(vlan_id)
        connector.close_session()


def is_error(response_list):
    """
    Checks for error in response
    """
    error = False
    for response in response_list:
        if ERROR in response:
            error = True
            break
    return error
