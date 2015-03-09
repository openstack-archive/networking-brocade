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
Driver to interact with fastiron devices. Currently has no specific
implementations. Refer EthernetDriver
"""

from networking_brocade.mlx.ml2.fi_ni.fi_ni_driver import FiNiDriver


class FastIronDriver(FiNiDriver):

    """
    Driver to interact with fastiron devices. Currently has no specific
    implementations. Refer EthernetDriver
    """

    def __init__(self, device):
        super(FastIronDriver, self).__init__(device)

    def create_l3_router(self, vlan_id, gateway_ip_cidr):
        """
        Create router interface.

        :param:vlan_id: vlan id to which the created router interface will
            be part of
        :param:gateway_ip_cidr: Gateway IP address with network length.
        :raises: Exception
        """
        raise Exception("create_l3_router - This operation is currently not"
                        " supported in this platform ")

    def delete_l3_router(self, vlan_id):
        """
        Remove router interface.

        :param:vlan_id: vlan id to which the router interface is part of
        :raises: Exception
        """
        raise Exception("delete_l3_router - This operation is currently not"
                        " supported in this platform ")
