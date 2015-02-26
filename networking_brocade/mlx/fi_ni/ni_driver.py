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
Driver to interact with netiron devices. Currently has no specific
implementations. Refer EthernetDriver
"""

from neutron.plugins.ml2.drivers.brocade.fi_ni.fi_ni_driver import FiNiDriver


class NetIronDriver(FiNiDriver):

    """
    Driver to interact with netiron devices. Currently has no specific
    implementations. Refer EthernetDriver
    """

    def __init__(self, device):
        super(NetIronDriver, self).__init__(device)
