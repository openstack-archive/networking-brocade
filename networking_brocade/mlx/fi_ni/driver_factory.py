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
#

"""
Returns the driver based on the firmware version of the device
"""

from neutron.i18n import _LI
from neutron.openstack.common import log as logging
from oslo_utils import importutils

LOG = logging.getLogger(__name__)
CONNECTION_FACTORY = ("neutron.plugins.ml2.drivers.brocade.connector_factory."
    "ConnectorFactory")
FI = "neutron.plugins.ml2.drivers.brocade.fi_ni.fi_driver.FastIronDriver"
NI = "neutron.plugins.ml2.drivers.brocade.fi_ni.ni_driver.NetIronDriver"
NETIRON = "NetIron"
FASTIRON = "ICX"


class BrocadeDriverFactory(object):

    """
    Factory class that decides which driver to use based on the
    device type. It uses FastIron driver for ICX devices and
    NetIron driver for MLX devices
    """

    def get_driver(self, device):
        """
        Returns the driver based on the firmware.
        """

        connector = importutils.import_object(CONNECTION_FACTORY
                                              ).get_connector(device)
        connector.connect()
        version = connector.get_version()
        connector.close_session()
        driver = None
        if NETIRON in version:
            LOG.info(
                _LI("OS Type of the device %(host)s is as NetIron"), {
                    'host': device.get('address')
                })
            driver = importutils.import_object(NI, device)
        elif FASTIRON in version:
            LOG.info(
                _LI("OS Type of the device %(host)s is as FastIron"), {
                    'host': device.get('address')
                })
            driver = importutils.import_object(FI, device)
        else:
            raise Exception("Unsupported firmware")

        return driver
