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
#

"""
Returns the driver based on the firmware version of the device
"""
from neutron.i18n import _LE
from neutron.i18n import _LI
from oslo_log import log as logging
from oslo_utils import importutils

LOG = logging.getLogger(__name__)
CONNECTION_FACTORY = ("networking_brocade.mlx.ml2.connector_factory."
                      "ConnectorFactory")
FI_DRIVER = "networking_brocade.mlx.ml2.fi_ni.fi_driver.FastIronDriver"
NI_DRIVER = "networking_brocade.mlx.ml2.fi_ni.ni_driver.NetIronDriver"
NETIRON = "NetIron"
FASTIRON = "ICX"
FI = "FI"
NI = "NI"


class BrocadeDriverFactory(object):

    """
    Factory class that decides which driver to use based on the
    device type. It uses FastIron driver for ICX devices and
    NetIron driver for MLX devices
    """

    def get_driver(self, device):
        """
        Returns the driver based on the firmware.

        :param:device: A dictionary which has the device details
        :returns: Appropriate driver for the device based on the firmware
            version, None otherwise
        :raises: Exception
        """
        driver = None
        address = device.get('address')
        os_type = device.get('ostype')
        if os_type == FI:
            driver = importutils.import_object(FI_DRIVER, device)
        elif os_type == NI:
            driver = importutils.import_object(NI_DRIVER, device)
        else:
            connector = importutils.import_object(CONNECTION_FACTORY
                                                  ).get_connector(device)
            connector.connect()
            version = connector.get_version()
            connector.close_session()
            if NETIRON in version:
                LOG.info(
                    _LI("OS Type of the device %(host)s is as NetIron"),
                    {'host': address})
                driver = importutils.import_object(NI_DRIVER, device)
                device.update({'ostype': NI})
            elif FASTIRON in version:
                LOG.info(
                    _LI("OS Type of the device %(host)s is as FastIron"),
                    {'host': device.get('address')})
                driver = importutils.import_object(FI_DRIVER, device)
                device.update({'ostype': FI})
            else:
                LOG.exception(_LE("Brocade Driver Factory: failed to "
                                  "identify device type for device="
                                  "%(device)s"), {'device': address})

                raise Exception("Unsupported firmware %(firmware)s for device "
                                "%(host)s", {'firmware': version,
                                             'host': address})

        return driver
