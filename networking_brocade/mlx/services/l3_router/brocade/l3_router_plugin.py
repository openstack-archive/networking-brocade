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
#


"""Implementation of Brocade L3RouterPlugin for NI devices."""

from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.plugins.ml2.driver_context import NetworkContext
from neutron.services.l3_router import l3_router_plugin as router
from oslo_log import log as logging
from oslo_utils import importutils

LOG = logging.getLogger(__name__)
NI = "networking_brocade.mlx.ml2.fi_ni.ni_driver.NetIronDriver"
BROCADE_CONFIG = ("networking_brocade.mlx.ml2.fi_ni.brcd_config."
                  "ML2BrocadeConfig")
DRIVER_FACTORY = ("networking_brocade.mlx.ml2.fi_ni."
                  "driver_factory.BrocadeDriverFactory")
# Property to identify which device type to use
# Currently supports only NI devices. If FI devices needs to be
# supported add FI to the list as shown below:
# ['NI', 'FI']
ROUTER_DEVICE_TYPE = ['NI']


class BrocadeRouterPlugin(router.L3RouterPlugin):

    """
    SVI Mechanism driver for Brocade ICX and MLX devices. This will take care
    of Create/Delete router interface to introduce L3 support.
    """

    def __init__(self):
        """Initialize Brocade Plugin

        Specify switch address and db configuration.
        """
        self._devices = {}
        self._physical_networks = {}
        self._driver_map = {}
        super(BrocadeRouterPlugin, self).__init__()
        self.brocade_init()

    def brocade_init(self):
        """Brocade specific initialization. Parses the configuration template
        and stores all the device information in a dictionary. Then it filters
        the router devices from it.
        """
        LOG.debug("BrocadeRouterPlugin::brocade_init()")

        self._devices, self._physical_networks = importutils.import_object(
            BROCADE_CONFIG).create_brocade_dictionary(isL2=False)

    def add_router_interface(self, context, router_id, interface_info):
        """Adds router interface to a vlan on NI device and assigns ip
         address to configure l3 router interface.
        """

        return self.add_remove_router_interface(context, router_id,
                                         interface_info,
                                         True)

    def remove_router_interface(self, context, router_id, interface_info):
        """Removes router interface on NI device
        """
        return self.add_remove_router_interface(context, router_id,
                                                interface_info,
                                                False)

    def add_remove_router_interface(self, context, router_id, interface_info,
                                    is_add):
        """
        Add/Remove router interface on NI device

        :param:context: Contains the network details
        :param:router_id: The router ID
        :param:interface_info: Contains interface details
        :param:is_add: True for add operation, False for remove operation.
        :raises: Exception
        """
        operation = None
        method = None
        if is_add is True:
            method = "add_router_interface"
            operation = "Add"
        else:
            method = "remove_router_interface"
            operation = "Remove"
        info = getattr(super(BrocadeRouterPlugin, self),
                       method)(context, router_id, interface_info)
        interface_info = info
        subnet = self._core_plugin._get_subnet(context.elevated(),
                                               interface_info["subnet_id"])
        vlan_id, gateway_ip_cidr = self._get_network_info(context, subnet)
        for device in self._devices:
            device_info = self._devices.get(device)
            address = device_info.get('address')
            driver = self._get_driver(device)
            LOG.info(_LI("BrocadeRouterPlugin:Before %(op)s l3 "
                         "router to vlan %(vlan_id)s with ip %(gatewayip)s"
                         "on device "
                         "%(host)s"), {'op': operation,
                                       'vlan_id': vlan_id,
                                       'gatewayip': gateway_ip_cidr,
                                       'host': address})
            try:
                if is_add is True:
                    getattr(driver, method)(vlan_id, gateway_ip_cidr)
                else:
                    getattr(driver, method)(vlan_id)
            except Exception as e:
                if is_add:
                    method = "remove_router_interface"
                    info = getattr(super(BrocadeRouterPlugin, self),
                                   method)(context, router_id, interface_info)
                LOG.exception(_LE("BrocadeRouterPlugin: failed to"
                                  " %(op)s l3 router interface for "
                                  "device= %(device)s exception : "
                                  "%(error)s"), {'op': operation,
                                                 'device': address,
                                                 'error': e.args})
                raise Exception(
                    _("BrocadeRouterPlugin: %(op)s router "
                      "interface failed"), {'op': operation})
            LOG.info(_LI("BrocadeRouterPlugin:%(op)sed router "
                         "interface in vlan = %(vlan_id)s with ip address"
                         " %(gatewayip)s on device %(host)s "
                         "successful"), {'op': operation,
                                         'vlan_id': vlan_id,
                                         'gatewayip': gateway_ip_cidr,
                                         'host': address})
        return info

    def _get_driver(self, device):
        """
        Gets the driver based on the firmware version of the device.

        :param:device: Contains device name
        :raises: Exception
        """
        driver = self._driver_map.get(device)
        if driver is None:
            driver_factory = importutils.import_object(DRIVER_FACTORY)
            device_info = self._devices.get(device)
            address = device_info.get('address')
            os_type = device_info.get('ostype')
            try:
                driver = driver_factory.get_driver(device_info)
                if driver is not None and os_type in ROUTER_DEVICE_TYPE:
                    self._driver_map.update({device: driver})
            except Exception as e:
                LOG.exception(_LE("BrocadeRouterPlugin:"
                                  "_filter_router_devices: Error while getting"
                                  " driver : device - %(host)s: %(error)s"),
                              {'host': address, 'error': e.args})
                raise Exception(_("BrocadeRouterPlugin:"
                                  "_filter_router_devices failed for "
                                  "device %(host)s"), {'host': address})
        return driver

    def _get_network_info(self, context, subnet):
        """
        Gets the network info from the context and brocade db

        :param:context: Contains the network details
        :param:subnet: Contains the subnet details
        :returns:vlan_id - VLAN ID of the network
        :returns:gateway_ip_cidr - Gateway IP address with network length.
            Example: 1.1.1.1/24
        """
        cidr = subnet["cidr"]
        net_addr, net_len = self.net_addr(cidr)
        gateway_ip = subnet["gateway_ip"]
        network_id = subnet['network_id']
        ml2_db = NetworkContext(self, context, {'id': network_id})
        vlan_id = ml2_db.network_segments[0]['segmentation_id']
        gateway_ip_cidr = gateway_ip + '/' + str(net_len)

        return vlan_id, gateway_ip_cidr

    @staticmethod
    def net_addr(addr):
        """Get network address prefix and length from a given address."""
        if addr is None:
            return None, None
        nw_addr, nw_len = addr.split('/')
        nw_len = int(nw_len)
        return nw_addr, nw_len
