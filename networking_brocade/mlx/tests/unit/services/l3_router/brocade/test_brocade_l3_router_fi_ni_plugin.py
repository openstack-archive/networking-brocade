# Copyright 2015 Brocade Communications Systems, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import mock
from networking_brocade.mlx.services.l3_router.brocade import (
    l3_router_fi_ni_plugin as brocadel3routerfiniplugin)
from neutron import context
from neutron.db import l3_db
from neutron.i18n import _LE
from neutron.services.l3_router import l3_router_plugin as router
from neutron.tests import base
from oslo_utils import importutils


MECHANISM_NAME = ('networking_brocade.mlx.services.l3_router.brocade.'
                  'l3_router_fi_ni_plugin.BrocadeFiNiL3RouterPlugin')
VE = 've '
config_map = {}
device_map = {
    'mlx': {
        'address': '2.2.2.2',
        'username': 'admin',
        'password': 'pass',
        'physical_networks': 'physnet1',
        'ports': '2/1,2/2',
        'os_type': 'NI'
    }
}
add_config_map = {
    '2.2.2.2': {
        '402': {'ve 402': '12.0.0.1/24'
                }
    }
}

delete_config_map = {
    '2.2.2.2': {
        '402': {}
    }
}

vlan_id = '402'
gateway_ip_cidr = '12.0.0.1/24'
ROUTER = 'router1'
SUBNET = 'subnet1'
PORT = 'port1'

INVALID_INPUT = "Invalid input"
RANGE_ERROR = "outside of allowed max"


class TestBrocadeL3RouterFiNiPlugin(base.BaseTestCase,
                                    router.L3RouterPlugin):

    """
    Test Brocade L3 Router FI/NI plugin.
    """

    def setUp(self):
        _mechanism_name = MECHANISM_NAME

        def mocked_initialize(self):
            self._router_devices_map = device_map
            self._driver_map = {'mlx': FakeDriver(device_map.get('mlx'))}

        with mock.patch.object(brocadel3routerfiniplugin
                               .BrocadeFiNiL3RouterPlugin,
                               'brocade_init', new=mocked_initialize):
            super(TestBrocadeL3RouterFiNiPlugin, self).setUp()
            self.interface_info = {'subnet_id': SUBNET,
                                   'port_id': PORT}
            self.driver = importutils.import_object(_mechanism_name)

    @mock.patch.object(
        brocadel3routerfiniplugin.BrocadeFiNiL3RouterPlugin,
        '_get_network_info')
    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_core_plugin')
    @mock.patch.object(router.L3RouterPlugin,
                       'add_router_interface')
    def test_add_router_interface(
            self, mock_super, mock_core_plugin, mock_network_info):

        mech_ctx = _get_network_context('physnet1', 'vlan')
        ctx = mech_ctx._plugin_context
        ctx.session.begin = mock.MagicMock()
        mock_super.returnValue = self.interface_info
        mock_core_plugin.side_effect = mock.MagicMock()
        mock_network_info.side_effect = side_effect_network_info
        self.driver.add_router_interface(ctx, ROUTER,
                                         self.interface_info)
        global config_map
        self.assertDictSupersetOf(config_map, add_config_map)

    @mock.patch.object(
        brocadel3routerfiniplugin.BrocadeFiNiL3RouterPlugin,
        '_get_network_info')
    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_core_plugin')
    @mock.patch.object(router.L3RouterPlugin, 'remove_router_interface')
    def test_remove_router_interface(
            self, mock_super, mock_core_plugin, mock_network_info):
        mech_ctx = _get_network_context('physnet1', 'vlan')
        ctx = mech_ctx._plugin_context
        ctx.session.begin = mock.MagicMock()
        mock_super.returnValue = self.interface_info
        mock_core_plugin.side_effect = mock.MagicMock()
        mock_network_info.side_effect = side_effect_network_info
        self.driver.remove_router_interface(ctx, ROUTER,
                                            self.interface_info)
        global config_map
        self.assertDictSupersetOf(config_map, delete_config_map)


class TestBrocadeL3RouterFiNiPluginException(base.BaseTestCase,
                                             router.L3RouterPlugin):

    """
    Test Brocade L3 Router FI/NI plugin for negative scenario
    """

    def setUp(self):
        _mechanism_name = MECHANISM_NAME

        def mocked_initialize(self):
            self._router_devices_map = device_map
            self._driver_map = {
                'mlx': FakeDriver(
                    device_map.get('mlx'),
                    error=True)}

        with mock.patch.object(brocadel3routerfiniplugin
                               .BrocadeFiNiL3RouterPlugin,
                               'brocade_init', new=mocked_initialize):
            super(TestBrocadeL3RouterFiNiPluginException, self).setUp()
            self.interface_info = {'subnet_id': SUBNET,
                                   'port_id': PORT}
            self.driver = importutils.import_object(_mechanism_name)

    @mock.patch.object(
        brocadel3routerfiniplugin.BrocadeFiNiL3RouterPlugin,
        '_get_network_info')
    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_core_plugin')
    @mock.patch.object(router.L3RouterPlugin, 'add_router_interface')
    def test_add_router_interface_exception(
            self, mock_super, mock_core_plugin, mock_network_info):

        mech_ctx = _get_network_context('physnet1', 'vlan')
        ctx = mech_ctx._plugin_context
        ctx.session.begin = mock.MagicMock()
        mock_super.returnValue = self.interface_info
        mock_core_plugin.side_effect = mock.MagicMock()
        mock_network_info.side_effect = side_effect_network_info
        self.assertRaisesRegexp(
            Exception, (_LE("BrocadeFiNiL3RouterPlugin")),
            self.driver.add_router_interface,
            ctx, ROUTER, self.interface_info)


def _get_network_context(physnet, network_type):
    """
    Create mock network context
    """
    network = {
        'id': 1,
        'name': 'private',
        'tenant_id': 1,
        'vlan': 200,
        'network_type': network_type,
        'provider:segmentation_id': 200
    }

    network_segments = [{
        'id': 1,
        'segmentation_id': 200,
        'network_type': network_type,
        'physical_network': physnet
    }]

    _plugin_context = context.get_admin_context()
    return FakeNetworkContext(network, network_segments, _plugin_context)


def side_effect_network_info(vlan, ip):
    """
    Mock _get_driver method and return FakeDriver
    """

    return vlan_id, gateway_ip_cidr


class FakeNetworkContext(object):

    """To generate network context for testing purposes only."""

    def __init__(self, network, segments=None, original_network=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments

    @property
    def current(self):
        return self._network

    @property
    def _plugin_context(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class FakeDriver(object):

    """
    Fake driver which will implement create and delete
    network. Create network will update the global dictionary with
    the address of the device along with vlan and ports to be tagged.
    Example : {'10.10.23.1':{'200':['1/1/1', '1/1/2']}}

    Delete network will delete the corresponding entry from the dictionary.
    """

    def __init__(self, device, error=None):
        self.error = error
        self.device = device
        self.address = device.get('address')

    def add_router_interface(self, vlan_id, gateway_ip_cidr):
        if self.error is INVALID_INPUT:
            raise Exception("Ethernet Driver : Create"
                            "network failed: error= Invalid Input")
        elif self.error is RANGE_ERROR:
            raise Exception("Configuring router interface failed: "
                            "ve out of range error")
        elif self.error:
            raise Exception("Add Router Interface failed")
        vlan_map = {}
        interface_map = {}
        interface_map.update({VE + vlan_id: gateway_ip_cidr})
        vlan_map.update({vlan_id: interface_map})
        global config_map
        config_map.update({self.address: vlan_map})

    def remove_router_interface(self, vlan_id):
        vlan_map = delete_config_map.pop(self.address, None)
        interface_map = vlan_map.pop(vlan_id, None)
        if vlan_map is None:
            raise Exception("No Address")
        elif interface_map is None:
            raise Exception("No Router Interface")
        else:
            interface_map.pop(VE + vlan_id, None)
