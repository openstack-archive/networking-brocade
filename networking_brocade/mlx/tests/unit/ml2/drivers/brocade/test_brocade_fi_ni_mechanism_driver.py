# Copyright 2015 Brocade Communications Systems, Inc.
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
from networking_brocade.mlx.ml2.fi_ni import (
    mechanism_brocade_fi_ni as brocadefinimechanism)
from neutron import context
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.tests import base
from oslo_log import log as logging
from oslo_utils import importutils

LOG = logging.getLogger(__name__)
MECHANISM_NAME = ('networking_brocade.mlx.ml2.fi_ni.'
                  'mechanism_brocade_fi_ni.BrocadeFiNiMechanism')
FAKE_PHYSICAL_NETWORK = 'physnet1'

config_map = {}

devices = {
    'icx': {
        'address': '1.1.1.1',
        'username': 'admin',
        'password': 'pass',
        'physical_networks': 'physnet1',
        'ports': '1/1/1,1/1/2',
        'os_type': 'FI'
    },
    'mlx': {
        'address': '2.2.2.2',
        'username': 'admin',
        'password': 'pass',
        'physical_networks': 'physnet1',
        'ports': '2/1,2/2',
        'os_type': 'NI'
    },
}

physical_networks = {
    'physnet1': ['icx', 'mlx']
}

actual_config_map = {
    '1.1.1.1': {
        200: ['1/1/1', '1/1/2']
    },
    '2.2.2.2': {
        200: ['2/1', '2/2']
    }
}

empty_config_map = {
}


class TestBrocadeFiNiMechDriver(base.BaseTestCase):

    """
    Test Brocade FI/NI mechanism driver.
    """

    def setUp(self):
        _mechanism_name = MECHANISM_NAME

        def mocked_initialize(self):
            self._devices = devices
            self._physical_networks = physical_networks

        with mock.patch.object(brocadefinimechanism.BrocadeFiNiMechanism,
                        'initialize', new=mocked_initialize):
            super(TestBrocadeFiNiMechDriver, self).setUp()
            self.mechanism_driver = importutils.import_object(_mechanism_name)

    def test_create_network_postcommit_wrong_physnet(self):
        """
        Test create network with wrong value for physical network.
        Physical network to which the devices belong is 'physnet1' but
        we make a call to create network with physical network 'physnet2'.
        In this case we raise an exception with error message -
        "Brocade Mechanism: failed to create network, network cannot be
        created in the configured physical network."
        """
        ctx = self._get_network_context('physnet2', 'vlan')
        self.assertRaises(ml2_exc.MechanismDriverError,
                          self.mechanism_driver.create_network_postcommit, ctx)

    def test_create_network_postcommit_wrong_network_type(self):
        """
        Test create network with wrong value for network type. The plugin
        allows to create network only if the request is to create a VLAN
        network. For any other network type following exception is raised -
        'Brocade Mechanism failed to create network, only network type vlan
        is supported"
        """
        ctx = self._get_network_context('physnet1', 'vxlan')
        self.assertRaises(ml2_exc.MechanismDriverError,
                          self.mechanism_driver.create_network_postcommit, ctx)

    @mock.patch.object(brocadefinimechanism.BrocadeFiNiMechanism,
                       '_get_driver')
    def test_create_network_postcommit(self, mock_driver):
        """
        Test create network with correct input values
        """
        mock_driver.side_effect = self.side_effect
        ctx = self._get_network_context('physnet1', 'vlan')
        self.mechanism_driver.create_network_postcommit(ctx)
        self.assertDictSupersetOf(config_map, actual_config_map)

    @mock.patch.object(brocadefinimechanism.BrocadeFiNiMechanism,
                       '_get_driver')
    def test_create_network_postcommit_driver_exception(self, mock_driver):
        """
        Expect an exception while trying to get the driver
        """
        mock_driver.side_effect = self.side_effect_error
        ctx = self._get_network_context('physnet1', 'vlan')
        self.assertRaises(ml2_exc.MechanismDriverError,
                          self.mechanism_driver.create_network_postcommit, ctx)

    @mock.patch.object(brocadefinimechanism.BrocadeFiNiMechanism,
                       '_get_driver')
    def test_create_network_postcommit_exception(self, mock_driver):
        """
        Exception is raised when the input values are incorrect.
        """
        mock_driver.side_effect = self.side_effect_error
        ctx = self._get_network_context('physnet1', 'vlan')
        self.assertRaises(ml2_exc.MechanismDriverError,
                          self.mechanism_driver.create_network_postcommit, ctx)

    @mock.patch.object(brocadefinimechanism.BrocadeFiNiMechanism,
                       '_get_driver')
    def test_delete_network_postcommit(self, mock_driver):
        """
        Test delete network
        """
        mock_driver.side_effect = self.side_effect
        ctx = self._get_network_context('physnet1', 'vlan')
        vlan_map = {200: ['1/1/1', '1/1/2']}
        config_map.update({'1.1.1.1': vlan_map})
        vlan_map = {200: ['2/1', '2/2']}
        config_map.update({'2.2.2.2': vlan_map})
        self.mechanism_driver.delete_network_postcommit(ctx)
        self.assertDictSupersetOf(config_map, empty_config_map)

    def _get_network_context(self, physnet, network_type):
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

    def side_effect(self, dev_name):
        """
        Mock _get_driver method and return FakeDriver
        """
        device = devices.get(dev_name)
        return FakeDriver(device)

    def side_effect_error(self, dev_name):
        """
        Mock _get_driver method and return FakeDriver
        """
        device = devices.get(dev_name)
        return FakeDriver(device, error=True)


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

    def __init__(self, device, error=False):
        self.error = error
        self.device = device
        self.address = device.get('address')

    def create_network(self, vlan_id, ports):
        if self.error:
            raise ml2_exc.MechanismDriverError(method='create_network')
        vlan_map = {}
        vlan_map.update({vlan_id: ports})
        config_map.update({self.address: vlan_map})

    def delete_network(self, vlan_id):
        vlan_map = config_map.pop(self.address, None)
        if vlan_map is None:
            raise ml2_exc.MechanismDriverError(method='delete_network')
        else:
            vlan_map.pop(vlan_id, None)
