# Copyright (c) 2013 OpenStack Foundation
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
from networking_brocade.vdx.uplinkports import (
    mechanism_brocade as brocademechanism)
from networking_brocade.vdx.uplinkports.mechanism_brocade import (
     BrocadePortValidationError as INVALID_PORT)
from networking_brocade.vdx.uplinkports.mechanism_brocade import (
     BrocadeProfileValidationError as VLAN_ALREADY_APPLIED)
from neutron.extensions import portbindings
from neutron.plugins.ml2 import config as ml2_config
from neutron.tests.unit import testlib_api
#from neutron.tests.unit.plugins.ml2 import test_plugin
from oslo_log import log as logging
from oslo_utils import importutils

LOG = logging.getLogger(__name__)

MECHANISM_NAME = ('networking_brocade.'
                  'vdx.uplinkports.mechanism_brocade.BrocadeMechanism')

BINDING_PROFILE = {'local_link_information': [
                  {"port_id": "Te:162/0/33"},
                  {"port_id": "Te:162/0/34"}]}

INVALID_NAME = {'local_link_information': [
               {"port_id": "Te:0/33"},
               {"port_id": "Te:0/34"}]}

INVALID_SPEED = {'local_link_information': [
                {"port_id": "eth1:1/0/33"},
                {"port_id": "eth2:1/0/34"}]}


class TestBrocadeUpLinkPortMechDriverV2(testlib_api.SqlTestCase):
    """Test Brocade VCS/VDX mechanism driver.

    """

    _mechanism_name = MECHANISM_NAME

    def setUp(self):

        _mechanism_name = MECHANISM_NAME

        ml2_opts = {
            'mechanism_drivers': ['brocade'],
            'tenant_network_types': ['vlan']}

        for opt, val in ml2_opts.items():
            ml2_config.cfg.CONF.set_override(opt, val, 'ml2')

        def mocked_brocade_init(self):
            LOG.debug("brocadeSVIPlugin::mocked_brocade_init()")
            self._switch = {'address': '10.37.18.131',
                            'username': 'admin',
                            'password': 'password',
                            }
            self._driver = mock.MagicMock()

        with mock.patch.object(brocademechanism.BrocadeMechanism,
                               'brocade_init', new=mocked_brocade_init):
            super(TestBrocadeUpLinkPortMechDriverV2, self).setUp()
            self.mechanism_driver = importutils.import_object(_mechanism_name)
            self.mechanism_driver.brocade_db = mock.MagicMock()
            self.mechanism_driver._driver = mock.MagicMock()

    def tearDown(self):
        super(TestBrocadeUpLinkPortMechDriverV2, self).tearDown()

    def test_port_commit_01(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='direct',
                                              profile=BINDING_PROFILE)

        self.mechanism_driver.create_port_precommit(port_context)
        self.mechanism_driver.create_port_postcommit(port_context)
        self.mechanism_driver.delete_port_precommit(port_context)
        self.mechanism_driver.delete_port_postcommit(port_context)

    def test_create_port_precommit_vlan_already_applied(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='direct',
                                              profile=BINDING_PROFILE)

        self.mechanism_driver.brocade_db.get_uplink_port_binding_profile.\
            return_value = BINDING_PROFILE
        try:
            self.mechanism_driver.create_port_precommit(port_context)
        except VLAN_ALREADY_APPLIED:
            #This case vlan already applied on port
            pass

    def test_create_port_precommit_invalid_vnic_type(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='baremetal',
                                              profile=BINDING_PROFILE)

        self.mechanism_driver.create_port_precommit(port_context)
        self.mechanism_driver.create_port_postcommit(port_context)

    def test_create_port_precommit_empty_profile(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='direct',
                                              profile=None)

        self.mechanism_driver.create_port_precommit(port_context)
        self.mechanism_driver.create_port_postcommit(port_context)

    def test_create_port_precommit_invalid_profile(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='direct',
                                              profile=INVALID_NAME)
        try:
            self.mechanism_driver.create_port_precommit(port_context)
        except INVALID_PORT:
            pass
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='direct',
                                              profile=INVALID_SPEED)
        try:
            self.mechanism_driver.create_port_precommit(port_context)
        except INVALID_PORT:
            pass

    def test_create_port_postcommit_nos_exception(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='direct',
                                              profile=BINDING_PROFILE)
        with mock.patch.object(self.mechanism_driver._driver,
                              'add_or_remove_vlan_from_interface') as m_exc:
            m_exc.side_effect = Exception("not in switching mode")
            try:
                self.mechanism_driver.create_port_postcommit(port_context)
            except Exception:
                #This case vlan already applied on port
                pass

    def test_delete_port_postcommit_nos_exception(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context,
                                              vnic_type='direct',
                                              profile=BINDING_PROFILE)
        with mock.patch.object(self.mechanism_driver._driver,
                              'add_or_remove_vlan_from_interface') as m_exc:
            m_exc.side_effect = Exception("not in switching mode")
            try:
                self.mechanism_driver.delete_port_postcommit(port_context)
            except Exception:
                #This case vlan already applied on port
                pass

    def _get_network_context(self, tenant_id, net_id, seg_id, shared):
        network = {'id': net_id,
                   'tenant_id': tenant_id,
                   'name': 'test-net',
                   'shared': shared}
        network_segments = [{'segmentation_id': seg_id,
                             'network_type': 'vlan'}]
        return FakeNetworkContext(tenant_id, network, network_segments,
                                  network)

    def _get_port_context(self, tenant_id, net_id, device_id, network,
                          device_owner='compute', status='ACTIVE',
                          vnic_type=None, profile=None):
        port = {'device_id': device_id,
                'device_owner': device_owner,
                'binding:host_id': 'ubuntu1',
                'name': 'test-port',
                'tenant_id': tenant_id,
                'id': 101,
                'network_id': net_id,
                'binding:vnic_type': vnic_type,
                'binding:profile': profile,
                'security_groups': None,
                }
        orig_port = {'device_id': device_id,
                     'device_owner': device_owner,
                     'binding:host_id': 'ubuntu1',
                     'name': 'test-port',
                     'tenant_id': tenant_id,
                     'id': 101,
                     'network_id': net_id,
                     'binding:vnic_type': vnic_type,
                     'binding:profile': profile,
                     'security_groups': None,
                     }
        return FakePortContext(port, dict(orig_port), network, status)


class FakeNetworkContext(object):
    """To generate network context for testing purposes only."""

    def __init__(self, tenant_id, network, segments=None,
                 original_network=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments
        self._plugin_context = FakePluginContext(tenant_id)

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class FakePortContext(object):
    """To generate port context for testing purposes only."""

    def __init__(self, port, original_port, network, status):
        self._port = port
        self._original_port = original_port
        self._network_context = network
        self._status = status

    @property
    def current(self):
        return self._port

    @property
    def original(self):
        return self._original_port

    @property
    def network(self):
        return self._network_context

    @property
    def host(self):
        return self._port.get(portbindings.HOST_ID)

    @property
    def original_host(self):
        return self._original_port.get(portbindings.HOST_ID)

    @property
    def status(self):
        return self._status


class FakePluginContext(object):
    """Plugin context for testing purposes only."""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
