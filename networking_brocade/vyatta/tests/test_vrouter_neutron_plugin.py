# Copyright 2015 Brocade Communications System, Inc.
# All Rights Reserved.
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

import mock
from oslo_config import cfg

from neutron import context
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import models_v2
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import l3
from neutron.openstack.common import uuidutils
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_plugin
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit import testlib_api


from networking_brocade.vyatta.common import utils as vyatta_utils
from networking_brocade.vyatta.vrouter import neutron_plugin as vrouter_plugin

_uuid = uuidutils.generate_uuid


class FakeVRouterDriver(mock.Mock):
    def create_router(self, *args, **kwargs):
        return _uuid()


class VRouterTestPlugin(vrouter_plugin.VyattaVRouterMixin,
                        db_base_plugin_v2.NeutronDbPluginV2,
                        external_net_db.External_net_db_mixin,
                        sg_db_rpc.SecurityGroupServerRpcMixin):

    def delete_port(self, context, port_id, l3_port_check=False):
        super(VRouterTestPlugin, self).delete_port(context, port_id)


class TestVyattaVRouterPlugin(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestVyattaVRouterPlugin, self).setUp()

        self.setup_coreplugin(__name__ + '.' + VRouterTestPlugin.__name__)

        self._mock('eventlet.greenthread.sleep')

        self.driver = mock.Mock(wraps=FakeVRouterDriver())
        fake_driver_mock = mock.Mock()
        fake_driver_mock.return_value = self.driver

        self._mock(
            'networking_brocade.vyatta.vrouter.driver.VyattaVRouterDriver',
            fake_driver_mock)

        self.context = context.get_admin_context()
        self.plugin = VRouterTestPlugin()

        session = self.context.session
        with session.begin(subtransactions=True):
            self.ext_net = self._make_net('ext', is_external=True)
            self.ext_subnet = self._make_subnet(
                'ext', '10.10.10', self.ext_net['id'])
            self.ext_port = self._make_port('f0', self.ext_net['id'])
            self._make_fixed_ip(
                self.ext_port['id'], self.ext_net['id'],
                self.ext_subnet['id'], '10.10.10.22')

    def _mock(self, target, new=mock.DEFAULT):
        patcher = mock.patch(target, new)
        return patcher.start()

    def _mock_object(self, target, attribute, new=mock.DEFAULT):
        patcher = mock.patch.object(target, attribute, new)
        return patcher.start()

    def _make_net(self, n, is_shared=False, is_external=False):
        session = self.context.session
        network = models_v2.Network(tenant_id='fake-tenant-id',
                                    name='test-network-{0}'.format(n),
                                    status='ACTIVE',
                                    admin_state_up=True,
                                    shared=is_shared)
        session.add(network)
        session.flush()
        if is_external:
            extnet = external_net_db.ExternalNetwork(
                network_id=network['id'])
            session.add(extnet)
            session.flush()
        return network

    def _make_subnet(self, n, cidr_prefix, network_id):
        session = self.context.session
        subnet = models_v2.Subnet(tenant_id='fake-tenant-id',
                                  name='test-subnet-{0}'.format(n),
                                  network_id=network_id,
                                  ip_version=4,
                                  cidr='{0}.0/24'.format(cidr_prefix),
                                  gateway_ip='{0}.1'.format(cidr_prefix),
                                  enable_dhcp=True,
                                  shared=False)
        session.add(subnet)
        session.flush()
        ippool = models_v2.IPAllocationPool(
            subnet_id=subnet['id'],
            first_ip='{0}.1'.format(cidr_prefix),
            last_ip='{0}.254'.format(cidr_prefix))
        session.add(ippool)
        session.flush()
        iprange = models_v2.IPAvailabilityRange(
            allocation_pool_id=ippool['id'],
            first_ip='{0}.1'.format(cidr_prefix),
            last_ip='{0}.254'.format(cidr_prefix))
        session.add(iprange)
        session.flush()
        return subnet

    def _make_fixed_ip(self, port_id, network_id, subnet_id, ip):
        session = self.context.session
        ip_allocation = models_v2.IPAllocation(
            port_id=port_id,
            ip_address=ip,
            subnet_id=subnet_id,
            network_id=network_id)
        session.add(ip_allocation)
        session.flush()
        return ip_allocation

    def _make_port(self, port, network_id, device_id=None, device_owner=None):
        session = self.context.session
        port = models_v2.Port(tenant_id='fake-tenant-id',
                              name='',
                              network_id=network_id,
                              mac_address='aa:bb:cc:dd:ee:{0}'.format(port),
                              admin_state_up=True,
                              status='ACTIVE',
                              device_id=device_id or '',
                              device_owner=device_owner or '')
        session.add(port)
        session.flush()
        return port

    def test_create_router(self):
        router_data = {
            'router': {'name': 'test_router1', 'admin_state_up': True}}
        result = self.plugin.create_router(self.context, router_data)
        self.assertTrue(uuidutils.is_uuid_like(result.get('id')))
        self.driver.create_router.assert_called_once_with(mock.ANY)

    def test_update_router1(self):
        router_data = {
            'router': {
                'name': 'test_router1',
                'admin_state_up': True,
                'external_gateway_info': {},
            }
        }
        router = self.plugin.create_router(self.context, router_data)
        router_new = self.plugin.update_router(self.context, router['id'], {
            'router': {
                'name': 'router2',
                'external_gateway_info': {},
            }
        })
        self.assertEqual(router_new['name'], 'router2')

    def test_update_router2(self):
        self._mock_object(self.plugin, '_validate_routes_nexthop')

        router_data = {
            'router': {
                'name': 'test_router2',
                'admin_state_up': True,
                'external_gateway_info': {},
            },
        }

        router = self.plugin.create_router(self.context, router_data)

        routes = [
            {'destination': '10.1.0.0/24', 'nexthop': '192.168.1.1'},
            {'destination': '10.2.0.0/24', 'nexthop': '192.168.1.1'},
            {'destination': '10.3.0.0/24', 'nexthop': '192.168.1.1'}
        ]

        set_routes = []
        update_data = {
            'router': {
                'id': router['id'],
                'routes': set_routes,
            },
        }

        RouteRule = vyatta_utils.RouteRule

        for rules_add in routes:
            rules_add = [rules_add]

            set_routes.extend(rules_add)
            rules_del = set_routes[:-2]
            set_routes[:-2] = []

            self.plugin.update_router(self.context, router['id'], update_data)

            rules_add = tuple(RouteRule(dest_cidr=x['destination'],
                                        next_hop=x['nexthop'])
                              for x in rules_add)
            rules_del = tuple(RouteRule(dest_cidr=x['destination'],
                                        next_hop=x['nexthop'])
                              for x in rules_del)

            self.driver.update_static_routes.assert_called_once_with(
                self.context, router['id'],
                rules_add, rules_del)
            self.driver.reset_mock()

    def test_get_router(self):
        router_data = {
            'router': {'name': 'test_router1', 'admin_state_up': True}}
        router = self.plugin.create_router(self.context, router_data)
        router = self.plugin.get_router(self.context, router['id'])
        self.assertTrue(uuidutils.is_uuid_like(router.get('id')))

        self.assertRaises(l3.RouterNotFound, self.plugin.get_router,
                          self.context, uuidutils.generate_uuid())

    def test_delete_router(self):
        router_data = {
            'router': {'name': 'test_router1', 'admin_state_up': True}}
        router = self.plugin.create_router(self.context, router_data)
        self.plugin.delete_router(self.context, router['id'])
        self.driver.delete_router.assert_called_once_with(
            self.context, router['id'])
        self.assertRaises(
            l3.RouterNotFound, self.plugin.delete_router,
            self.context, router['id'])

    def test_router_interface_by_subnet(self):
        router_data = {
            'router': {'name': 'test_router1', 'admin_state_up': True}}
        router = self.plugin.create_router(self.context, router_data)

        result = self.plugin.add_router_interface(self.context, router['id'], {
            'subnet_id': self.ext_subnet['id'],
        })
        self.driver.attach_interface.assert_called_once_with(
            self.context, router['id'], result['port_id'])

        result = self.plugin.remove_router_interface(
            self.context, router['id'], {
                'subnet_id': self.ext_subnet['id']})

        self.driver.detach_interface.assert_called_once_with(
            self.context, router['id'], result['port_id'])

    def test_router_interface_by_port(self):
        router_data = {
            'router': {'name': 'test_router1', 'admin_state_up': True}}
        router = self.plugin.create_router(self.context, router_data)

        self.plugin.add_router_interface(self.context, router['id'], {
            'port_id': self.ext_port['id'],
        })
        self.driver.attach_interface.assert_called_once_with(
            self.context, router['id'], self.ext_port['id'])

        self.plugin.remove_router_interface(
            self.context, router['id'], {
                'port_id': self.ext_port['id']
            })
        self.driver.detach_interface.assert_called_once_with(
            self.context, router['id'], self.ext_port['id'])

    def test_floatingip(self):
        router_data = {
            'router': {'name': 'test_router1', 'admin_state_up': True}}
        router = self.plugin.create_router(self.context, router_data)

        floatingip = self.plugin.create_floatingip(
            self.context,
            {'floatingip': {'floating_network_id': self.ext_net['id']}})
        self.addCleanup(self.plugin.delete_floatingip,
                        self.context, floatingip['id'])
        self.assertTrue(
            floatingip['floating_ip_address'].startswith('10.10.10.'))

        self.plugin.associate_floatingip(
            self.context, router['id'], floatingip)
        self.driver.assign_floating_ip.assert_called_once_with(
            self.context, router['id'], floatingip['floating_ip_address'],
            None)

        self.plugin.disassociate_floatingip(
            self.context, router['id'], floatingip)
        self.driver.unassign_floating_ip.assert_called_once_with(
            self.context, router['id'], floatingip['floating_ip_address'],
            None)

        self.plugin.update_floatingip(self.context, floatingip['id'], {
            'floatingip': {
                'router_id': router['id'],
            }})
        self.driver.assign_floating_ip.assert_called_once_with(
            self.context, router['id'], floatingip['floating_ip_address'],
            None)

CORE_PLUGIN_CLASS = (
    "networking_brocade.vyatta.tests.test_vrouter_neutron_plugin"
    ".TestVRouterNatPlugin")
L3_PLUGIN_CLASS = (
    "networking_brocade.vyatta.vrouter.neutron_plugin.VyattaVRouterMixin")


class TestVRouterNatPlugin(test_l3_plugin.TestL3NatBasePlugin,
                           sg_db_rpc.SecurityGroupServerRpcMixin):
    supported_extension_aliases = ["external-net"]


class VRouterTestCase(test_db_plugin.NeutronDbPluginV2TestCase,
                      test_l3_plugin.L3NatTestCaseBase):
    def setUp(self, core_plugin=None, l3_plugin=None, ext_mgr=None):

        if not core_plugin:
            core_plugin = CORE_PLUGIN_CLASS
        if not l3_plugin:
            l3_plugin = L3_PLUGIN_CLASS

        service_plugins = {'l3_plugin_name': l3_plugin}

        self._mock('eventlet.greenthread.sleep')

        self._mock(
            'networking_brocade.vyatta.vrouter.driver.'
            'VyattaVRouterDriver', FakeVRouterDriver)

        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_override('tenant_id', 'tenant_a', 'VROUTER')

        super(VRouterTestCase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=test_l3_plugin.L3TestExtensionManager())

        self.setup_notification_driver()

    def _mock(self, target, new=mock.DEFAULT):
        patcher = mock.patch(target, new)
        return patcher.start()

    def test_router_add_interface_ipv6_subnet(self):
        self.skipTest("Fails because router port is created with"
                      " empty device owner")

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        self.skipTest("Fails because router port is created with"
                      " empty device owner")

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        self.skipTest("Fails because router port is created with"
                      " empty device owner")

    def test_router_add_gateway_no_subnet(self):
        self.skipTest("Skip because it is not supported.")

    def test_router_specify_id_backend(self):
        self.skipTest("Router id is autogenerated")

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        self.skipTest("Router external gateway supports only one IP address")
