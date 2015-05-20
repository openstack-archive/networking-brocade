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
import requests
import urllib

from neutron import context
from neutron.db import models_v2
from neutron.openstack.common import uuidutils
from neutron.tests import base as n_base

from networking_brocade.vyatta.common import utils as vyatta_utils
from networking_brocade.vyatta.vrouter import client as vyatta_client
from networking_brocade.vyatta.vrouter import driver as vrouter_driver


_uuid = uuidutils.generate_uuid


def mock_patch(target, new=mock.DEFAULT):
    patcher = mock.patch(target, new)
    return patcher.start()


def mock_object(target, attribute, new=mock.DEFAULT):
    patcher = mock.patch.object(target, attribute, new)
    return patcher.start()


class TestVRouterDriver(n_base.BaseTestCase):
    def setUp(self):
        super(TestVRouterDriver, self).setUp()

        # mock_object(
        #     vrouter_driver.VyattaVRouterDriver,
        #     '_management_network').return_value = _uuid()

        self._nova_client = mock_patch(
            'novaclient.v1_1.client.Client').return_value

        self._server = self._create_server()
        self._nova_client.servers.create.return_value = self._server
        self._nova_client.servers.get.return_value = self._server

        self._router_api_mock = mock_object(
            vrouter_driver.VyattaVRouterDriver, '_get_router_api')
        self._router_api = self._router_api_mock.return_value

        self.driver = vrouter_driver.VyattaVRouterDriver()

    @staticmethod
    def _create_server():
        server = mock.Mock()
        server.id = _uuid()
        server.status = 'ACTIVE'
        server.interface_list.return_value = ['mng-iface']

        return server

    def test_create_router(self):
        ctx = context.Context('', 'tenant_id1')
        router = self.driver.create_router(ctx)
        self.assertEqual(self._server.id, router)

    def test_init_router(self):
        ctx = context.Context('', 'tenant_id1')

        router = {'id': _uuid()}

        self.driver.init_router(ctx, router)

        self._router_api_mock.assert_called_once_with(mock.ANY, router['id'])
        self._router_api.init_router.assert_called_once_with(
            mock.ANY, mock.ANY)

    def test_delete_router(self):
        ctx = context.Context('', 'tenant_id1')

        router_id = _uuid()

        self.driver.delete_router(ctx, router_id)

        self._router_api_mock.assert_called_once_with(mock.ANY, router_id)
        self._router_api.disconnect.assert_called_once_with()
        self._nova_client.servers.delete.assert_called_once_with(router_id)

    def test_attach_interface(self):
        ctx = context.Context('', 'tenant_id1')
        port_id = _uuid()

        self.driver.attach_interface(ctx, self._server.id, port_id)

        self._nova_client.servers.get.assert_called_once_with(self._server.id)
        self._server.interface_attach.assert_called_once_with(
            port_id, mock.ANY, mock.ANY)

    def test_detach_interface(self):
        ctx = context.Context('', 'tenant_id1')
        port_id = _uuid()

        self.driver.detach_interface(ctx, self._server.id, port_id)

        self._nova_client.servers.get.assert_called_once_with(self._server.id)
        self._server.interface_detach.assert_called_once_with(port_id)

    def test_configure_interface(self):

        ctx = context.Context('', 'tenant_id1')
        router_id = _uuid()
        interfaces = ['eth0', 'eth1']

        self.driver.configure_interface(ctx, router_id, interfaces)

        for interface in interfaces:
            self._router_api.add_interface_to_router.assert_any_call(interface)

    def test_deconfigure_interface(self):
        ctx = context.Context('', 'tenant_id1')
        router_id = _uuid()
        interfaces = ['eth0', 'eth1']

        self.driver.deconfigure_interface(ctx, router_id, interfaces)

        for interface in interfaces:
            self._router_api.remove_interface_from_router.assert_any_call(
                interface)

    def test_configure_gateway(self):
        ctx = context.Context('', 'tenant_id1')
        router_id = _uuid()
        interfaces = ['eth0']

        self.driver.configure_gateway(ctx, router_id, interfaces)

        self._router_api.update_router.assert_called_once_with(
            external_gateway_info=interfaces[0])

    def test_clear_gateway(self):
        ctx = context.Context('', 'tenant_id1')
        router_id = _uuid()

        self.driver.clear_gateway(ctx, router_id)

        self._router_api.update_router.assert_called_once_with(
            external_gateway_info=None)

    def test_assign_floating_ip(self):
        ctx = context.Context('', 'tenant_id1')
        router_id = _uuid()
        floating_ip = '192.168.1.13'
        fixed_ip = '10.10.1.13'

        self.driver.assign_floating_ip(ctx, router_id, floating_ip, fixed_ip)

        self._router_api.assign_floating_ip.assert_called_once_with(
            floating_ip, fixed_ip)

    def test_unassign_floating_ip(self):
        ctx = context.Context('', 'tenant_id1')
        router_id = _uuid()
        floating_ip = '192.168.1.13'
        fixed_ip = '10.10.1.13'

        self.driver.unassign_floating_ip(ctx, router_id, floating_ip, fixed_ip)

        self._router_api.unassign_floating_ip.assert_called_once_with(
            floating_ip, fixed_ip)

    def test_update_static_routes(self):
        ctx = context.Context('', 'tenant_idl')
        router_id = _uuid()

        RouteRule = vyatta_utils.RouteRule
        routes_to_add = (
            RouteRule(dest_cidr='10.1.0.0/24', next_hop='192.168.1.1'),
            RouteRule(dest_cidr='10.2.0.0/24', next_hop='192.168.1.1')
        )
        routes_to_del = (
            RouteRule(dest_cidr='10.3.0.0/24', next_hop='192.168.1.1'),
        )

        self.driver.update_static_routes(ctx, router_id,
                                         routes_to_add, routes_to_del)
        self._router_api.update_static_routes.assert_called_once_with(
            routes_to_add, routes_to_del)


class TestVRouterDriverApi(n_base.BaseTestCase):

    def setUp(self):
        super(TestVRouterDriverApi, self).setUp()

        self._nova_client = mock_patch(
            'novaclient.v1_1.client.Client').return_value

        # self._mock_object(vrouter_driver.VyattaVRouterDriver,
        #                   '_management_network')

        self.driver = vrouter_driver.VyattaVRouterDriver()

    def _mock_object(self, target, attribute, new=mock.DEFAULT):
        patcher = mock.patch.object(target, attribute, new)
        return patcher.start()

    def test_get_router_api(self):
        ctx = mock.Mock()
        router_id = _uuid()

        router_addr = '172.16.18.10'

        server = self._nova_client.servers.get.return_value
        server.addresses = {
            'external': [
                {'addr': router_addr, }
            ]
        }

        query = ctx.session.query.return_value
        query.filter_by.return_value.one.return_value = models_v2.Network(
            name='external')

        with mock.patch.object(
                vyatta_client.VRouterRestAPIClient, 'connect') as api_connect:
            api = self.driver._get_router_api(ctx, router_id)
            self.assertIsNotNone(api)
            api_connect.assert_called_once_with(router_addr)


SHOW_VERSION_OUTPUT = """
Version:      VSE6.6R5X3
Description:  Brocade Vyatta 5410 vRouter 6.6 R5X3
Copyright:    2006-2014 Vyatta, Inc.
"""

SHOW_CONFIG_OUTPUT = """
interfaces {
    ethernet eth0 {
        address 10.10.0.1
        description External_Gateway
        hw-id 08:00:27:02:b4:67
        duplex auto
        smp_affinity auto
        speed auto
    }
    loopback lo {
    }
}
service {
    https {
        http-redirect disable
    }
    lldp {
        interface all {
        }
        snmp {
            enable
        }
    }
    snmp {
        community public {
            authorization ro
        }
    }
    ssh {
        port 22
    }
}
system {
    host-name router1
    login {
        user vyatta {
            authentication {
                encrypted-password ****************
            }
            level admin
        }
    }
    syslog {
        global {
            facility all {
                level debug
            }
            facility protocols {
                level debug
            }
        }
        user all {
            facility all {
                level emerg
            }
        }
    }
    time-zone GMT
}
"""


class VRouterRestAPIClientMixin(object):

    def _create_client(self):

        self.address = 'example.com'

        client = vyatta_client.VRouterRestAPIClient()
        client.address = self.address
        client._vrouter_model = (
            vyatta_client.VRouterRestAPIClient._VROUTER_VR_MODEL)

        return client


class TestVRouterRestAPIClient(n_base.BaseTestCase,
                               VRouterRestAPIClientMixin):

    def setUp(self):
        super(TestVRouterRestAPIClient, self).setUp()

        self._rest_mock = mock_object(
            vyatta_client.VRouterRestAPIClient, '_rest_call')
        self._rest_mock.side_effect = self._rest_call

        m = mock_object(vyatta_client.VRouterRestAPIClient,
                        'get_ethernet_if_id')
        m.return_value = 'eth0'

        m = mock_object(
            vyatta_client.VRouterRestAPIClient, '_get_admin_state')
        m.return_value = False

    def _check_cmd(self, cmd, check_type=None, check_cmd=None):
        if check_type is not None:
            self.assertEqual(cmd.cmd_type, check_type)
        if check_cmd is not None:
            self.assertEqual(cmd.cmd, check_cmd)

    @staticmethod
    def _rest_call(method, uri, headers=None, session=None):
        response = mock.Mock()
        response.status_code = requests.codes.OK
        response.reason = 'Ok'
        response.text = '{}'
        response.headers = {
            'Location': 'location'
        }

        return response

    def _check_update_interface(self, action, interface_info):
        prefix = '/location/{action}/interfaces/dataplane/eth0'.format(
            action=action)

        self._rest_mock.assert_any_call(
            'PUT', prefix + '/address/' + interface_info['ip_address'])
        self._rest_mock.assert_any_call(
            'POST', '/location/commit')
        self._rest_mock.assert_any_call(
            'POST', '/location/save')

    def test_init_router(self):
        client = self._create_client()
        with mock.patch('eventlet.greenthread.sleep'):
            client.init_router('router1', True)

        self._rest_mock.assert_any_call(
            'PUT', '/location/delete/system/ip/disable-forwarding',
        )

    def test_add_interface_to_router(self):

        interface_info = {
            'mac_address': '08:00:27:02:b4:67',
            'ip_address': '10.10.16.20',
            'gateway_ip': '10.10.16.1'
        }

        client = self._create_client()
        client.add_interface_to_router(interface_info)

        self._check_update_interface('set', interface_info)

    def test_remove_interface_from_router(self):

        interface_info = {
            'mac_address': '08:00:27:02:b4:67',
            'ip_address': '10.10.16.20',
            'gateway_ip': '10.10.16.1'
        }

        client = self._create_client()
        client.remove_interface_from_router(interface_info)

        self._check_update_interface('delete', interface_info)

    def test_assign_floating_ip(self):
        client = self._create_client()
        client._external_gw_info = vyatta_client.InterfaceInfo(
            'eth0', '172.16.18.10', '172.16.18.1')
        client.assign_floating_ip('172.16.18.12', '10.10.10.12')

        self.assertIn('172.16.18.12.10.10.10.12', client._floating_ip_dict)

        client.unassign_floating_ip('172.16.18.12', '10.10.10.12')

        self.assertNotIn('172.16.18.12.10.10.10.12', client._floating_ip_dict)

    def test_update_static_routes(self):
        cmd_batch_mock = mock.Mock()
        mock_object(vyatta_client.VRouterRestAPIClient,
                    'exec_cmd_batch', cmd_batch_mock)

        RouteRule = vyatta_utils.RouteRule

        routes_to_add = tuple((
            RouteRule(dest_cidr='10.1.0.0/24', next_hop='192.168.1.1'),
            RouteRule(dest_cidr='10.2.0.0/24', next_hop='192.168.1.1'),
        ))
        routes_to_del = tuple((
            RouteRule(dest_cidr='10.3.0.0/24', next_hop='192.168.1.1'),
        ))

        client = self._create_client()
        client.update_static_routes(routes_to_add, routes_to_del)

        expected_batch = list()
        for rule in routes_to_add:
            cmd = vyatta_client.SetCmd((
                'protocols/static/route/{0}/next-hop/{1}').format(
                    urllib.quote_plus(rule.dest_cidr),
                    urllib.quote_plus(rule.next_hop)))
            expected_batch.append(cmd)
        for rule in routes_to_del:
            cmd = vyatta_client.DeleteCmd('protocols/static/route/{0}'.format(
                urllib.quote_plus(rule.dest_cidr)))
            expected_batch.append(cmd)

        cmd_batch_mock.assert_called_once_with(expected_batch)

    def test_update_router(self):
        client = self._create_client()

        gw_info = {
            'mac_address': '08:00:27:02:b4:67',
            'ip_address': '10.10.16.20',
            'gateway_ip': '10.10.16.1'
        }

        client.update_router('rotuer1', True, gw_info)

        self._check_update_interface('set', gw_info)
        self._rest_mock.assert_any_call(
            'PUT', '/location/set/protocols/static/route/0.0.0.0%2F0/next-hop/'
            + gw_info['gateway_ip'])

        self._rest_mock.reset_mock()

        client.update_router('rotuer1', True)

        self._check_update_interface('delete', gw_info)
        self._rest_mock.assert_any_call(
            'PUT', '/location/delete/protocols/static/route/0.0.0.0%2F0')

    def test_get_nat_cmd(self):
        client = self._create_client()

        nat_cmd = client._get_nat_cmd()
        self.assertEqual(nat_cmd, 'service/nat')

        client._vrouter_model = (
            vyatta_client.VRouterRestAPIClient._VROUTER_VSE_MODEL)
        nat_cmd = client._get_nat_cmd()
        self.assertEqual(nat_cmd, 'nat')

    def test_add_snat_rule_cmd(self):

        client = self._create_client()
        cmd_list = []
        client._add_snat_rule_cmd(
            cmd_list, 2, 'eth1', '10.10.12.1', '192.168.12.1')

        prefix = 'service/nat/source/rule/2'

        self._check_cmd(cmd_list[0], 'set', prefix)
        self._check_cmd(cmd_list[1], 'set',
                        prefix + '/outbound-interface/eth1')
        self._check_cmd(cmd_list[2], 'set',
                        prefix + '/source/address/10.10.12.1')
        self._check_cmd(cmd_list[3], 'set',
                        prefix + '/translation/address/192.168.12.1')

    def test_add_dnat_rule_cmd(self):

        client = self._create_client()
        cmd_list = []
        client._add_dnat_rule_cmd(
            cmd_list, 2, 'eth1', '10.10.12.1', '192.168.12.1')

        prefix = 'service/nat/destination/rule/2'

        self._check_cmd(cmd_list[0], 'set', prefix)
        self._check_cmd(cmd_list[1], 'set', prefix + '/inbound-interface/eth1')
        self._check_cmd(cmd_list[2], 'set',
                        prefix + '/destination/address/10.10.12.1')
        self._check_cmd(cmd_list[3], 'set',
                        prefix + '/translation/address/192.168.12.1')

    def test_delete_snat_rule_cmd(self):
        client = self._create_client()
        cmd_list = []
        client._delete_snat_rule_cmd(cmd_list, 2)

        self._check_cmd(cmd_list[0], 'delete', 'service/nat/source/rule/2')

    def test_delete_dnat_rule_cmd(self):
        client = self._create_client()
        cmd_list = []
        client._delete_dnat_rule_cmd(cmd_list, 2)

        self._check_cmd(cmd_list[0],
                        'delete', 'service/nat/destination/rule/2')

    def test_set_router_name_cmd(self):
        client = self._create_client()
        cmd_list = []
        client._set_router_name_cmd(cmd_list, 'router1')

        self._check_cmd(cmd_list[0], 'set', 'system/host-name/router1')

    def test_set_system_gateway_cmd(self):
        client = self._create_client()
        cmd_list = []
        client._set_system_gateway_cmd(cmd_list, '10.10.16.1')

        self.assertEqual(len(cmd_list), 1)
        self._check_cmd(
            cmd_list[0], 'set',
            'protocols/static/route/0.0.0.0%2F0/next-hop/10.10.16.1')

    def test_delete_system_gateway_cmd(self):
        client = self._create_client()
        cmd_list = []
        # NOTE: Gateway parameter is not used
        client._delete_system_gateway_cmd(cmd_list, '10.10.16.1')

        self.assertEqual(len(cmd_list), 1)
        self._check_cmd(
            cmd_list[0], 'delete',
            'protocols/static/route/0.0.0.0%2F0')

    def test_configure_cmd_batch(self):
        client = self._create_client()
        cmd_list = [
            vyatta_client.SetCmd('cmd1'),
            vyatta_client.DeleteCmd('cmd2')
        ]

        client.exec_cmd_batch(cmd_list)

        self.assertEqual(
            self._rest_mock.call_count, len(cmd_list) + 4)

    def test_get_config_cmd(self):
        client = self._create_client()
        client._get_config_cmd('system/ip/disable-forwarding')

        self.assertEqual(self._rest_mock.call_count, 3)

    def test_show_cmd(self):

        self._rest_mock.side_effect = [
            self._make_http_response(201, headers={'Location': '/fake-url'}),
            self._make_http_response(200, text=SHOW_VERSION_OUTPUT),
            self._make_http_response(410),
            self._make_http_response(200)]

        client = self._create_client()
        client._show_cmd('version')
        self.assertEqual(self._rest_mock.call_count, 4)

    def test_process_model(self):
        client = vyatta_client.VRouterRestAPIClient()

        with mock.patch.object(
                vyatta_client.VRouterRestAPIClient, '_show_cmd') as show_cmd:
            show_cmd.return_value = SHOW_VERSION_OUTPUT
            client._process_model()

            self.assertEqual(client._vrouter_model, 54)

    def test_sync_cache(self):

        client = self._create_client()

        with mock.patch.object(
                vyatta_client.VRouterRestAPIClient, '_show_cmd') as show_cmd:
            show_cmd.return_value = SHOW_CONFIG_OUTPUT

            client._sync_cache()

        interface_info = vyatta_client.InterfaceInfo(
            'eth0', '10.10.0.1')
        self.assertEqual(client._external_gw_info, interface_info)

    def _make_http_response(self, status_code, headers=None, text=None):

        if headers is None:
            headers = {}

        response = mock.Mock()
        response.status_code = status_code
        response.headers = headers
        response.text = text

        return response


class TestLowLevelRestAPIClient(n_base.BaseTestCase,
                                VRouterRestAPIClientMixin):
    def test_get_admin_state(self):

        client = self._create_client()
        with mock.patch.object(
                vyatta_client.VRouterRestAPIClient,
                '_show_cmd') as get_cmd:
            get_cmd.return_value = "IP forwarding is on"

            state = client._get_admin_state()
            self.assertTrue(state)

    def test_get_ethernet_if_id(self):

        client = self._create_client()
        with mock.patch.object(
                vyatta_client.VRouterRestAPIClient,
                '_get_interfaces') as get_ifs:
            get_ifs.return_value = [{'name': 'dp0e5',
                                     'ip_addrs': '192.168.21.3',
                                     'mac_address': '08:00:27:4a:be:12'}]
            if_id = client.get_ethernet_if_id('08:00:27:4a:be:12')
            self.assertEqual(if_id, 'dp0e5')

    def test_rest_call(self):
        action = 'GET'
        uri = '/show/config'

        client = self._create_client()
        with mock.patch('requests.request') as request:
            client._rest_call(action, uri)

            uri = 'https://{0}{1}'.format(self.address, uri)

            request.assert_called_once_with(
                action, uri, verify=False, auth=mock.ANY,
                headers={'Content-Length': 0, 'Accept': 'application/json'})
