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

from novaclient.v1_1 import client as novaclient

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import router_info
from neutron.agent import l3_agent as entry
from neutron.common import constants as l3_constants

from networking_brocade.vyatta.common import config as vyatta_config
from networking_brocade.vyatta.common import exceptions as v_exc
from networking_brocade.vyatta.vrouter import client as vyatta_client


_KEY_VYATTA_EXTRA_DATA = '_vyatta'
_KEY_MANAGEMENT_IP_ADDRESS = 'management_ip_address'


class L3AgentMiddleware(l3_agent.L3NATAgentWithStateReport):
    def __init__(self, host, conf=None):
        super(L3AgentMiddleware, self).__init__(host, conf)

        compute_client = novaclient.Client(
            vyatta_config.VROUTER.tenant_admin_name,
            vyatta_config.VROUTER.tenant_admin_password,
            auth_url=vyatta_config.CONF.nova_admin_auth_url,
            service_type="compute",
            tenant_id=vyatta_config.VROUTER.tenant_id)
        self._vyatta_clients_pool = vyatta_client.ClientsPool(compute_client)

    def get_router(self, router_id):
        try:
            router = self.router_info[router_id]
        except KeyError:
            raise v_exc.InvalidL3AgentStateError(description=_(
                'L3 agent have no info about reouter id={0}').format(
                    router_id))
        return router.router

    def get_router_client(self, router_id):
        router = self.get_router(router_id)
        try:
            address = router[_KEY_VYATTA_EXTRA_DATA]
            address = address[_KEY_MANAGEMENT_IP_ADDRESS]
        except KeyError:
            raise v_exc.CorruptedSystemError(
                description=('router {0} does not contain vyatta vrouter '
                             'management ip address').format(router_id))
        return self._vyatta_clients_pool.get_by_address(router_id, address)

    def _router_added(self, router_id, router):
        ri = router_info.RouterInfo(
            router_id, router, self.conf, self.driver)
        self.router_info[router_id] = ri
        self.process_router_add(ri)

    def _router_removed(self, router_id):
        ri = self.router_info[router_id]
        if ri:
            ri.router['gw_port'] = None
            ri.router[l3_constants.INTERFACE_KEY] = []
            ri.router[l3_constants.FLOATINGIP_KEY] = []
            self.process_router(ri)

        del self.router_info[router_id]

    def _create_router_namespace(self, ri):
        """terminate super call to avoid calls to iptables"""
        pass

    def _destroy_router_namespace(self, namespace):
        """terminate super call to avoid calls to iptables"""
        pass

    def _spawn_metadata_proxy(self, router_id, ns_name):
        """terminate super call to avoid calls to iptables"""
        pass

    def _destroy_metadata_proxy(self, router_id, ns_name):
        """terminate super call to avoid calls to iptables"""
        pass

    def _handle_router_snat_rules(self, ri, ex_gw_port,
                                  interface_name, action):
        """terminate super call to avoid calls to iptables"""
        pass

    def _send_gratuitous_arp_packet(self, ns_name, interface_name, ip_address,
                                    distributed=False):
        """terminate super call to avoid calls to iptables"""
        pass

    def _update_routing_table(self, ri, operation, route):
        """terminate super call to avoid calls to iptables"""
        pass

    def process_router(self, ri):
        pass

    def _get_router_info_list_for_tenant(self, router_ids, tenant_id):
        """Returns the list of router info objects on which to apply the fw."""
        router_info_list = []
        # Pick up namespaces for Tenant Routers
        for rid in router_ids:
            # for routers without an interface - get_routers returns
            # the router - but this is not yet populated in router_info
            if rid not in self.router_info:
                continue
            router_info_list.append(self.router_info[rid])
        return router_info_list


def main():
    entry.main(
        manager='networking_brocade.vyatta.common.l3_agent.L3AgentMiddleware')
