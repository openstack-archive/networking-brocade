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

import netaddr
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils
from sqlalchemy.orm import exc

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.api.v2 import attributes
from neutron.common import constants as l3_constants
from neutron.common import exceptions as q_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.db import l3_dvr_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.i18n import _LE
from neutron.plugins.common import constants

from networking_brocade.vyatta.common import config
from networking_brocade.vyatta.common import exceptions as v_exc
from networking_brocade.vyatta.common import utils as vyatta_utils
from networking_brocade.vyatta.vrouter import driver as vrouter_driver


LOG = logging.getLogger(__name__)


class VyattaVRouterMixin(common_db_mixin.CommonDbMixin,
                         extraroute_db.ExtraRoute_db_mixin,
                         l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                         l3_gwmode_db.L3_NAT_db_mixin,
                         l3_agentschedulers_db.L3AgentSchedulerDbMixin):
    """Brocade Neutron L3 Plugin for Vyatta vRouter.

    Supports CRUD operations on vRouter, add/remove interfaces from vRouter
    and floating IPs for VMs.It performs vRouter VM lifecyle management by
    calling Nova APIs during the Create and Delete Router calls.
    Once the vRouter VM is up, L3 plugin uses REST API to perform the
    configurations. L3 plugin supports add/remove router interfaces by
    attaching the neutron ports to vRouter VM using Nova API.
    RPC notifications will be used by the firewall agent that is coupled
    with l3-agent. This is needed for our firewall plugin.
    """

    ATTACH_PORT_RETRY_LIMIT = 5
    ATTACH_PORT_RETRY_DELAY = 5

    def __init__(self):
        self.setup_rpc()
        self.driver = vrouter_driver.VyattaVRouterDriver()
        self.router_scheduler = importutils.import_object(
            config.CONF.router_scheduler_driver)
        self.start_periodic_l3_agent_status_check()

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.agent_notifiers.update(
            {l3_constants.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})
        self.endpoints = [_VyattaL3RPCEndpoint()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """Returns string description of the plugin."""
        return ("Brocade Vyatta Router Service Plugin for basic L3 forwarding "
                "between (L2) Neutron networks and access to external "
                "networks via a NAT gateway.")

    def create_router(self, context, router):
        """Creates the vRouter VM using vrouter_driver.

        If we encounter vRouter VM creation failure or connectivity failure
        vrouter_driver will handle the appropriate exceptions and delete
        the vRouter VM.
        """
        LOG.debug("Vyatta vRouter Plugin::Create router: %s", router)

        r = router['router']
        router_id = self.driver.create_router(context)
        if router_id is None:
            raise q_exc.BadRequest(
                resource='router',
                msg=_('Vyatta vRouter creation failed'))

        gw_info = r.pop(l3.EXTERNAL_GW_INFO, attributes.ATTR_NOT_SPECIFIED)

        tenant_id = self._get_tenant_id_for_create(context, r)

        with context.session.begin(subtransactions=True):
            # noinspection PyArgumentList
            router_db = l3_db.Router(id=router_id,
                                     tenant_id=tenant_id,
                                     name=r['name'],
                                     admin_state_up=r['admin_state_up'],
                                     status="ACTIVE")
            context.session.add(router_db)
            self._process_extra_attr_router_create(context, router_db, router)
            router_dict = self._make_router_dict(router_db)

        try:
            self.driver.init_router(context, router_dict)
        except (v_exc.InvalidVRouterInstance,
                v_exc.InvalidInstanceConfiguration,
                v_exc.VRouterConnectFailure,
                v_exc.VRouterOperationError,
                Exception):
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    context.session.delete(router_db)

        if gw_info != attributes.ATTR_NOT_SPECIFIED:
            self._update_router_gw_info(context, router_db['id'], gw_info)
            router_dict[l3.EXTERNAL_GW_INFO] = gw_info

        return self._make_router_dict(router_db)

    def update_router(self, context, router_id, router):
        LOG.debug("Vyatta vRouter Plugin::Update router: %s", router)

        r = router['router']

        gw_info = r.pop(l3.EXTERNAL_GW_INFO, attributes.ATTR_NOT_SPECIFIED)

        if gw_info != attributes.ATTR_NOT_SPECIFIED:
            self._update_router_gw_info(context, router_id, gw_info)

        return super(VyattaVRouterMixin, self).update_router(
            context, router_id, router)

    def delete_router(self, context, router_id):
        LOG.debug("Vyatta vRouter Plugin::Delete router: %s", router_id)

        gw_port = None

        with context.session.begin(subtransactions=True):
            router = self._get_router(context, router_id)

            self._ensure_router_not_in_use(context, router_id)

            # delete any gw port
            device_filter = {
                'device_id': [router_id],
                'device_owner': [l3_constants.DEVICE_OWNER_ROUTER_GW]
            }
            ports = self._core_plugin.get_ports(context.elevated(),
                                                filters=device_filter)

            if ports:
                gw_port = ports[0]
                router.gw_port = None
                context.session.add(router)

        if gw_port:
            self._delete_router_port(context, router_id, gw_port)

        with context.session.begin(subtransactions=True):
            context.session.delete(router)

        self.driver.delete_router(context, router_id)

        self.l3_rpc_notifier.router_deleted(context, router_id)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug("Vyatta vRouter Plugin::Add Router Interface. "
                  "router: %s; interface: %s", router_id, interface_info)
        router = self._get_router(context, router_id)

        self._validate_interface_info(interface_info)

        port_tenant_id = None

        if 'port_id' in interface_info:
            # make sure port update is committed
            with context.session.begin(subtransactions=True):
                if 'subnet_id' in interface_info:
                    msg = _("Cannot specify both subnet-id and port-id")
                    raise q_exc.BadRequest(resource='router', msg=msg)

                port = self._core_plugin._get_port(context.elevated(),
                                                   interface_info['port_id'])
                if port['device_id']:
                    raise q_exc.PortInUse(net_id=port['network_id'],
                                          port_id=port['id'],
                                          device_id=port['device_id'])
                fixed_ips = [ip for ip in port['fixed_ips']]
                if len(fixed_ips) != 1:
                    msg = _('Router port must have exactly one fixed IP')
                    raise q_exc.BadRequest(resource='router', msg=msg)
                subnet_id = fixed_ips[0]['subnet_id']
                subnet = self._core_plugin._get_subnet(context.elevated(),
                                                       subnet_id)
                self._check_for_dup_router_subnet(context, router,
                                                  port['network_id'],
                                                  subnet['id'],
                                                  subnet['cidr'])
            port_tenant_id = port['tenant_id']
            port = self._core_plugin.update_port(
                context.elevated(), port['id'], {'port': {
                    'tenant_id': config.VROUTER.tenant_id,
                }})
            port_created = False
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._core_plugin._get_subnet(context.elevated(),
                                                   subnet_id)

            # Ensure the subnet has a gateway
            if not subnet['gateway_ip']:
                msg = _('Subnet for router interface must have a gateway IP')
                raise q_exc.BadRequest(resource='router', msg=msg)
            if (subnet['ip_version'] == 6 and subnet['ipv6_ra_mode'] is None
                    and subnet['ipv6_address_mode'] is not None):
                msg = (_('IPv6 subnet %s configured to receive RAs from an '
                       'external router cannot be added to Neutron Router.') %
                       subnet['id'])
                raise q_exc.BadRequest(resource='router', msg=msg)
            self._check_for_dup_router_subnet(context, router,
                                              subnet['network_id'],
                                              subnet_id,
                                              subnet['cidr'])

            fixed_ip = {'ip_address': subnet['gateway_ip'],
                        'subnet_id': subnet['id']}

            port_tenant_id = subnet['tenant_id']
            port = self._core_plugin.create_port(context.elevated(), {
                'port': {
                    'tenant_id': config.VROUTER.tenant_id,
                    'network_id': subnet['network_id'],
                    'fixed_ips': [fixed_ip],
                    'mac_address': attributes.ATTR_NOT_SPECIFIED,
                    'admin_state_up': True,
                    'device_id': '',
                    'device_owner': '',
                    'name': '',
                }
            })
            port_created = True

        try:
            self._attach_port(context, router_id, port)
        except Exception:
            with excutils.save_and_reraise_exception():
                if port_created:
                    try:
                        self._core_plugin.delete_port(context.elevated(),
                                                      port['id'])
                    except Exception:
                        LOG.exception(_LE(
                            'Failed to delete previously created '
                            'port for Vyatta vRouter.'))

        port = self._core_plugin.update_port(
            context.elevated(), port['id'], {'port': {
                'tenant_id': port_tenant_id,
            }})

        with context.session.begin(subtransactions=True):
            router_port = l3_db.RouterPort(
                port_id=port['id'],
                router_id=router.id,
                port_type=port['device_owner']
            )
            context.session.add(router_port)

        router_interface_info = self._make_router_interface_info(
            router_id, port['tenant_id'], port['id'],
            port['fixed_ips'][0]['subnet_id'])
        self.notify_router_interface_action(
            context, router_interface_info, 'add')
        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug("Vyatta vRouter Plugin::Remove Router Interface. "
                  "router: %s; interface_info: %s", router_id, interface_info)

        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise q_exc.BadRequest(resource='router', msg=msg)

        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            port_db = self._core_plugin._get_port(context.elevated(), port_id)
            if not (port_db['device_owner'] ==
                    l3_constants.DEVICE_OWNER_ROUTER_INTF and
                    port_db['device_id'] == router_id):
                raise l3.RouterInterfaceNotFound(router_id=router_id,
                                                 port_id=port_id)
            if 'subnet_id' in interface_info:
                port_subnet_id = port_db['fixed_ips'][0]['subnet_id']
                if port_subnet_id != interface_info['subnet_id']:
                    raise q_exc.SubnetMismatchForPort(
                        port_id=port_id,
                        subnet_id=interface_info['subnet_id'])
            subnet_id = port_db['fixed_ips'][0]['subnet_id']
            subnet = self._core_plugin._get_subnet(context.elevated(),
                                                   subnet_id)
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet_id)
            port = port_db
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            self._confirm_router_interface_not_in_use(context, router_id,
                                                      subnet_id)
            subnet = self._core_plugin._get_subnet(context.elevated(),
                                                   subnet_id)
            found = False
            try:
                rport_qry = context.session.query(models_v2.Port)
                ports = rport_qry.filter_by(
                    device_id=router_id,
                    device_owner=l3_constants.DEVICE_OWNER_ROUTER_INTF,
                    network_id=subnet['network_id'])

                for p in ports:
                    if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                        port = p
                        found = True
                        break
            except exc.NoResultFound:
                pass

            if not found:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                          subnet_id=subnet_id)

        port = self._core_plugin.update_port(
            context.elevated(), port['id'], {'port': {
                'tenant_id': config.VROUTER.tenant_id,
            }})

        self._delete_router_port(context, router_id, port)

        router_interface_info = self._make_router_interface_info(
            router_id, subnet['tenant_id'], port['id'], subnet['id'])
        self.notify_router_interface_action(
            context, router_interface_info, 'remove')
        return router_interface_info

    def _get_interface_infos(self, context, port):
        LOG.debug("Vyatta vRouter Plugin::Get interface infos")

        mac_address = port['mac_address']
        interface_infos = []
        for fip in port['fixed_ips']:
            try:
                subnet = self._core_plugin._get_subnet(context.elevated(),
                                                       fip['subnet_id'])
                ipnet = netaddr.IPNetwork(subnet.cidr)
                interface_infos.append({
                    'mac_address': mac_address,
                    'ip_address': '{0}/{1}'.format(fip['ip_address'],
                                                   ipnet.prefixlen),
                    'gateway_ip': subnet.gateway_ip
                })
            except q_exc.SubnetNotFound:
                pass
        return interface_infos

    def _delete_router_port(self, context, router_id, port, external_gw=False):
        # Get instance, deconfigure interface and detach port from it. To do
        # this need to change port owner back to that instance.
        LOG.debug("Vyatta vRouter Plugin::Delete router port. "
                  "router: %s; port: %s", router_id, port)

        self.driver.deconfigure_interface(
            context, router_id, self._get_interface_infos(context.elevated(),
                                                          port))

        self._core_plugin.update_port(context.elevated(), port['id'],
                                      {'port': {'device_owner': '',
                                                'device_id': router_id}})
        self.driver.detach_interface(context, router_id, port['id'])

        self._core_plugin.delete_port(context.elevated(), port['id'])

    def _attach_port(self, context, router_id, port, external_gw=False):
        LOG.debug("Vyatta vRouter Plugin::Attach port. "
                  "router: %s; port: %s", router_id, port)
        # Attach interface
        self.driver.attach_interface(context, router_id, port['id'])

        def configure_gateway_wrapper():
            if external_gw:
                self.driver.configure_gateway(
                    context, router_id,
                    self._get_interface_infos(context, port))
            else:
                self.driver.configure_interface(
                    context, router_id,
                    self._get_interface_infos(context, port))

        vyatta_utils.retry(
            configure_gateway_wrapper,
            exceptions=(v_exc.VRouterOperationError,),
            limit=self.ATTACH_PORT_RETRY_LIMIT,
            delay=self.ATTACH_PORT_RETRY_DELAY)

        if external_gw:
            device_owner = l3_constants.DEVICE_OWNER_ROUTER_GW
        else:
            device_owner = l3_constants.DEVICE_OWNER_ROUTER_INTF
        self._core_plugin.update_port(context.elevated(), port['id'],
                                      {'port': {'device_owner': device_owner,
                                                'device_id': router_id}})

    def _update_router_gw_info(self, context, router_id, info, router=None):
        LOG.debug("Vyatta vRouter Plugin::Update router gateway info")

        router = router or self._get_router(context, router_id)
        gw_port = router.gw_port
        ext_ips = info.get('external_fixed_ips') if info else []
        network_id = self._validate_gw_info(context, gw_port, info, ext_ips)
        ext_ip_change = self._check_for_external_ip_change(
            context, gw_port, ext_ips)

        self._delete_current_gw_port(context, router_id, router, network_id,
                                     ext_ip_change)
        self._create_gw_port(context, router_id, router, network_id, ext_ips,
                             ext_ip_change)

    def _delete_current_gw_port(self, context, router_id, router, new_network,
                                ext_ip_change):
        """Delete gw port if attached to an old network or IPs changed."""
        port_requires_deletion = (
            router.gw_port and
            (router.gw_port['network_id'] != new_network or ext_ip_change)
        )
        if not port_requires_deletion:
            return
        admin_ctx = context.elevated()
        if self.get_floatingips_count(
                admin_ctx, {'router_id': [router_id]}):
            raise l3.RouterExternalGatewayInUseByFloatingIp(
                router_id=router_id, net_id=router.gw_port['network_id'])

        gw_port = router.gw_port
        self.driver.clear_gateway(
            context, router_id,
            self._get_interface_infos(context.elevated(),
                                      gw_port))
        with context.session.begin(subtransactions=True):
            router.gw_port = None
            context.session.add(router)
            context.session.expire(gw_port)
            self._check_router_gw_port_in_use(context, router_id)

        self._delete_router_port(
            context, router_id, gw_port, external_gw=True)

    def _create_router_gw_port(self, context, router, network_id, ext_ips):
        if ext_ips and len(ext_ips) > 1:
            msg = _("Routers support only 1 external IP")
            raise q_exc.BadRequest(resource='router', msg=msg)

        gw_port = self._core_plugin.create_port(context.elevated(), {
            'port': {
                'tenant_id': config.VROUTER.tenant_id,
                'network_id': network_id,
                'mac_address': attributes.ATTR_NOT_SPECIFIED,
                'fixed_ips': ext_ips or attributes.ATTR_NOT_SPECIFIED,
                'device_owner': '',
                'device_id': '',
                'admin_state_up': True,
                'name': ''
            }})

        if not gw_port['fixed_ips']:
            self._core_plugin.delete_port(context.elevated(), gw_port['id'],
                                          l3_port_check=False)
            msg = (_('No IPs available for external network %s') %
                   network_id)
            raise q_exc.BadRequest(resource='router', msg=msg)

        with context.session.begin(subtransactions=True):
            router.gw_port = self._core_plugin._get_port(context.elevated(),
                                                         gw_port['id'])
            router_port = l3_db.RouterPort(
                router_id=router.id,
                port_id=gw_port['id'],
                port_type=l3_constants.DEVICE_OWNER_ROUTER_GW
            )
            context.session.add(router)
            context.session.add(router_port)

        try:
            self._attach_port(context, router['id'], gw_port,
                              external_gw=True)
        except Exception as ex:
            LOG.exception(_LE("Exception while attaching port : %s"), ex)
            with excutils.save_and_reraise_exception():
                try:
                    with context.session.begin(subtransactions=True):
                        router.gw_port = None
                        context.session.add(router)
                        self._core_plugin.delete_port(context.elevated(),
                                                      gw_port['id'])
                except Exception:
                    LOG.exception(_LE('Failed to roll back changes to '
                                    'Vyatta vRouter after external '
                                    'gateway assignment.'))

    def _update_extra_routes(self, context, router, routes):
        LOG.debug(
            'Vyatta vRouter Plugin::update static routes. '
            'router_id={0}'.format(router['id']))

        routes_old = self._get_extra_routes_by_router_id(
            context, router['id'])
        super(VyattaVRouterMixin, self)._update_extra_routes(
            context, router, routes)
        routes_new = self._get_extra_routes_by_router_id(
            context, router['id'])

        routes_old = self._route_rules_to_set(routes_old)
        routes_new = self._route_rules_to_set(routes_new)

        self.driver.update_static_routes(
            context, router['id'],
            tuple(routes_new - routes_old),
            tuple(routes_old - routes_new))

    @staticmethod
    def _route_rules_to_set(rules):
        result = set()
        for r in rules:
            result.add(vyatta_utils.RouteRule(
                dest_cidr=r['destination'], next_hop=r['nexthop']))
        return result

    def create_floatingip(
            self, context, floatingip,
            initial_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        LOG.debug("Vyatta vRouter Plugin::Create floating ip")

        floatingip_dict = super(VyattaVRouterMixin, self).create_floatingip(
            context, floatingip,
            initial_status=initial_status)
        router_id = floatingip_dict['router_id']
        if router_id:
            self.associate_floatingip(context, router_id, floatingip_dict)
        return floatingip_dict

    def associate_floatingip(self, context, router_id, floatingip):
        LOG.debug("Vyatta vRouter Plugin::Associate floating ip")

        fixed_ip = floatingip['fixed_ip_address']
        floating_ip = floatingip['floating_ip_address']
        if router_id:
            self.driver.assign_floating_ip(
                context, router_id, floating_ip, fixed_ip)
            with context.session.begin(subtransactions=True):
                floatingip_db = self._get_floatingip(context, floatingip['id'])
                floatingip_db['status'] = l3_constants.FLOATINGIP_STATUS_ACTIVE

    def update_floatingip(self, context, floatingip_id, floatingip):
        LOG.debug("Vyatta vRouter Plugin::Update floating ip")

        fip = floatingip['floatingip']
        with context.session.begin(subtransactions=True):
            floatingip_db = self._get_floatingip(context, floatingip_id)
            old_floatingip = self._make_floatingip_dict(floatingip_db)
            fip['tenant_id'] = floatingip_db['tenant_id']
            fip['id'] = floatingip_id
            fip_port_id = floatingip_db['floating_port_id']
            before_router_id = floatingip_db['router_id']
            self._update_fip_assoc(context, fip, floatingip_db,
                                   self._core_plugin.get_port(
                                       context.elevated(), fip_port_id))

        if before_router_id:
            self.disassociate_floatingip(
                context, before_router_id, old_floatingip)

        router_id = floatingip_db['router_id']
        if router_id:
            self.associate_floatingip(context, router_id, floatingip_db)

        return self._make_floatingip_dict(floatingip_db)

    def delete_floatingip(self, context, floatingip_id):
        LOG.debug("Vyatta vRouter Plugin::Delete floating ip: %s",
                  floatingip_id)

        floatingip_dict = self._get_floatingip(context, floatingip_id)
        router_id = floatingip_dict['router_id']
        if router_id:
            self.disassociate_floatingip(context, router_id, floatingip_dict)
        super(VyattaVRouterMixin, self).delete_floatingip(
            context, floatingip_id)

    def disassociate_floatingip(self, context, router_id, floatingip):
        LOG.debug("Vyatta vRouter Plugin::Disassociate floating ip."
                  "router: %s; floating_ip: %s", router_id, floatingip)

        fixed_ip = floatingip['fixed_ip_address']
        floating_ip = floatingip['floating_ip_address']
        if router_id:
            self.driver.unassign_floating_ip(
                context, router_id, floating_ip, fixed_ip)
            with context.session.begin(subtransactions=True):
                floatingip_db = self._get_floatingip(context, floatingip['id'])
                floatingip_db['status'] = l3_constants.FLOATINGIP_STATUS_DOWN

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        LOG.debug("Vyatta vRouter Plugin::Disassociate floating ips."
                  "port_id: %s", port_id)

        with context.session.begin(subtransactions=True):
            fip_qry = context.session.query(l3_db.FloatingIP)
            floating_ips = fip_qry.filter_by(fixed_port_id=port_id)
            for floating_ip in floating_ips:
                self.disassociate_floatingip(
                    context, floating_ip['router_id'], floating_ip)

        return super(VyattaVRouterMixin, self).disassociate_floatingips(
            context, port_id, do_notify)


class _VyattaL3RPCEndpoint(l3_rpc.L3RpcCallback):
    def sync_routers(self, context, **kwargs):
        routers_list = super(_VyattaL3RPCEndpoint, self).sync_routers(
            context, **kwargs)

        if not routers_list:
            return routers_list

        routers_by_id = dict((x['id'], x) for x in routers_list)

        query = context.session.query(models_v2.Port)
        query = query.filter(models_v2.Port.network_id
                             == config.VROUTER.management_network_id)
        query = query.filter(models_v2.Port.device_id.in_(routers_by_id))

        need_processed = set(routers_by_id)
        for port in query:
            router_id = port['device_id']

            try:
                need_processed.remove(router_id)
            except KeyError:
                raise v_exc.CorruptedSystemError(
                    description=(
                        'router {0} contain multiple interface joined to '
                        'management network').format(router_id))

            # this statement can't raise KeyError because query condition
            router = routers_by_id[router_id]

            try:
                ip = port['fixed_ips']
                ip = ip[0]
                ip = ip['ip_address']
            except (IndexError, KeyError):
                raise v_exc.CorruptedSystemError(
                    description=(
                        'vyatta vrouter id={0} management interface have no '
                        'ip address').format(router_id))

            router['_vyatta'] = {
                'management_ip_address': ip}

        if need_processed:
            raise v_exc.CorruptedSystemError(
                description=(
                    'vyatta vrouters not linked to management network: '
                    '{0}').format(', '.join(sorted(need_processed))))

        return routers_list
