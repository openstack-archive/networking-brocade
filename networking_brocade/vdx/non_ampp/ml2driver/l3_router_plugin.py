# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2016 Brocade Communications System, Inc.
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


"""Implentation of Brocade SVI service Plugin."""
from networking_brocade.vdx.db import models as brocade_db
from networking_brocade.vdx.non_ampp.ml2driver.nos import nosdriver as driver
from networking_brocade.vdx.non_ampp.ml2driver import utils
from neutron.api.v2 import attributes
from neutron.common import constants as l3_constants
from neutron.common import utils as neutron_utils
from neutron.db import models_v2
from neutron.extensions import extraroute
from neutron.i18n import _
from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import constants as plugin_constants
from neutron.services.l3_router import l3_router_plugin as router
from oslo_log import log as logging
from oslo_utils import excutils

DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP

LOG = logging.getLogger(__name__)


class BrocadeSVIPlugin(router.L3RouterPlugin):

    def __init__(self):
        """Initialize Brocade Plugin.
        Specify switch address and db configuration.
        """
        super(BrocadeSVIPlugin, self).__init__()
        self._driver = None
        self._switch = None
        self.brocade_init()

    def brocade_init(self):
        """Brocade specific initialization."""
        LOG.debug("brocade init brocadeSVIPlugin")
        self._switch = utils.get_brocade_credentials()
        self._svi = utils.get_brocade_l3_config()
        LOG.info(_LI("rbridge id %(rbridge id)s redundancy %(redundancy)s") %
                 {'rbridge id': self._svi['rbridge_ids'],
                  'redundancy': self._svi['redundancy']})

        self._driver = driver.NOSdriver(self._switch['address'],
                                        self._switch['username'],
                                        self._switch['password'])
        if self._svi['redundancy']:
            for rbridge_id in self._svi['rbridge_ids']:
                LOG.info(_LI("rbridge id %s protocol vrrp enabled"),
                         rbridge_id)
                self._driver.configure_protocol_vrrp(rbridge_id)
        self._driver.close_session()

    def _update_ips_for_port(self, context, port):
        LOG.info(_LI("_update_ips_for_port called()"))
        port['fixed_ips'] is not attributes.ATTR_NOT_SPECIFIED
        filter = {'network_id': [port['network_id']]}
        subnets = self._core_plugin.get_subnets(context, filters=filter)
        result = self._core_plugin.ipam._generate_ip(context, subnets)
        LOG.info(_LI("_update_ips_for_port generated ip %s"), result)

        allocated = models_v2.IPAllocation(network_id=port['network_id'],
                                           port_id=port['id'],
                                           ip_address=result['ip_address'],
                                           subnet_id=result['subnet_id'])
        context.session.add(allocated)
        return result

    def _invoke_nos_driver_api(self, func_name, router_id,
                               vlan_id=None,
                               gateway_ip_cidr=None,
                               context=None,
                               port=None,
                               added=None,
                               removed=None):
        LOG.info(_LI("_invoke_nos_driver_api called()"))
        self._switch
        priority = 1
        if self._svi['redundancy'] and\
            (func_name == 'delete_svi' or
             func_name == 'create_svi'):
            vip, net_len = self.net_addr(gateway_ip_cidr)
            LOG.info(_LI("_invoke_nos_driver_api vip %(vip)s"
                         " net_len %(net_len)s") %
                     {'vip': vip, 'net_len': net_len})

        for rbridge_id in self._svi['rbridge_ids']:
            if func_name == 'create_router' or\
               func_name == 'delete_router':
                self._driver.__getattribute__(func_name)(rbridge_id,
                                                         str(router_id))
            elif func_name == 'create_svi':
                if self._svi['redundancy']:
                    LOG.info(_LI("calling update_ips_for_port"))
                    res = self._update_ips_for_port(context, port)
                    gateway_ip_cidr = res['ip_address'] + '/' + str(net_len)
                    LOG.info(_LI("after _update_ips_for_port generated"
                                 " gate_ip_cidr %s"), gateway_ip_cidr)

                LOG.info(_LI("invoke create svi"))
                self._driver.__getattribute__(func_name)(rbridge_id,
                                                         vlan_id,
                                                         gateway_ip_cidr,
                                                         str(router_id))
                if self._svi['redundancy']:
                    vrrp_version = self._svi['vrrp_version']
                    vrrp_group_id = self._svi['vrrp_group_id']
                    vrrp_advt_interval =\
                        self._svi['vrrp_advertisement_interval']
                    try:
                        self._driver.configure_vrrp_on_svi(rbridge_id,
                                                           vlan_id,
                                                           vrrp_group_id,
                                                           vrrp_version,
                                                           vip,
                                                           vrrp_advt_interval,
                                                           priority)
                        priority += 1
                    except Exception:
                        self._driver.delete_svi(rbridge_id, vlan_id,
                                                gateway_ip_cidr,
                                                str(router_id))
                        raise "vrrp configuration failed on NOS"

            elif func_name == 'delete_svi':
                self._driver.__getattribute__(func_name)(rbridge_id,
                                                         vlan_id,
                                                         gateway_ip_cidr,
                                                         str(router_id))
            elif func_name == 'update_router':
                self._driver.__getattribute__(func_name)(rbridge_id,
                                                         str(router_id),
                                                         added,
                                                         removed)

    def create_router(self, context, router):
        """creates a vrf on NOS device """
        r = router['router']
        self._get_tenant_id_for_create(context, r)
        with context.session.begin(subtransactions=True):
            new_router = super(BrocadeSVIPlugin, self).create_router(context,
                                                                     router)
        try:
            # Router on VDX
            self._invoke_nos_driver_api("create_router", new_router['id'])
        except Exception as e:
            LOG.error(_LE("Failed to create router Reason %s"), str(e))
            raise e
        return new_router

    def _validate_routes_nexthop(self, cidrs, ips, routes, nexthop):
        # lets skip to check connected routes
        # lets keep it FR
        if nexthop in ips:
            raise extraroute.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is used by router'))

    def update_router(self, context, router_id, router):
        """Update the router with static route"""
        r = router['router']
        if "routes" not in r:
            updated_router = super(BrocadeSVIPlugin, self).\
                update_router(context, router_id, router)
            return updated_router

        old_routes, routes_dict = self._get_extra_routes_dict_by_router_id(
            context, router_id)
        added, removed = neutron_utils.diff_list_of_dict(old_routes,
                                                         r['routes'])
        try:
            updated_router = super(BrocadeSVIPlugin, self).\
                update_router(context, router_id, router)
            self._invoke_nos_driver_api('update_router',
                                        router_id,
                                        None,
                                        None,
                                        None,
                                        None,
                                        added,
                                        removed)
        except Exception as e:
            LOG.error(_LE("Failed to modify route %s"), str(e))
            raise e
        return updated_router

    def delete_router(self, context, router_id):
        """delete a vrf on NOS device """
        router = super(BrocadeSVIPlugin, self).get_router(context, router_id)
        router['tenant_id']
        with context.session.begin(subtransactions=True):
            super(BrocadeSVIPlugin, self).delete_router(context, router_id)
        try:
            self._invoke_nos_driver_api("delete_router", router['id'])
        except Exception as e:
            LOG.error(_LE("Failed to delete router Reason %s"), str(e))
            raise e

    def add_router_interface(self, context, router_id, interface_info):
        """creates svi on NOS device and assigns ip addres to SVI"""
        LOG.debug("BrocadeSVIPlugin.add_router_interface called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})
        with context.session.begin(subtransactions=True):
            info = super(BrocadeSVIPlugin, self).add_router_interface(
                context, router_id, interface_info)
        try:
            port = self._core_plugin._get_port(context, info["port_id"])
            # shutting  down neutron port to allow NOS to do Arp/Routing
            # Propose to community to allow this to do more gracefully
            port.update({"admin_state_up": False})
            interface_info = info
            subnet = self._core_plugin._get_subnet(context,
                                                   interface_info["subnet_id"])
            cidr = subnet["cidr"]
            net_addr, net_len = self.net_addr(cidr)
            gateway_ip = subnet["gateway_ip"]
            network_id = subnet['network_id']
            tenant_id = subnet['tenant_id']
            bnet = brocade_db.get_network(context, network_id)
            vlan_id = bnet['vlan']
            gateway_ip_cidr = gateway_ip + '/' + str(net_len)
            LOG.debug("Allocated cidr (%s) from the pool, network_id(%s)"
                      "bnet (%s) vlan (%d) ", gateway_ip_cidr, network_id,
                      bnet, int(vlan_id))
            port_filters = {'network_id': [network_id],
                            'device_owner': [DEVICE_OWNER_ROUTER_INTF]}
            port_count = self._core_plugin.get_ports_count(context,
                                                           port_filters)
            LOG.info(_LI("BrocadeSVIPlugin.add_router_interface"
                         " ports_count %d"), port_count)
            # port count is checked against 2 since the
            # current port is already added to db
            if port_count == 2:
                # This subnet is already part of some router is not
                # supported
                # in this version of brocadesvi plugin
                LOG.error(_LE("BrocadeSVIPlugin:adding redundent router"
                              "interface is not supported"))
                raise Exception(_("BrocadeSVIPlugin:adding redundent"
                                  "router interface is not supported"))
            # res = self._update_ips_for_port(context, port)
            # gateway_ip = res['ip_address']
            # gateway_ip_cidr  = gateway_ip +'/'+str(net_len)
            brocade_db.create_svi(context, router_id, tenant_id, str(vlan_id),
                                  True, gateway_ip, str(net_len))
            self._invoke_nos_driver_api("create_svi", router_id, vlan_id,
                                        gateway_ip_cidr, context, port)
            self._update_firewall(context, vlan_id, tenant_id)

        except Exception:
            LOG.error(_LE("Failed to create Brocade resources to add router "
                          "interface. info=%(info)s, router_id=%(router_id)s"),
                      {"info": info, "router_id": router_id})
            with excutils.save_and_reraise_exception():
                self._invoke_nos_driver_api("delete_svi", router_id,
                                            vlan_id, gateway_ip_cidr)
                with context.session.begin(subtransactions=True):
                    info = super(BrocadeSVIPlugin, self).\
                        remove_router_interface(context,
                                                router_id,
                                                interface_info)

        return info

    def remove_router_interface(self, context, router_id, interface_info):
        """Deletes svi from NOS device"""
        LOG.debug("BrocadeSVIPlugin.remove_router_interface called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})
        remove_by_port, remove_by_subnet = (
            self._validate_interface_info(interface_info, for_removal=True)
        )
        with context.session.begin(subtransactions=True):
            info = super(BrocadeSVIPlugin, self).remove_router_interface(
                context, router_id, interface_info)

        try:
            subnet = self._core_plugin._get_subnet(context, info['subnet_id'])
            if self._svi['redundancy'] and remove_by_subnet:
                self._core_plugin.delete_port(context, info['port_id'],
                                              l3_port_check=False)
            cidr = subnet['cidr']
            net_addr, net_len = self.net_addr(cidr)
            gateway_ip = subnet['gateway_ip']
            network_id = subnet['network_id']
            tenant_id = subnet['tenant_id']
            bnet = brocade_db.get_network(context, network_id)
            vlan_id = bnet['vlan']
            gateway_ip_cidr = gateway_ip + '/' + str(net_len)
            LOG.debug("remove_router_interface removed cidr (%s)"
                      "from the pool, network_id (%s) bnet (%s) vlan (%d) ",
                      gateway_ip_cidr, network_id, bnet, int(vlan_id))
            brocade_db.delete_svi(context, router_id, tenant_id, vlan_id,
                                  gateway_ip, str(net_len))
            self._invoke_nos_driver_api("delete_svi", router_id,
                                        vlan_id, gateway_ip_cidr)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to remove interface from brocade router"
                              "interface. info=%(info)s,"
                              " router_id=%(router_id)s"),
                          {"info": info, "router_id": router_id})

    def _update_firewall(self, context, svi, tenant_id):
        """update newly added interface with firewall rules"""
        fw_plugin = manager.NeutronManager.get_service_plugins().get(
            plugin_constants.FIREWALL, None)

        if not fw_plugin:
            LOG.info(_LI('No Firewall plugin registered!!'))
            return
        context.tenant_id = tenant_id
        if hasattr(fw_plugin, 'handle_router_interface_add'):
            fw_plugin.handle_router_interface_add(context, svi, tenant_id)
        else:
            LOG.warning(_LW("Brocade SVI Plugin is used but brocade firewall"
                            " plugin you may want to configure"
                            " brocade firewall plugin"))

    @staticmethod
    def net_addr(addr):
        """Get network address prefix and length from a given address."""
        if addr is None:
            return (None, None)
        nw_addr, nw_len = addr.split('/')
        nw_len = int(nw_len)
        return nw_addr, nw_len
