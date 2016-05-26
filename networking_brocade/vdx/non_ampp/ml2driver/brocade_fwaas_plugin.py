# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Brocade Networks Inc.
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
import brocade_fwaas_driver as fwaas_driver

from networking_brocade.vdx.db import models as brocade_db
from networking_brocade.vdx.non_ampp.ml2driver import utils

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron.common import exceptions as n_exception
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron import manager
from neutron.plugins.common import constants as const

import neutron_fwaas
from neutron_fwaas.db.firewall import firewall_db
from neutron_fwaas.extensions import firewall as fw_ext
from neutron_fwaas.services.firewall import fwaas_plugin as plugin

import threading
LOG = logging.getLogger(__name__)


class RouterInfo(object):

    def __init__(self, router):
        self._router = router

    @property
    def router(self):
        return self._router


class FirewallCallbacks(object):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(FirewallCallbacks, self).__init__()
        self.plugin = plugin

    def set_firewall_status(self, context, firewall_id, status, **kwargs):
        """Agent uses this to set a firewall's status."""
        LOG.debug("Setting firewall %s to status: %s" % (firewall_id, status))
        # Sanitize status first
        if status in (const.ACTIVE, const.DOWN, const.INACTIVE):
            to_update = status
        else:
            to_update = const.ERROR
        # ignore changing status if firewall expects to be deleted
        # That case means that while some pending operation has been
        # performed on the backend, neutron server received delete request
        # and changed firewall status to PENDING_DELETE
        updated = self.plugin.update_firewall_status(
            context, firewall_id, to_update, not_in=(const.PENDING_DELETE,))
        if updated:
            LOG.debug("firewall %s status set: %s" % (firewall_id, to_update))
        return updated and to_update != const.ERROR

    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug("firewall_deleted() called")
        return

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Agent uses this to get all firewalls and rules for a tenant."""
        LOG.debug("get_firewalls_for_tenant() called")
        fw_list = []
        for fw in self.plugin.get_firewalls(context):
            fw_with_rules = self.plugin._make_firewall_dict_with_rules(
                context, fw['id'])
            if fw['status'] == const.PENDING_DELETE:
                fw_with_rules['add-router-ids'] = []
                fw_with_rules['del-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
            else:
                fw_with_rules['add-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
                fw_with_rules['del-router-ids'] = []
            fw_list.append(fw_with_rules)
        return fw_list

    def get_firewalls_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all firewalls for a tenant."""
        LOG.debug("get_firewalls_for_tenant_without_rules() called")
        fw_list = [fw for fw in self.plugin.get_firewalls(context)]
        return fw_list

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Agent uses this to get all tenants that have firewalls."""
        LOG.debug("get_tenants_with_firewalls() called")
        ctx = neutron_context.get_admin_context()
        fw_list = self.plugin.get_firewalls(ctx)
        fw_tenant_list = list(set(fw['tenant_id'] for fw in fw_list))
        return fw_tenant_list


class FirewallAgentApi(object):
    """Plugin side of plugin to agent RPC API."""

    def create_firewall(self, context, firewall):
        return

    def update_firewall(self, context, firewall):
        return

    def delete_firewall(self, context, firewall):
        return


class FirewallCountExceeded(n_exception.Conflict):

    """Reference implementation specific exception for firewall count.

    Only one firewall is supported per tenant. When a second
    firewall is tried to be created, this exception will be raised.
    """
    message = _("Exceeded allowed count of firewalls for tenant "
                "%(tenant_id)s. Only one firewall is supported per tenant.")


class BrocadeFirewallPlugin(plugin.FirewallPlugin):

    """Implementation of the Neutron Brocade Firewall Service Plugin.
       This class manages fwass request and response with the help
       fwaas_driver.BrocadeFwaasDriver
    """
    supported_extension_aliases = ["fwaas"]
    path_prefix = fw_ext.FIREWALL_PREFIX

    def __init__(self):
        ext_path = neutron_fwaas.extensions.__path__[0]
        if ext_path not in cfg.CONF.api_extensions_path.split(':'):
            cfg.CONF.set_override('api_extensions_path',
                                  cfg.CONF.api_extensions_path + ':' +
                                  ext_path)
        self._fwaas_driver = fwaas_driver.BrocadeFwaasDriver()
        self._lock = threading.Lock()
        self.endpoints = [FirewallCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = FirewallAgentApi()
        firewall_db.subscribe()

    def get_plugin_type(self):
        return const.FIREWALL

    def _is_l3_agent_running(self, context):
        l3plugin = manager.NeutronManager.get_service_plugins()[
            const.L3_ROUTER_NAT]
        if not l3plugin:
            LOG.error(_('No plugin for L3 routing registered! Will reply '
                        'no l3 agents!! '))
            return False
        l3_agents = l3plugin.get_l3_agents(context, True)
        LOG.info(_("List of L3 agents _is_l3_agent_running %s"), l3_agents)
        return ((l3_agents) and (len(l3_agents) > 0))

    def _get_routers(self, context):
        """get all active routers for tenant"""
        l3plugin = manager.NeutronManager.get_service_plugins()[
            const.L3_ROUTER_NAT]
        if not l3plugin:
            routers = {}
            LOG.error(_('No plugin for L3 routing registered! Will reply '
                        'to l3 agent with empty router dictionary.'))
            return routers
        routers = l3plugin._get_sync_routers(context)
        for r in routers:
            router_id = r['id']
            tenant_id = r['tenant_id']
            svis = brocade_db.get_list_svi_ids(context, router_id, tenant_id)
            r['svis'] = svis
        return routers

    def handle_router_interface_add(self, context, svi, tenant_id):
        fw_list = self.get_firewalls(context)
        for fw in fw_list:
            fw = self._make_firewall_dict(fw)
            policy_name = utils.get_firewall_object_prefix(fw)
            if fw['tenant_id'] == tenant_id and\
                    fw['status'] == const.ACTIVE:
                try:
                    if not self._fwaas_driver._is_policy_exists(policy_name):
                        fw_with_rules = (
                            self._make_firewall_dict_with_rules(context,
                                                                fw['id']))
                        self._invoke_driver_for_plugin_api(context,
                                                           fw_with_rules,
                                                           'update_firewall')
                    else:
                        self._fwaas_driver._apply_policy_on_interface(
                            policy_name, svi)
                except Exception as e:
                    LOG.error(_("Error adding Firewall rule to"
                                "interface %s "), e)
            elif fw['tenant_id'] == tenant_id and\
                    fw['status'] == const.PENDING_CREATE:
                fw_with_rules = (
                    self._make_firewall_dict_with_rules(context, fw['id']))
                self._invoke_driver_for_plugin_api(context, fw_with_rules,
                                                   'update_firewall')
                self.endpoints[0].set_firewall_status(context, fw['id'],
                                                      const.ACTIVE)

    def create_firewall(self, context, firewall):
        with self._lock:
            tenant_id = self._get_tenant_id_for_create(context,
                                                       firewall['firewall'])
            fw_count = self.get_firewalls_count(
                context, filters={'tenant_id': [tenant_id]})
            if fw_count:
                raise FirewallCountExceeded(tenant_id=tenant_id)

            fw = super(BrocadeFirewallPlugin, self).create_firewall(
                context, firewall)
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context, fw['id']))
            self._invoke_driver_for_plugin_api(context, fw_with_rules,
                                               'create_firewall')
            return fw

    def update_firewall(self, context, id, firewall):
        with self._lock:
            fw = super(BrocadeFirewallPlugin, self).update_firewall(context,
                                                                    id,
                                                                    firewall)
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context, fw['id']))
            self._invoke_driver_for_plugin_api(context, fw_with_rules,
                                               'update_firewall')
            return fw

    def delete_firewall(self, context, id):
        with self._lock:
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context, id))
            super(BrocadeFirewallPlugin, self).delete_db_firewall_object(
                context, id)
            self._invoke_driver_for_plugin_api(context, fw_with_rules,
                                               'delete_firewall')
            self.endpoints[0].firewall_deleted(context, id)

    def _rpc_update_firewall(self, context, firewall_id):
        with self._lock:
            super(BrocadeFirewallPlugin, self)._rpc_update_firewall(
                context, firewall_id)
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context,
                                                    firewall_id))
            self._invoke_driver_for_plugin_api(context,
                                               fw_with_rules,
                                               'update_firewall')

    def _get_router_info_list_for_tenant(self, routers, tenant_id):
        """Returns the list of router info objects on which to apply the fw."""
        router_info_list = []
        for router in routers:
            # for routers without an interface - _get_routers returns
            # the router - but this is not yet populated in router_info
            if router['tenant_id'] != tenant_id:
                continue
            LOG.info(_("_get_router_info_list_for_tenant router %s"), router)
            # This is done to Keep fwaas driver code unchanged
            ri = RouterInfo(router)
            router_info_list.append(ri)
        return router_info_list

    def _is_interface_present_added_to_routers(self, appply_list):
        for ri in appply_list:
            router = ri.router
            if router['svis']:
                return True
        return False

    def _invoke_driver_for_plugin_api(self, context, fw, func_name):
        """Invoke driver method for plugin API and provide status back."""
        LOG.debug(_("%(func_name)s from agent for fw: %(fwid)s"),
                  {'func_name': func_name, 'fwid': fw['id']})
        try:
            routers = self._get_routers(context)
            router_info_list = self._get_router_info_list_for_tenant(
                routers,
                fw['tenant_id'])
            if not router_info_list and func_name != 'delete_firewall':
                LOG.debug(_('No Routers on tenant: %s'), fw['tenant_id'])
                # fw was created before any routers were added, and if a
                # delete is sent then we need to ack so that plugin can
                # cleanup.
                return
            elif not self._is_interface_present_added_to_routers(
                    router_info_list) and func_name != 'delete_firewall':
                LOG.debug(_('No Router interface'))
                return
            LOG.debug(_("Apply fw on Router List: '%s'"),
                      [ri.router['id'] for ri in router_info_list])
            # call into the driver
            try:
                self._fwaas_driver.__getattribute__(func_name)(
                    router_info_list,
                    fw)
                if func_name != "delete_firewall":
                    self.endpoints[0].set_firewall_status(context, fw['id'],
                                                          const.ACTIVE)
            except Exception as e:
                LOG.error(_("Exception %s"), e)
                LOG.error(_("Firewall Driver Error for %(func_name)s "
                            "for fw: %(fwid)s"),
                          {'func_name': func_name, 'fwid': fw['id']})
                raise e

        except Exception as e:
            LOG.exception(
                _("FWaaS RPC failure in %(func_name)s for fw: %(fwid)s"),
                {'func_name': func_name, 'fwid': fw['id']})
            raise e

        return
