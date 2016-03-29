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
# Shiv Haris (shivharis@hotmail.com)


"""Implentation of Brocade ML2 Mechanism driver for ML2 Plugin."""

from networking_brocade.vdx.bare_metal import util as baremetal_util
from networking_brocade.vdx.db import models as brocade_db
from networking_brocade.vdx.non_ampp.ml2driver.nos import nosdriver as driver
from networking_brocade.vdx.non_ampp.ml2driver import utils
from neutron.common import constants as n_const
from neutron import context as neutron_context
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
import oslo_i18n
import sys
_translators = oslo_i18n.TranslatorFactory(domain="brcd")
_LI = _translators.log_info
_LW = _translators.log_warning
_LE = _translators.log_error
_LC = _translators.log_critical

try:
    from oslo_log import log as logging
except ImportError:
    from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)
MECHANISM_VERSION = 1.0


class BrocadeMechanism(api.MechanismDriver):

    """ML2 Mechanism driver for Brocade VDX switches. This is the upper
    Layer driver class that interfaces to lower layer (NETCONF) below.
    """

    def __init__(self):
        self._driver = None
        self._physical_networks = None
        self._switch = None
        self._device_dict = {}
        self._bond_mappings = {}
        self._lacp_ports = {}
        self.initialize()

    def initialize(self):
        """Initilize of variables needed by this class."""
        self.brocade_init()

    def brocade_init(self):
        """Brocade specific initialization for this class."""
        utils.register_brocade_credentials()
        self._switch = utils.get_brocade_credentials()
        self._fqdn_supported = utils.is_fqdn_supported()
        self.initialize_vcs = utils.get_vcs_initialize()
        self._physical_networks = utils.get_physical_networks()
        self._driver = driver.NOSdriver(self._switch['address'],
                                        self._switch['username'],
                                        self._switch['password'])
        try:
            self._device_dict, self._bond_mappings, self._mtu,\
                self._native_vlans = utils._parse_connection_info()
        except Exception as e:
            LOG.error(_("%s"), e)
            sys.exit(0)

        if self.initialize_vcs:
            self.configure_vcs()
        self._driver.close_session()

    def configure_vcs(self):
        # configure vcs interfaces based on topology
        if not utils._is_valid_interface(self._device_dict,
                                         self._switch, self._driver):
            sys.exit(0)

        LOG.debug(_("device dictionary %s"), self._device_dict)

        try:
            if utils._is_lacp_enabled():
                LOG.debug(_("LACP enabled"))
                (self._device_dict, self._lacp_ports) =\
                    utils._aggregate_nics_to_support_lacp(self._device_dict,
                                                          self._bond_mappings)
            self._driver.configure_l2_and_trunk_mode_for_interface(
                self._device_dict, self._lacp_ports,
                self._mtu, self._native_vlans)
        except Exception:
            LOG.exception(
                _("Brocade Mechanism: failed to put interface l2 or tr mode"))
            raise Exception(
                _("Brocade Mechanism: failed to put interface l2 or tr mode"))

    def create_network_precommit(self, mech_context):
        """Create Network in the mechanism specific database table."""

        network = mech_context.current
        context = mech_context._plugin_context
        tenant_id = network['tenant_id']
        network_id = network['id']

        segments = mech_context.network_segments
        # currently supports only one segment per network
        segment = segments[0]

        network_type = segment['network_type']
        vlan_id = segment['segmentation_id']
        segment_id = segment['id']

        if network_type != 'vlan':
            raise Exception(
                _("Brocade Mechanism: failed to create network, "
                  "only network type vlan is supported"))

        try:
            brocade_db.create_network(context, network_id, vlan_id,
                                      segment_id, network_type, tenant_id)
        except Exception:
            LOG.exception(
                _("Brocade Mechanism: failed to create network in db"))
            raise Exception(
                _("Brocade Mechanism: create_network_precommit failed"))

    def create_network_postcommit(self, mech_context):
        """Create Network as a portprofile on the switch."""

        LOG.debug(_("create_network_postcommit: called"))

        network = mech_context.current
        # use network_id to get the network attributes
        # ONLY depend on our db for getting back network attributes
        # this is so we can replay postcommit from db
        context = mech_context._plugin_context

        network_id = network['id']
        network = brocade_db.get_network(context, network_id)
        network['network_type']
        network['tenant_id']
        vlan_id = network['vlan']
        segments = mech_context.network_segments
        # currently supports only one segment per network
        segment = segments[0]
        physical_network = segment['physical_network']

        try:
            self._driver.create_network(self._device_dict,
                                        physical_network,
                                        vlan_id)
        except Exception:
            LOG.exception(_("Brocade NOS driver: failed in create network"))
            brocade_db.delete_network(context, network_id)
            raise Exception(
                _("Brocade Mechanism: create_network_postcommmit failed"))

    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""

        LOG.debug(_("delete_network_precommit: called"))
        network = mech_context.current
        network_id = network['id']
        network['tenant_id']

        context = mech_context._plugin_context

        try:
            brocade_db.delete_network(context, network_id)
        except Exception:
            LOG.exception(
                _("Brocade Mechanism: failed to delete network in db"))
            raise Exception(
                _("Brocade Mechanism: delete_network_precommit failed"))

    def delete_network_postcommit(self, mech_context):
        """Delete network which translates to removng portprofile
        from the switch.
        """
        LOG.debug(_("delete_network_postcommit: called"))
        network = mech_context.current
        network['id']
        vlan_id = network['provider:segmentation_id']
        network['tenant_id']
        try:
            self._driver.delete_network(vlan_id)
        except Exception:
            LOG.exception(_("Brocade NOS driver: failed to delete network"))
            raise Exception(
                _("Brocade switch exception, "
                  "delete_network_postcommit failed"))

    def update_network_precommit(self, mech_context):
        """Noop now, it is left here for future."""

    def update_network_postcommit(self, mech_context):
        """Noop now, it is left here for future."""

    def create_port_precommit(self, mech_context):
        """Create logical port on the switch (db update)."""
        LOG.debug(_("create_port_precommit: called"))
        port = mech_context.current
        if not self._is_compute_or_dhcp_port(port, mech_context):
            return
        if baremetal_util.is_baremetal_deploy(port):
            LOG.debug(_("create_port_precommit: baremetal deploy"))
            return

        context = neutron_context.get_admin_context()
        self._create_brocade_port(
            context, port, mech_context.top_bound_segment)

    def create_port_postcommit(self, mech_context):
        """Associate the assigned MAC address to the portprofile."""
        LOG.debug(_("create_port_postcommit(self: called"))
        port = mech_context.current
        if not self._is_compute_or_dhcp_port(port, mech_context):
            return

        context = mech_context._plugin_context
        self._create_nos_port(context, port, mech_context.top_bound_segment)

    def delete_port_precommit(self, mech_context):
        """Delete logical port on the switch (db update)."""

        LOG.debug(_("delete_port_precommit: called"))
        port = mech_context.current
        if not self._is_compute_or_dhcp_port(port, mech_context):
            return

        context = mech_context._plugin_context
        self._delete_brocade_port(context, port)

    def delete_port_postcommit(self, mech_context):
        """Dissociate MAC address from the portprofile."""
        LOG.debug(_("delete_port_postcommit(self: called"))
        port = mech_context.current
        if not self._is_compute_or_dhcp_port(port, mech_context):
            return

        context = mech_context._plugin_context
        self._delete_nos_port(context, port, mech_context.top_bound_segment)

    def update_port_precommit(self, mech_context):
        """updates brocade db if vm is migrating"""
        context = mech_context._plugin_context
        port = mech_context.current
        LOG.debug(_("update_port_precommit(self: called"))
        if not self._is_compute_or_dhcp_port(port, mech_context):
            return

        if self._is_vm_migration(mech_context):
            # PortContext.current['binding:host_id']: current (new) value
            port = mech_context.original
            LOG.debug(_("update_port_precommit: VM is migrating to"
                        "new host %s(case 1) port['status'] %s"),
                      port[portbindings.HOST_ID], port['status'])
            self._delete_brocade_port(context, port)
        else:
            # PortContext.current['binding:host_id']: previous value
            if mech_context.top_bound_segment and\
                    port['status'] == n_const.PORT_STATUS_BUILD:
                LOG.debug(_("update_port_pretcommit: VM is migrating to"
                            "new host %s(case 2)"), port[portbindings.HOST_ID])
                self._create_brocade_port(context, port,
                                          mech_context.top_bound_segment)

    def update_port_postcommit(self, mech_context):
        """updates brocade nos if vm is migrating"""
        port = mech_context.current
        context = mech_context._plugin_context
        LOG.debug(_("update_port_postcommit: called"))
        if not self._is_compute_or_dhcp_port(port, mech_context):
            return

        if self._is_vm_migration(mech_context):
            # add new entry to switch
            # PortContext.current['binding:host_id']: current (new) value
            port = mech_context.original
            LOG.debug(_("update_port_precommit: VM is migrating to"
                        "new host %s(case 1) port['status'] %s"),
                      port[portbindings.HOST_ID], port['status'])
            self._delete_nos_port(context, port,
                                  mech_context.original_bound_segment)
        else:
            # remove previouse port binings
            # PortContext.current['binding:host_id']: previous value
            if mech_context.top_bound_segment and\
                    port['status'] == n_const.PORT_STATUS_BUILD:
                LOG.debug(_("update_port_postcommit: VM is migrating to"
                            "new host %s(case 2)"), port[portbindings.HOST_ID])
                self._create_nos_port(context, port,
                                      mech_context.top_bound_segment)

    def create_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("create_subnetwork_precommit: called"))

    def create_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("create_subnetwork_postcommit: called"))

    def delete_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("delete_subnetwork_precommit: called"))

    def delete_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("delete_subnetwork_postcommit: called"))

    def update_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_subnet_precommit(self: called"))

    def update_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_subnet_postcommit: called"))

    def _is_vm_migration(self, context):
        LOG.debug(_("_is_vm_migration called"))
        return (context.current.get(portbindings.HOST_ID) !=
                context.original.get(portbindings.HOST_ID))

    def _is_compute_or_dhcp_port(self, port, context):
        if (("compute" not in port['device_owner']) and
                ("dhcp" not in port['device_owner'])):
            # Not a compute port or dhcp , return
            return False
        if not self._is_profile_bound_to_port(port, context):
            # it is baremetal port
            return False
        return True

    def _is_profile_bound_to_port(self, port, context):
        profile = context.current.get(portbindings.PROFILE, {})
        if not profile:
            LOG.debug("Missing profile in port binding")
            return False
        return True

    def _is_dhcp_port(self, port):
        if("dhcp" in port['device_owner']):
            # dhcp port, return
            return True
        return False

    def _get_vlanid(self, segment):
        if (segment and segment[api.NETWORK_TYPE] == p_const.TYPE_VLAN):
            return segment.get(api.SEGMENTATION_ID)

    def _get_physical_interface(self, segment):
        if (segment and segment[api.NETWORK_TYPE] == p_const.TYPE_VLAN):
            return segment.get(api.PHYSICAL_NETWORK)

    def _get_hostname(self, port):
        host = port[portbindings.HOST_ID]
        LOG.debug(_("_get_hostname host %s"), host)
        return host if self._fqdn_supported else host.split('.')[0]

    def _get_port_info(self, port, segment):
        "get vlan id and physical networkkfrom bound segment"
        if port and segment:
            vlan_id = self._get_vlanid(segment)
            hostname = self._get_hostname(port)
            physical_interface = self._get_physical_interface(segment)
            LOG.debug(_("_get_port_info: hostname %s, vlan_id %s,"
                        " physical_interface %s"), hostname, str(vlan_id),
                      physical_interface)
            return hostname, vlan_id, physical_interface
        return None, None, None

    def _create_brocade_port(self, context, port, segment):
        port_id = port['id']
        network_id = port['network_id']
        tenant_id = port['tenant_id']
        admin_state_up = port['admin_state_up']
        hostname, vlan_id, physical_network = self._get_port_info(
            port, segment)
        try:
            brocade_db.create_port(context, port_id, network_id,
                                   physical_network, vlan_id, tenant_id,
                                   admin_state_up, hostname)
        except Exception:
            LOG.exception(_("Brocade Mechanism: failed to create port in db"))
            raise Exception(
                _("Brocade Mechanism: create_port_precommit failed"))

    def _create_nos_port(self, context, port, segment):
        hostname, vlan_id, physical_network = self._get_port_info(
            port, segment)
        if not hostname:
            return
        for (speed, name) in self._device_dict[(hostname, physical_network)]:
            LOG.debug(_("_create_nos_port:port %s %s vlan %s"),
                      speed, name, str(vlan_id))
            try:
                if not brocade_db.is_vm_exists_on_host(context,
                                                       hostname,
                                                       physical_network,
                                                       vlan_id):
                    self._driver.add_or_remove_vlan_from_interface(
                        "add", speed, name, vlan_id)
                else:
                    LOG.debug(_("_create_nos_port:port is already trunked"))
            except Exception:
                self._delete_brocade_port(context, port)
                LOG.exception(_("Brocade NOS driver:failed to trunk vlan"))
                raise Exception(_("Brocade switch exception:"
                                  " create_port_postcommit failed"))

    def _delete_brocade_port(self, context, port):
        try:
            port_id = port['id']
            brocade_db.delete_port(context, port_id)
        except Exception:
            LOG.exception(_("Brocade Mechanism: failed to delete port in db"))
            raise Exception(
                _("Brocade Mechanism: delete_port_precommit failed"))

    def _delete_nos_port(self, context, port, segment):

        hostname, vlan_id, physical_network =\
            self._get_port_info(port, segment)
        if not hostname:
            return
        for (speed, name) in self._device_dict[(hostname, physical_network)]:
            try:
                if brocade_db.is_last_vm_on_host(context,
                                                 hostname,
                                                 physical_network, vlan_id)\
                        and not self._is_dhcp_port(port):

                    self._driver.add_or_remove_vlan_from_interface("remove",
                                                                   speed,
                                                                   name,
                                                                   vlan_id)
                else:
                    LOG.info(_("more vm exist for network on host hence vlan"
                               " is not removed from port"))
            except Exception:
                LOG.exception(
                    _("Brocade NOS driver: failed to remove vlan from port"))
                raise Exception(
                    _("Brocade switch exception: delete_port_postcommit"
                      "failed"))
