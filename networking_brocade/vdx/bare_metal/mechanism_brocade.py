# Copyright 2014 Brocade Communications System, Inc.
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


"""Implentation of Brocade ML2 Mechanism driver for ML2 Plugin."""

from networking_brocade._i18n import _
from networking_brocade._i18n import _LE
from networking_brocade._i18n import _LI
from networking_brocade.vdx.bare_metal import util as baremetal_util
from networking_brocade.vdx.non_ampp.ml2driver.nos import nosdriver as driver
from neutron_lib.api.definitions import portbindings
from neutron.common import constants as n_const
from neutron.plugins.ml2 import driver_api as api
from oslo_config import cfg
from oslo_log import helpers as log_helpers
try:
    from oslo_log import log as logging
except ImportError:
    from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

NOS_DRIVER = 'networking_brocade.vdx.non_ampp.ml2driver'
'.nos.nosdriver.NOSdriver'
ML2_BROCADE = [cfg.StrOpt('address', default='',
                          help=_('The address of the host to SSH to')),
               cfg.StrOpt('username', default='admin',
                          help=_('The SSH username to use')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=_('The SSH password to use')),
               cfg.StrOpt('physical_networks', default='',
                          help=_('Allowed physical networks')),
               cfg.StrOpt('ostype', default='NOS',
                          help=_('OS Type of the switch')),
               cfg.StrOpt('osversion', default='4.0.0',
                          help=_('OS Version number'))
               ]

cfg.CONF.register_opts(ML2_BROCADE, "ml2_brocade")


class BrocadeMechanism(api.MechanismDriver):
    """ML2 Mechanism driver for Brocade VDX switches.
    This is the upper layer driver class that interfaces to
    lower layer (NETCONF) below.
    """

    def __init__(self):
        self._driver = None
        self._physical_networks = None
        self._switch = None
        self.initialize()

    def initialize(self):
        """Initilize of variables needed by this class."""

        self._physical_networks = cfg.CONF.ml2_brocade.physical_networks
        self.brocade_init()
        self._driver.close_session()

    def brocade_init(self):
        """Brocade specific initialization for this class."""

        osversion = None
        self._switch = {
            'address': cfg.CONF.ml2_brocade.address,
            'username': cfg.CONF.ml2_brocade.username,
            'password': cfg.CONF.ml2_brocade.password,
            'ostype': cfg.CONF.ml2_brocade.ostype,
            'osversion': cfg.CONF.ml2_brocade.osversion}

        self._driver = driver.NOSdriver(self._switch['address'],
                                        self._switch['username'],
                                        self._switch['password'])

        # Detect version of NOS on the switch
        osversion = self._switch['osversion']
        if osversion == "autodetect":
            osversion = self._driver.get_nos_version(
                self._switch['address'],
                self._switch['username'],
                self._switch['password'])
        self._driver.close_session()

    def create_network_precommit(self, mech_context):
        """Create Network in the mechanism specific database table."""

    def create_network_postcommit(self, mech_context):
        """Create Network as a portprofile on the switch."""

    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""

    def delete_network_postcommit(self, mech_context):
        """Delete network.

        This translates to removng portprofile
        from the switch.
        """

    def update_network_precommit(self, mech_context):
        """Noop now, it is left here for future."""

    def update_network_postcommit(self, mech_context):
        """Noop now, it is left here for future."""

    def create_port_precommit(self, mech_context):
        """Create logical port on the switch (db update)."""

    def create_port_postcommit(self, mech_context):
        """Associate the assigned MAC address to the portprofile."""

    def delete_port_precommit(self, mech_context):
        """Delete logical port on the switch (db update)."""

    def delete_port_postcommit(self, mech_context):
        """Dissociate VLAN from baremetal connected
           port.
        """
        LOG.debug(("brocade_baremetal delete_port_postcommit(self: called"))
        port = mech_context.current
        if baremetal_util.is_baremetal_deploy(port):
            params = baremetal_util.validate_physical_net_params(mech_context)
            try:
                # TODO(rmadapur): Handle local_link_info portgroups
                for i in params["local_link_information"]:
                    speed, name = i['port_id']
                    self._driver.remove_native_vlan_from_interface(speed, name)
            except Exception:
                LOG.exception(_LE("Brocade NOS driver:failed to remove native"
                                  " vlan from bare metal interface"))
                raise Exception(_("NOS driver:failed to remove native vlan"))

    def update_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""

    def update_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""

    @log_helpers.log_method_call
    def bind_port(self, context):
        port = context.current
        vnic_type = port['binding:vnic_type']

        LOG.debug("Brcd:Attempting to bind port %(port)s with vnic_type "
                  "%(vnic_type)s on network %(network)s",
                  {'port': port['id'], 'vnic_type': vnic_type,
                   'network': context.network.current['id']})

        if baremetal_util.is_baremetal_deploy(port):
            segments = context.segments_to_bind
            LOG.info(_LI("Segments:%s"), segments)
            params = baremetal_util.validate_physical_net_params(context)
            try:
                # TODO(rmadapur): Handle local_link_info portgroups
                for i in params["local_link_information"]:
                    speed, name = i['port_id']
                    vlan_id = segments[0][api.SEGMENTATION_ID]
                    self._driver.configure_native_vlan_on_interface(
                        speed,
                        name, vlan_id)
            except Exception:
                LOG.exception(_LE("Brocade NOS driver:failed to trunk"
                                  " bare metal vlan"))
                raise Exception(_("Brocade switch exception:"
                                  " bind_port failed for baremetal"))
            context.set_binding(segments[0][api.ID],
                                portbindings.VIF_TYPE_OTHER, {},
                                status=n_const.PORT_STATUS_ACTIVE)

    def create_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""

    def create_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""

    def delete_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""

    def delete_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""

    def update_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""

    def update_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
