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


"""Implentation of Brocade ML2 Mechanism driver for ML2 Plugin."""
from networking_brocade.vdx.db import models as brocade_db
from networking_brocade.vdx.non_ampp.ml2driver.nos import nosdriver as driver
from networking_brocade.vdx.non_ampp.ml2driver import utils
from neutron.common import exceptions
from neutron import context as neutron_context
from neutron.extensions import portbindings
from neutron.i18n import _
from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from oslo_config import cfg
from oslo_serialization import jsonutils
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


class BrocadeProfileValidationError(exceptions.NeutronException):
    """Exception class duplicate port entries.

    if Vlan is already added to port
    this exeception will be raised
    """

    message = _('%(msg)s')


class BrocadePortValidationError(exceptions.NeutronException):
    """Exception class invalid port.

    if port is not in three tupple format
    this exeception will be raised
    """

    message = _('%(msg)s')


class PortIdSet(object):
    """Maintains set of interface names"""

    def __init__(self):
        self.vlan_port_ids = {}

    def prepare_vlan_portlist(self, vlan_id):
        n_ctxt = neutron_context.get_admin_context()
        port_ids = []
        uplink_ports = brocade_db.get_uplinkport(n_ctxt, vlan_id=vlan_id)
        for port in uplink_ports:
            profile = jsonutils.loads(port.binding_profile)
            for link in profile.get('local_link_information'):
                port_ids.append(link.get('port_id').replace(" ", ""))
            if port.vlan_id in self.vlan_port_ids:
                self.vlan_port_ids[port.vlan_id] += port_ids
            else:
                self.vlan_port_ids[port.vlan_id] = port_ids
            port_ids = []

    def _is_valid_port(self, port):
        speed, name = utils._get_interface_speed_and_name(port)
        return utils._is_valid_nos_interface(speed, name)

    def add_ports(self, vlan_id, profile):
        port_ids = []
        self.prepare_vlan_portlist(vlan_id)
        if vlan_id not in self.vlan_port_ids:
            for link in profile.get('local_link_information'):
                port = link.get('port_id').replace(" ", "")
                if not self._is_valid_port(port):
                    LOG.error(_LE("Invalid Port %s"), port)
                    err = ("Invalid interface name")
                    raise BrocadePortValidationError(msg=err)
            LOG.debug("adding ports %s to vlan %s", port_ids, vlan_id)
            return

        for link in profile.get('local_link_information'):
            port = link.get('port_id').replace(" ", "")
            if not self._is_valid_port(port):
                LOG.error(_LE("Invalid Port %s"), port)
                raise BrocadePortValidationError("Invalid interface name")
            if port in self.vlan_port_ids[vlan_id]:
                LOG.error(_LE("vlans %s is already applied on "
                              "port %s"), vlan_id, port)
                err = ("Vlan  is already applied on port")
                raise BrocadeProfileValidationError(msg=err)


class BrocadeMechanism(api.MechanismDriver):
    """ML2 Mechanism driver for Brocade VDX switches.

    This is the upper layer driver class that interfaces to
    lower layer (NETCONF) below.
    """

    def __init__(self):
        self._driver = None
        self._physical_networks = None
        self._switch = None
        self.vlan_port_set = PortIdSet()
        self.supported_vnic_types = portbindings.VNIC_DIRECT
        self.initialize()

    def initialize(self):
        """Initilize of variables needed by this class."""

        self._physical_networks = cfg.CONF.ml2_brocade.physical_networks
        self.brocade_init()
        self._driver.close_session()

    def brocade_init(self):
        """Brocade specific initialization for this class."""

        self._switch = {
            'address': cfg.CONF.ml2_brocade.address,
            'username': cfg.CONF.ml2_brocade.username,
            'password': cfg.CONF.ml2_brocade.password,
            'ostype': cfg.CONF.ml2_brocade.ostype,
            'osversion': cfg.CONF.ml2_brocade.osversion}

        self._driver = driver.NOSdriver(self._switch['address'],
                                        self._switch['username'],
                                        self._switch['password'])

        self._driver.close_session()

    def is_valid_message(self, mech_context):
        port = mech_context.current
        if not port[portbindings.PROFILE]:
            LOG.debug("binding profile not present")
            return False
        vnic_type = port[portbindings.VNIC_TYPE]
        if not vnic_type == portbindings.VNIC_DIRECT:
            LOG.debug("binding profile vnic type %s is not direct", vnic_type)
            return False
        return True

    def create_port_precommit(self, mech_context):
        LOG.debug("create_port_precommit(self: called")
        if not self.is_valid_message(mech_context):
            return
        port = mech_context.current
        port_binding_profile = port[portbindings.PROFILE]
        segment = mech_context._network_context._segments[0]
        vlan_id = self._get_vlanid(segment)
        try:
            n_ctxt = neutron_context.get_admin_context()
            self.vlan_port_set.add_ports(str(vlan_id), port_binding_profile)
            port = mech_context.current
            port_id = port['id']
            tenant_id = port['tenant_id']
            brocade_db.create_uplinkport(n_ctxt, port_id, tenant_id,
                                         vlan_id, port_binding_profile)
        except Exception as e:
            LOG.error(_LE("Error Handling portbinding profile %s"), e)
            raise e

    def create_port_postcommit(self, mech_context):
        LOG.debug("create_port_postcommit(self: called")
        if not self.is_valid_message(mech_context):
            return
        port = mech_context.current
        try:
            self._create_port_binding_config(port, mech_context)
        except Exception as e:
            port_id = port['id']
            n_ctxt = neutron_context.get_admin_context()
            brocade_db.delete_uplinkport(n_ctxt, port_id=port_id)
            LOG.error(_LE("Error Handling portbinding profile/nos dev %s"), e)
            raise e

    def delete_port_precommit(self, mech_context):
        LOG.debug("create_port_precommit(self: called")
        if not self.is_valid_message(mech_context):
            return
        port = mech_context.current
        port_id = port['id']
        try:
            n_ctxt = neutron_context.get_admin_context()
            brocade_db.delete_uplinkport(n_ctxt, port_id=port_id)
        except Exception as e:
            LOG.error(_LE("Error deleting portbinding profile %s"), e)
            raise e

    def delete_port_postcommit(self, mech_context):
        """Dissociate MAC address from the portprofile."""
        LOG.debug("create_port_postcommit(self: called")
        if not self.is_valid_message(mech_context):
            return
        port = mech_context.current
        try:
            self._delete_port_binding_config(port, mech_context)
        except Exception as e:
            port_id = port['id']
            tenant_id = port['tenant_id']
            n_ctxt = neutron_context.get_admin_context()
            segment = mech_context._network_context._segments[0]
            port_binding_profile = port[portbindings.PROFILE]
            vlan_id = self._get_vlanid(segment)
            brocade_db.create_uplinkport(n_ctxt, port_id, tenant_id,
                                         vlan_id, port_binding_profile)
            LOG.error(_LE("Error Handling portbinding profile/nos dev %s"), e)

    def _is_profile_bound_to_port(self, port, context):
        profile = context.current.get(portbindings.PROFILE, {})
        if not profile:
            LOG.debug("Missing profile in port binding")
            return False
        return True

    def _get_vlanid(self, segment):
        if (segment and segment[api.NETWORK_TYPE] == p_const.TYPE_VLAN):
            return segment.get(api.SEGMENTATION_ID)

    def _delete_port_binding_config(self, port, mech_context):
        ll, vlan = self._get_local_link_info(
            port[portbindings.PROFILE], mech_context)
        for speed, name in ll:
            if speed and name and vlan:
                self._driver.add_or_remove_vlan_from_interface("remove", speed,
                                                               name, vlan)

    def _create_port_binding_config(self, port, mech_context):
        """update binding profile confix to VCS"""
        ll, vlan = self._get_local_link_info(
            port[portbindings.PROFILE], mech_context)
        for speed, name in ll:
            if speed and name and vlan:
                self._driver.prepare_interface_in_l2_mode(speed, name)
                self._driver.add_or_remove_vlan_from_interface("add", speed,
                                                               name, vlan)

    def _get_local_link_info(self, profile, ctxt):
        """Retirieves port native vlan
           tenant vlan, mtu info from profile
        """
        segment = ctxt._network_context._segments[0]
        vlan_id = self._get_vlanid(segment)
        ll = []

        try:
            local_link = profile
            for link in local_link.get('local_link_information'):
                port = link.get('port_id')
                if not port:
                    # if port is not present do we raise error
                    # or continue skipping
                    LOG.error(_LE("_get_local_link_info:invalid port"))
                    continue
                speed, name = utils._get_interface_speed_and_name(port)
                if not utils._is_valid_nos_interface(speed, name):
                    LOG.error(_LE("_get_local_link_info:invalid "
                                  "port %s"), port)
                    continue
                ll.append((speed, name))
                LOG.info(_LI("_get_local_link_info port %s %s"), speed, name)
        except Exception as e:
            LOG.error(_LE("Error Handling portbinding profile %s"), e)
            raise e

        return ll, vlan_id
