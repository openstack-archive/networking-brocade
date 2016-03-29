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
# Authors:
# Varma Bhupatiraju (vbhupati@brocade.com)
# Shiv Haris (shivharis@hotmail.com)


"""Brocade NOS Driver implements NETCONF over SSHv2 for
Neutron network life-cycle management.
"""

import sys
from ncclient import manager
from ncclient.operations.errors import TimeoutExpiredError
from ncclient.transport.errors import TransportError
from oslo_utils import excutils
from neutron.common import exceptions
from oslo_log import log as logging
from networking_brocade.vdx.non_ampp.ml2driver.nos import nctemplates as template
from networking_brocade.vdx.non_ampp.ml2driver import utils
from xml.etree import ElementTree
import time
from functools import wraps

LOG = logging.getLogger(__name__)
SSH_PORT = 22
RETRYABLE_ERRORS = ["NODE_IS_NOT_READY",
                    "CLUSTER_FORMATION_IS_IN_PROGRESS",
                    "NODE_IS_ZEROIZED",
                    "WAVE_FRAMEWORK_STATE_CLUSTER_FORMATION"
                    ]

_RETRIES, _NDELAY, _NBACKOFF = utils.get_retry_args()


def nos_unknown_host_cb(host, fingerprint):
    """An unknown host callback.

    Returns `True` if it finds the key acceptable,
    and `False` if not. This default callback for NOS always returns 'True'
    (i.e. trusts all hosts for now).
    """
    return True

# 5 retries is equal to 8 mins


def retry(ExceptionToCheck, tries=_RETRIES, delay=_NDELAY, backoff=_NBACKOFF):
    """Retry decorator
    """
    def deco_retry(f):
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 0:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck as e:
                    LOG.warning(_("Retrying in %d seconds..."), mdelay)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
                    lastException = e
            raise lastException
        return f_retry  # true decorator
    return deco_retry


class RetryableException(exceptions.NeutronException):
    message = _("Transient errors Try again after some time."
                " Reason: %(exc)s.")


class NOSdriver(object):

    """NOS NETCONF interface driver for Neutron network.
    Handles life-cycle management of Neutron network
    """

    def __init__(self, host, username, password):
        self.mgr = None
        self.host = host
        self.username = username
        self.password = password
        self.osversion = self.get_nos_version().split('.', 2)

    def _set_default_timeout_ncclient(self):
        mgr = self.connect(self.host, self.username, self.password)
        mgr.timeout = 30

    @retry(RetryableException)
    def _edit_config(self, target, config, timeout=30):
        """Modify switch config for a target config type."""
        try:
            mgr = self.connect(self.host, self.username, self.password)
            if timeout != 30:
                mgr.timeout = timeout
            mgr.edit_config(target=target, config=config)
        except TransportError as e:
            self.close_session()
            LOG.warning(_("_edit_config()TransportErrorFailed"
                          "for Reason %(exc)s"), {'exc': e})
            raise RetryableException(exc=e)
        except TimeoutExpiredError as e:
            LOG.warning(_("_edit_config(TimeoutExpiredError)"
                          "for Reason %(exc)s"), {'exc': e})
            raise RetryableException(exc=e)
        except Exception as e:
            LOG.warning(_("_edit_config(CLUSTER ERRORS)"
                          "for Reason %(exc)s"), {'exc': e})
            for exc_str in RETRYABLE_ERRORS:
                if exc_str in str(e):
                    raise RetryableException(exc=e)
            raise e
        finally:
            if timeout != 30:
                self._set_default_timeout_ncclient()

    @retry(RetryableException)
    def _get_config(self, source, filterstr):
        """get switch config for a source config type."""
        try:
            mgr = self.connect(self.host, self.username, self.password)
            response = mgr.get_config(source=source,
                                      filter=('xpath', filterstr)).data_xml
            return response
        except TransportError as e:
            LOG.warning(_("_edit_config()TransportErrorFailed"
                          "for Reason %s"), unicode(str(e)))
            self.close_session()
            raise RetryableException(exc=e)
        except TimeoutExpiredError as e:
            LOG.warning(_("_edit_config(TimeoutExpiredError)"
                          "for Reason %s"), unicode(str(e)))
            raise RetryableException(exc=e)
        except Exception as e:
            LOG.warning(_("_edit_config(CLUSTER ERRORS)"
                          "for Reason %s"), unicode(str(e)))
            for exc_str in RETRYABLE_ERRORS:
                if exc_str in str(e):
                    raise RetryableException(exc=e)
            raise e

    def connect(self, host, username, password):
        """Connect via SSH and initialize the NETCONF session."""
        # Use the persisted NETCONF connection
        if self.mgr and self.mgr.connected:
            return self.mgr

        # check if someone forgot to edit the conf file with real values
        if host == '':
            raise Exception(_("Brocade Switch IP address is not set, "
                              "check config ml2_conf_brocade.ini file"))

        # Open new NETCONF connection
        try:
            self.mgr = manager.connect(host=host, port=SSH_PORT,
                                       username=username, password=password,
                                       unknown_host_cb=nos_unknown_host_cb)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Connect failed to switch"))

        LOG.debug(_("Connect success to host %(host)s:%(ssh_port)d"),
                  dict(host=host, ssh_port=SSH_PORT))
        return self.mgr

    def close_session(self):
        """Close NETCONF session."""
        if self.mgr and self.mgr.connected:
            self.mgr.close_session()
            self.mgr = None

    def get_nos_version(self):
        """Show version of NOS."""
        try:
            mgr = self.connect(self.host, self.username, self.password)
            return self.nos_version_request(mgr)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
                self.close_session()

    def create_network(self, topology,
                       physical_network, net_id):
        """Creates a new virtual network."""
        try:
            self.create_vlan_interface(net_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def delete_network(self, net_id):
        """Deletes a virtual network."""
        try:
            self.delete_vlan_interface(net_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def configure_l2_and_trunk_mode_for_interface(self, devices, lacp=[],
                                                  mtu={}, native_vlans={}):
        """configure interface in switchport and trunk mode."""
        for key in lacp.keys():
            lacp_args = utils.get_lacp_args()
            create_interface = template.CREATE_INTERFACE.format(name=key)
            configure_lb_mode = template.PORT_CHANNEL_LB_MODE.format(
                name=key,
                                    po_lb_mode=lacp_args['po_lb_mode'])
            configure_po_speed = template.PORT_CHANNEL_SPEED.format(
                name=key,
                                    po_speed=lacp_args['po_speed'])
            if not self.is_interface_id_exists('port-channel', key):
                self._edit_config('running', create_interface)
            self._edit_config('running', configure_lb_mode)
            self._edit_config('running', configure_po_speed)

            for (speed,  interface_name) in lacp[key]:
                self.remove_l2_mode_for_interface(speed, interface_name,
                                                  lacp_args['remove_ch_grp'])

            for (speed,  interface_name) in lacp[key]:
                confstr_channel_group = template.\
                    CONFIGURE_CHANNEL_GROUP.format(
                        speed=speed, name=interface_name,
                                            port=key, po_mode=lacp_args[
                                                'po_mode'],
                                            po_type=lacp_args['po_type'])
                self._edit_config('running', confstr_channel_group)
                self.activate_interface(speed, interface_name)

        for key in devices.keys():
            for (interface_speed, interface_name) in devices[key]:

                confstr_trunk = template.CONFIGURE_INTERFACE_SWITCHPORT_TRUNK.\
                    format(speed=interface_speed,
                           name=interface_name)
                try:
                    if not self.is_interface_id_exists(interface_speed,
                                                       interface_name):
                        LOG.error(_("topology incorrect incorrect VDX interface"
                                    "%s %s"), interface_speed, interface_name)
                        sys.exit(0)
                    self.configure_l2_mode_for_interface(interface_speed,
                                                         interface_name)
                    self.configure_interface_in_trunk_mode(confstr_trunk)
                    self.activate_interface(interface_speed, interface_name)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("VDX interfaces may not be in proper "
                                        "mode configure switchport mode"))

        for (speed, name), mtu in mtu.iteritems():
            self.configure_mtu_on_interface(speed, name, mtu)

        for (speed, name), vlan_id in native_vlans.iteritems():
            self.create_vlan_interface(vlan_id)
            self.configure_native_vlan_on_interface(speed, name, vlan_id)

    def configure_interface_in_trunk_mode(self, confstr_trunk):
        self._edit_config('running', confstr_trunk)

    def activate_interface(self, interface_speed, interface_name):
        """Activate physical interface """
        if not self.is_interface_shutdown(interface_speed, interface_name):
            return
        confstr_activate = template.ACTIVATE_INTERFACE.format(
            speed=interface_speed, name=interface_name)
        try:
            self._edit_config('running', confstr_activate)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("interface already in active state"))
                ctxt.reraise = False

    def remove_l2_mode_for_interface(self, interface_speed,
                                     interface_name, remove_ch_grp=False):
        """Configures given interface in L2 mode"""
        version = self.osversion
        if int(version[0]) >= 5 or (int(version[0]) >= 4
                                    and int(version[1]) >= 1):
            confstr = template.REMOVE_INTERFACE_SWITCHPORT_V1.format(
                speed=interface_speed, name=interface_name)
        else:
            confstr = template.REMOVE_INTERFACE_SWITCHPORT_V2.format(
                speed=interface_speed, name=interface_name)
        confstr_rm_cg = template.REMOVE_CHANNEL_GROUP.format(
            speed=interface_speed, name=interface_name)
        try:
            try:
                self._edit_config('running', confstr)
            except Exception as ex:
                with excutils.save_and_reraise_exception() as ctxt:
                    ctxt.reraise = False
            if remove_ch_grp:
                self._edit_config('running', confstr_rm_cg)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                ctxt.reraise = False

    def configure_l2_mode_for_interface(self, interface_speed,
                                        interface_name):
        """Configures given interface in L2 mode"""
        if self.is_interface_in_port_profile_mode(interface_speed,
                                                  interface_name):
            try:
                self.set_interface_to_accept_l2_mode(interface_speed,
                                                     interface_name)
            except Exception as ex:
                with excutils.save_and_reraise_exception() as ctxt:
                    LOG.warning(_("interface already in active state"))
                    ctxt.reraise = False

        try:
            if (interface_speed != 'port-channel'):
                confstr = template.REMOVE_CHANNEL_GROUP.format(
                    speed=interface_speed, name=interface_name)
                self._edit_config('running', confstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("exception cg removing"))
                ctxt.reraise = False

        try:
            version = self.osversion
            if int(version[0]) >= 5 or (int(version[0]) >= 4
                                        and int(version[1]) >= 1):
                confstr = template.CONFIGURE_INTERFACE_SWITCHPORT_V1.format(
                    speed=interface_speed, name=interface_name)
            else:
                confstr = template.CONFIGURE_INTERFACE_SWITCHPORT_V2.format(
                    speed=interface_speed, name=interface_name)
            self._edit_config('running', confstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("interface not accepting switching please check"
                              "innterface status"))

    def add_or_remove_vlan_from_interface(self, action, interface_speed,
                                          interface_name, vlan_id):
        """add or remove vlan on interface"""

        confstr = template.ADD_OR_REMOVE_VLAN_TO_INTERFACE.format(
            speed=interface_speed, name=interface_name,
                      action=action, vlan_id=vlan_id)
        try:
            self._edit_config('running', confstr)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def create_svi(self, rbridge_id, vlan_id,
                   ip_address, router_id):
        """create svi on configured rbridge-id"""
        try:
            self.configure_svi(rbridge_id, vlan_id)
            self.bind_vrf_to_svi(rbridge_id, vlan_id, router_id)
            self.configure_svi_with_ip_address(rbridge_id, vlan_id, ip_address)
            self.activate_svi(rbridge_id, vlan_id)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.exception(_("NETCONF error: %s"), ex)
                self.delete_svi(rbridge_id, vlan_id, ip_address, router_id)

    def delete_svi(self, rbridge_id, vlan_id,
                   gw_ip, router_id):
        """delete svi from configured rbridge-id"""
        try:
            if self.is_svi_exists(rbridge_id, vlan_id):
                self.remove_svi(rbridge_id, vlan_id)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error: %s"), ex)

    def create_router(self, rbridge_id, router_id):
        """create vrf NOS"""
        if not utils.is_vrf_required():
            LOG.warning(_("not requested to created vrf there will"
                          "no L5 traffic isolation and no overlapping IP"
                          "supported"))
            return
        vrf_name = template.OS_VRF_NAME.format(id=router_id)
        vrf_name = vrf_name[:32]
        # This is done because on 4.0.0 rd doesnt accept
        # alpha character nor hyphen
        rd = "".join(i for i in router_id if i in "0123456789")
        rd = rd[:4] + ":" + rd[:4]
        try:
            self.create_vrf(rbridge_id, vrf_name)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        try:
            self.configure_rd_for_vrf(rbridge_id, vrf_name, rd)
            self.configure_address_family_for_vrf(rbridge_id, vrf_name)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.exception(_("NETCONF error"))

    def delete_router(self, rbridge_id, router_id):
        """create vrf NOS"""
        if not utils.is_vrf_required():
            return
        vrf_name = template.OS_VRF_NAME.format(id=router_id)
        vrf_name = vrf_name[:32]
        try:
            self.delete_vrf(rbridge_id, vrf_name)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def update_router(self, rbridge_id, router_id, added, removed):
        """update router"""
        LOG.info(_("Inside update_router before sending to switch"))
        if added is None:
            LOG.info(_("Added is None"))

        if removed is None:
            LOG.info(_("Removed is None"))

        if not utils.is_vrf_required():
            """ Configure the static route at the rbridge mode"""
            try:
                if added is not None:
                    LOG.info(_("Adding new route"))
                    for route in added:
                        self.configure_static_route(rbridge_id,
                                                    route['destination'],
                                                    route['nexthop'])
                if removed is not None:
                    LOG.info(_("Deleting new route"))
                    for route in removed:
                        self.delete_static_route(rbridge_id,
                                                 route['destination'],
                                                 route['nexthop'])
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Failed to create static route %s"), str(e))
        else:
            """ config the static route in for the VRF"""
            vrf_name = template.OS_VRF_NAME.format(id=router_id)
            vrf_name = vrf_name[:32]
            try:
                if added is not None:
                    LOG.info(_("Adding new route with VRF %s"), vrf_name)
                    for route in added:
                        self.configure_vrf_static_route(rbridge_id,
                                                        vrf_name,
                                                        route['destination'],
                                                        route['nexthop'])
                if removed is not None:
                    LOG.info(_("Deleting new route from vrf %s"), vrf_name)
                    for route in removed:
                        self.delete_vrf_static_route(rbridge_id,
                                                     vrf_name,
                                                     route['destination'],
                                                     route['nexthop'])
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Failed to create static route %s"), str(e))

    def bind_vrf_to_svi(self, rbridge_id,
                        vlan_id, router_id):
        """binds vrf on svi"""
        if not utils.is_vrf_required():
            return
        vrf_name = template.OS_VRF_NAME.format(id=router_id)
        vrf_name = vrf_name[:32]
        try:
            self.add_vrf_to_svi(rbridge_id, vlan_id, vrf_name)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def unbind_vrf_to_svi(self, rbridge_id,
                          vlan_id, router_id):
        """binds vrf on svi"""
        if not utils.is_vrf_required():
            return
        vrf_name = template.OS_VRF_NAME.format(id=router_id)
        vrf_name = vrf_name[:32]
        try:
            self.delete_vrf_from_svi(rbridge_id, vlan_id, vrf_name)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

# L3 HA Lifecycle
    def configure_protocol_vrrp(self, rbridge_id):
        """enable protocol vrrp """
        try:
            self.enable_protocol_vrrp(rbridge_id)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def configure_vrrp_group(self, rbridge_id,
                             vlan_id, vrid, version):
        """config vrrp virtual ip on svi"""
        try:
            self.create_vrrp_group(rbridge_id, vlan_id, vrid, version)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def configure_vrrp_on_svi(self, rbridge_id, vlan_id, vrid,
                              version, vip, advt_int,
                              priority=100):
        """config vrrp virtual ip on svi"""
        try:
            self.create_vrrp_group(rbridge_id, vlan_id, vrid, version)
            self.configure_vrrp_priority(rbridge_id, vlan_id, vrid,
                                         version, priority)
            self.create_vrrp_virtual_ip(
                rbridge_id, vlan_id, vrid, version, vip)
            self.configure_vrrp_advt_intervel(rbridge_id, vlan_id, vrid,
                                              version, advt_int)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

# Acl Life Cycle Management
    def create_policy(self, policy_name):
        """Remove Acl Policy From VDX"""
        try:
            self.create_acl(policy_name)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def create_acl_rule(self, acl):
        """Remove Acl Policy From VDX"""
        try:
            self.create_rule(acl)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def delete_policy(self, rbridge_id, policy_name):
        """Remove Acl Policy From VDX"""
        try:
            self.delete_acl(rbridge_id, policy_name)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def configure_policy_on_interface(self,
                                      rbridge_id, vlan_id, name, direction):
        """provision  Acl Policy on VE"""
        try:
            self.configure_acl_on_svi(rbridge_id, vlan_id, name, direction)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def remove_policy_on_interface(self,
                                   rbridge_id, vlan_id, name, direction):
        """provision  Acl Policy on VE"""
        try:
            self.remove_acl_on_svi(rbridge_id, vlan_id, name, direction)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

    def create_vlan_interface(self, vlan_id):
        """Configures a VLAN interface."""

        confstr = template.CREATE_VLAN_INTERFACE.format(vlan_id=vlan_id)
        self._edit_config('running', confstr)

    def delete_vlan_interface(self, vlan_id):
        """Deletes a VLAN interface."""

        confstr = template.DELETE_VLAN_INTERFACE.format(vlan_id=vlan_id)
        self._edit_config('running', confstr)

    def create_vrf(self, rbridge_id, vrf_name):
        """create vrf on rbridge."""

        confstr = template.CREATE_VRF.format(rbridge_id=rbridge_id,
                                             vrf_name=vrf_name)
        self._edit_config('running', confstr)

    def delete_vrf(self, rbridge_id, vrf_name):
        """delete vrf  on rbridge."""

        confstr = template.DELETE_VRF.format(rbridge_id=rbridge_id,
                                             vrf_name=vrf_name)
        self._edit_config('running', confstr)

    def configure_rd_for_vrf(self, rbridge_id, vrf_name, rd):
        """configure rd on vrf  on rbridge."""

        confstr = template.CONFIGURE_RD_FOR_VRF.format(rbridge_id=rbridge_id,
                                                       vrf_name=vrf_name, rd=rd)
        self._edit_config('running', confstr)

    def configure_address_family_for_vrf_v1(self, rbridge_id, vrf_name):
        """configure ipv4 address family to vrf  on rbridge."""
        confstr = template.ADD_ADDRESS_FAMILY_FOR_VRF_V1.format(
            rbridge_id=rbridge_id, vrf_name=vrf_name)
        self._edit_config('running', confstr)

    def configure_address_family_for_vrf(self, rbridge_id, vrf_name):
        """configure ipv4 address family to vrf  on rbridge."""
        confstr = template.ADD_ADDRESS_FAMILY_FOR_VRF.format(
            rbridge_id=rbridge_id, vrf_name=vrf_name)
        self._edit_config('running', confstr)

    def configure_svi(self, rbridge_id, vlan_id):
        """configure SVI with ip address on rbridge."""
        confstr = template.CONFIGURE_SVI.format(
            rbridge_id=rbridge_id, vlan_id=vlan_id)

    def configure_svi_with_ip_address(self, rbridge_id, vlan_id, ip_address):
        """configure SVI with ip address on rbridge."""
        confstr = template.CONFIGURE_SVI_WITH_IP_ADDRESS.format(
            rbridge_id=rbridge_id, vlan_id=vlan_id,
                  ip_address=ip_address)
        self._edit_config('running', confstr)

    def activate_svi(self, rbridge_id, vlan_id):
        """configure SVI with ip address on rbridge."""
        if not self.is_svi_shutdown(rbridge_id, vlan_id):
            return
        confstr = template.ACTIVATE_SVI.format(rbridge_id=rbridge_id,
                                               vlan_id=vlan_id)
        self._edit_config('running', confstr)

    def add_vrf_to_svi(self, rbridge_id, vlan_id, vrf_name):
        """add vrf to svi on rbridge."""

        confstr = template.ADD_VRF_TO_SVI.format(rbridge_id=rbridge_id,
                                                 vlan_id=vlan_id,
                                                 vrf_name=vrf_name)
        self._edit_config('running', confstr)

    def delete_vrf_from_svi(self, rbridge_id, vlan_id, vrf_name):
        """delete vrf from svi on rbridge."""

        confstr = template.DELETE_VRF_FROM_SVI.format(rbridge_id=rbridge_id,
                                                      vlan_id=vlan_id,
                                                      vrf_name=vrf_name)
        self._edit_config('running', confstr)

    def remove_svi(self, rbridge_id, vlan_id):
        """delete vrf from svi on rbridge."""
        confstr = template.DELETE_SVI.format(rbridge_id=rbridge_id,
                                             vlan_id=vlan_id)
        self._edit_config('running', confstr)

    def enable_protocol_vrrp(self, rbridge_id):
        """enable protocol vrrp on given rbridge."""
        confstr = template.ENABLE_VRRP.format(rbridge_id=rbridge_id)
        self._edit_config('running', confstr)

    def create_vrrp_group(self, rbridge_id, vlan_id, vrid, version):
        """configure vrrp virtual ip on svi"""
        confstr = template.CONFIGURE_VRRP_GROUP.format(rbridge_id=rbridge_id,
                                                       vlan_id=vlan_id, vrid=vrid, version=version)
        confstr = self.strip_vrrp_version(confstr, version)
        self._edit_config('running', confstr)

    def create_vrrp_virtual_ip(self, rbridge_id, vlan_id, vrid, version, vip):
        """configure vrrp virtual ip on svi"""
        confstr = template.CONFIGURE_VRRP_VIP.format(rbridge_id=rbridge_id,
                                                     vlan_id=vlan_id, vrid=vrid, version=version, vip=vip)
        confstr = self.strip_vrrp_version(confstr, version)
        self._edit_config('running', confstr)

    def configure_vrrp_priority(self, rbridge_id, vlan_id,
                                vrid, version, priority=100):
        """configure vrrp virtual ip on svi"""
        confstr = template.CONFIGURE_VRRP_PRIORITY.format(
            rbridge_id=rbridge_id, vlan_id=vlan_id, vrid=vrid,
            version=version, priority=priority)
        confstr = self.strip_vrrp_version(confstr, version)
        self._edit_config('running', confstr)

    def configure_vrrp_advt_intervel(self, rbridge_id, vlan_id, vrid, version,
                                     advt_intervel):
        """configure vrrp virtual ip on svi"""
        confstr = template.CONFIGURE_VRRP_ADVERTISEMENT_INTERVEL.format(
            rbridge_id=rbridge_id, vlan_id=vlan_id, vrid=vrid,
            version=version, advt_int=advt_intervel)
        confstr = self.strip_vrrp_version(confstr, version)
        self._edit_config('running', confstr)

    def delete_vrf_static_route(self, rbridge_id, vrf_name, dest_ip, next_hop):
        configure_static_route = template.\
            DELETE_VRF_IP_STATIC_ROUTE.\
                                 format(rbridge_id=rbridge_id,
                                        vrf_name=vrf_name,
                                        destination_ip=dest_ip,
                                        next_hop=next_hop)
        try:
            self._edit_config('running', configure_static_route)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(
                    _("Configuration of static route failed for vrf %s"), vrf_name)
                ctxt.reraise = False

    def configure_vrf_static_route(self, rbridge_id, vrf_name, dest_ip, next_hop):
        configure_static_route = template.\
            CONFIGURE_VRF_IP_STATIC_ROUTE.\
                                 format(rbridge_id=rbridge_id,
                                        vrf_name=vrf_name,
                                        destination_ip=dest_ip,
                                        next_hop=next_hop)
        try:
            self._edit_config('running', configure_static_route)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(
                    _("Configuration of static route failed for vrf %s"), vrf_name)
                ctxt.reraise = False

    def delete_static_route(self, rbridge_id, dest_ip, next_hop):
        configure_static_route = template.\
            DELETE_IP_STATIC_ROUTE.\
                                 format(rbridge_id=rbridge_id,
                                        destination_ip=dest_ip,
                                        next_hop=next_hop)
        try:
            self._edit_config('running', configure_static_route)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("Configuration of static route failed"))
                ctxt.reraise = False

    def configure_static_route(self, rbridge_id, dest_ip, next_hop):
        configure_static_route = template.\
            CONFIGURE_IP_STATIC_ROUTE.\
                                 format(rbridge_id=rbridge_id,
                                        destination_ip=dest_ip,
                                        next_hop=next_hop)
        try:
            self._edit_config('running', configure_static_route)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("Configuration of static route failed"))
                ctxt.reraise = False

    def strip_vrrp_version(self, confstr, version):
        nos_version = self.osversion
        if (int(nos_version[0]) >= 5):
            return confstr
        vrrp_version = '<version>{0}</version>'.format(version)
        confstr = confstr.replace(vrrp_version, '')
        return confstr

    def create_rule(self, confstr):
        """delete Acl Policy from VDX"""
        self._edit_config('running', confstr, timeout=2000)

    def create_acl(self, policy_name):
        """delete Acl Policy from VDX"""
        confstr = template.CREATE_ACL_POLICY.format(acl_name=policy_name)
        self._edit_config('running', confstr)

    def delete_acl(self, rbridge_id, policy_name):
        """delete Acl Policy from VDX"""
        confstr = template.REMOVE_ACL_POLICY.format(acl_name=policy_name)
        if self.is_ip_acl_exists(policy_name) and \
            not self.is_ip_acl_applied_on_any_svi(rbridge_id,
                                                  policy_name):
            self._edit_config('running', confstr)

    def configure_acl_on_svi(self, rbridge_id, vlan_id, name, direction):
        """delete Acl Policy from VDX"""
        confstr = template.SVI_IP_ACL.format(rbridge_id=rbridge_id,
                                             vlan_id=vlan_id,
                                             name=name,
                                             direction=direction)
        if self.is_ip_acl_exists(name):
            self._edit_config('running', confstr)

    def configure_native_vlan_on_interface(self, speed, name, vlan_id):
        """configure native vlan on interface"""
        confstr1 = template.ALLOW_UNTAG_TRAF_ON_INTERFACE.format(speed=speed,
                                                                 name=name)
        confstr2 = template.ADD_NATIVE_VLAN_TO_INTERFACE.format(speed=speed,
                                                                name=name, vlan_id=vlan_id)
        confstr_trunk = template.CONFIGURE_INTERFACE_SWITCHPORT_TRUNK.format(
            speed=speed, name=name)
        self.configure_l2_mode_for_interface(speed, name)
        self.configure_interface_in_trunk_mode(confstr_trunk)
        self.activate_interface(speed, name)
        try:
            self._edit_config('running', confstr1)
        except Exception as ex:
            LOG.warning(_("interface ready to accept untagged traffic"))
        try:
            self._edit_config('running', confstr2)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("Error configuring native vlan on interface {}"))
                ctxt.reraise = False

    def remove_native_vlan_from_interface(self, speed, name):
        """configure native vlan on interface"""
        confstr = template.REMOVE_NATIVE_VLAN_FROM_INTERFACE.format(
            speed=speed, name=name)
        try:
            self._edit_config('running', confstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("Error remove native vlan on interface {}"))
                ctxt.reraise = False

    def configure_mtu_on_interface(self, speed, name, mtu):
        """native vlan on interfacew"""
        confstr = template.CONFIGURE_MTU_ON_INTERFACE.format(
            speed=speed,
                                             name=name,
                                             mtu=mtu)
        try:
            self._edit_config('running', confstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning(_("Error configuring Mtu on interface {}"))
                ctxt.reraise = False

    def remove_acl_on_svi(self, rbridge_id, vlan_id, name, direction):
        """delete Acl Policy from VDX"""
        confstr = template.REMOVE_SVI_IP_ACL.format(rbridge_id=rbridge_id,
                                                    vlan_id=vlan_id,
                                                    name=name,
                                                    direction=direction)
        if self.is_ip_acl_applied_on_svi(rbridge_id, vlan_id, name):
            self._edit_config('running', confstr)

    def is_ip_acl_exists(self, name):
        """checks if ip Acl exists on VDX box"""
        filterstr = template.IP_ACL_NAME_XPATH_FILTER.format(name=name)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if name in response:
            return True
        return False

    def is_ip_acl_applied_on_any_svi(self, rbridge_id, name):
        """checks if ip acl is applied on any of svi interface"""

        filterstr = template.ACL_ON_SVIS_XPATH_FILTER.format(
            rbridge_id=rbridge_id)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if name in response:
            return True
        return False

    def is_ip_acl_applied_on_svi(self, rbridge_id, svi, name):
        """checks if ip acl is applied on given of svi interface"""
        filterstr = template.ACL_ON_SVI_XPATH_FILTER.format(
            rbridge_id=rbridge_id, svi=svi)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if name in response:
            return True
        return False

    def is_sequence_id_exists(self, name, seq_id):
        """checks if sequence id configured for given Acl"""
        filterstr = template.SEQ_ID_EXISTS.format(name=name, id=seq_id)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))

        if name in response:
            return True
        return False

    def is_interface_id_exists(self, speed, name):
        """checks if given interface is present"""
        filterstr = template.INTERFACE_XPATH_FILTER.format(speed=speed,
                                                           name=name)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if name in response:
            return True
        return False

    def is_svi_exists(self, rbridge_id, name):
        """checks if given interface is present"""
        filterstr = template.SVI_EXISTS_XPATH_FILTER.format(
            rbridge_id=rbridge_id, name=name)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if name in response:
            return True

    def is_svi_shutdown(self, rbridge_id, name):
        """checks if given interface is active"""
        filterstr = template.SVI_STATUS_XPATH_FILTER.format(
            rbridge_id=rbridge_id, name=name)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if "shutdown" in response:
            return True
        return False

    def is_interface_shutdown(self, speed, name):
        """checks if given interface is active"""
        filterstr = template.INTERFACE_STATUS_XPATH_FILTER.format(
            speed=speed, name=name)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if "shutdown" in response:
            return True
        return False

    def is_interface_in_channel_group_mode(self, speed, name):
        """checks if given interface is active"""
        filterstr = template.INTERFACE_CG_STATUS_XPATH_FILTER.format(
            speed=speed, name=name)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if "channel-group" in response:
            return True
        return False

    def is_interface_in_port_profile_mode(self, speed, name):
        """checks if given interface is active"""
        filterstr = template.INTERFACE_PP_STATUS_XPATH_FILTER.format(
            speed=speed, name=name)
        try:
            response = self._get_config('running', filterstr)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
        if "port-profile-port" in response:
            return True
        return False

    def set_interface_to_accept_l2_mode(self, speed, name):

        confstr = template.REMOVE_PORT_PROFILE_PORT.format(speed=speed,
                                                           name=name)
        self._edit_config('running', confstr)

    @retry(RetryableException)
    def nos_version_request(self, mgr):
        """Get firmware information using NETCONF rpc."""
        # reply = mgr.dispatch(template.SHOW_FIRMWARE_VERSION, None, None)
        # LOG.info(_("msg {}".format(reply)))
        # et = ElementTree.fromstring(str(reply))
        # return et.find(template.NOS_VERSION).text
        return "7.0.0"
