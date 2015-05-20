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

import logging
import re
import urllib

import netaddr
from neutron.i18n import _LI, _LE
from novaclient import exceptions as nova_exc
from oslo_serialization import jsonutils
from oslo_utils import excutils
import requests

from networking_brocade.vyatta.common import config
from networking_brocade.vyatta.common import exceptions as v_exc
from networking_brocade.vyatta.common import globals as vyatta_globals
from networking_brocade.vyatta.common import parsers
from networking_brocade.vyatta.common import utils as vyatta_utils
from networking_brocade.vyatta.common import vrouter_config


LOG = logging.getLogger(__name__)


class VRouterRestAPIClient(object):
    """Vyatta vRouter REST API Client.

    Uses vRouter REST API to configure vRouter.
    """
    CFG_FMT_GENERIC = 'generic'
    CFG_FMT_COMMANDS = 'commands'

    IF_MAC_ADDRESS = 'mac_address'
    IF_IP_ADDRESS = 'ip_address'
    IF_GATEWAY_IP = 'gateway_ip'

    REST_RETRY_LIMIT = 10
    REST_RETRY_DELAY = 5

    _VROUTER_VSE_MODEL = 54
    _VROUTER_VR_MODEL = 56

    # Floating ip NAT rules will be prioritized before subnet NAT rules.
    # Same rule number is used for both SNAT and DNAT rule.
    _MAX_NAT_FLOATING_IP_RULE_NUM = 4000
    _MAX_NAT_EXCLUDE_RULE_NUM = 8000
    _MAX_NAT_SUBNET_IP_RULE_NUM = 12000

    _EXTERNAL_GATEWAY_DESCR = 'External_Gateway'
    _ROUTER_INTERFACE_DESCR = 'Router_Interface'

    _external_gw_info = None
    _router_if_subnet_dict = {}
    _router_subnet_nat_exclude_dict = {}
    _floating_ip_dict = {}

    # Floating IP NAT rule number counter.
    # It will be incremented in get next method.
    _nat_floating_ip_rule_num = 0

    # SNAT exclude rule number counter.
    # These exclusions need to be prioritized before any
    # subnet NAT rules
    # It will be incremented in get next method
    _nat_exclude_rule_num = _MAX_NAT_FLOATING_IP_RULE_NUM

    # Subnet ip NAT rules are for router interfaces.
    # As we want to prioritize floating ip NAT rules first,
    # subnet rules will start only after floating ip rules.
    # It will be incremented in get next method.
    _nat_subnet_ip_rule_num = _MAX_NAT_EXCLUDE_RULE_NUM

    # Stores the vrouter model
    _vrouter_model = None

    def __init__(self):
        self.address = None

    def connect(self, address):
        """Connects to vRouter using the provided address.

        Retrieves the configuration and updates the cache.
        """
        self.address = address
        LOG.info(_LI("Vyatta vRouter REST API: "
                     "Connecting to vRouter %s"), address)
        self._process_model()
        self._sync_cache()

    def init_router(self, router_name, admin_state_up):
        """
            Configures Router name and Admin State.
        """
        cmd_list = []

        self._set_router_name_cmd(cmd_list, router_name)
        self._set_admin_state_cmd(cmd_list, admin_state_up)

        vyatta_utils.retry(
            self.exec_cmd_batch,
            args=(cmd_list,), exceptions=(v_exc.VRouterOperationError,),
            limit=self.REST_RETRY_LIMIT, delay=self.REST_RETRY_DELAY)

    def update_router(self, router_name=None,
                      admin_state_up=None, external_gateway_info=None):
        """Updates Router name, Admin state, External gateway.

        All the parameters are optional.
        """

        cmd_list = []

        if router_name:
            self._set_router_name_cmd(cmd_list, router_name)

        if admin_state_up is not None:
            self._set_admin_state_cmd(cmd_list, admin_state_up)

        if external_gateway_info is not None:
            given_gw_info = self._get_gw_interface_info(external_gateway_info)
            nat_rules = self._update_gw_config_on_change(given_gw_info,
                                                         cmd_list)
            self._update_gw_cache_info(given_gw_info, nat_rules)
        else:
            self._clear_gw_configuration(cmd_list)
            self._clear_cached_gw_info()

    def add_interface_to_router(self, interface_info):
        """Sets ip address of the ethernet interface.

        Ethernet interface identifier is derived from the given mac-address.
        """

        (if_ip_address,
         eth_if_id) = self._get_ethernet_if_info(interface_info)

        cmd_list = []
        self._set_ethernet_if_cmd(cmd_list,
                                  eth_if_id,
                                  if_ip_address,
                                  self._ROUTER_INTERFACE_DESCR)

        ip_network = netaddr.IPNetwork(if_ip_address)
        router_if_subnet = str(ip_network.cidr)

        # If external gateway was configured before then
        # we need to add SNAT rules
        rule_num = None
        if ip_network.version == 4 and self._external_gw_info is not None:
            rule_num = self._add_snat_rule_for_router_if_cmd(
                cmd_list, router_if_subnet, self._external_gw_info)

        self.exec_cmd_batch(cmd_list)

        # Cache the router interface info using subnet
        if router_if_subnet not in self._router_if_subnet_dict:
            self._router_if_subnet_dict[router_if_subnet] = None

        if self._external_gw_info is not None:
            self._router_if_subnet_dict[router_if_subnet] = rule_num

    def remove_interface_from_router(self, interface_info):
        """Removes ip address of the ethernet interface.

        Ethernet interface identifier is derived from the given mac-address.
        """

        (if_ip_address,
         eth_if_id) = self._get_ethernet_if_info(interface_info)

        cmd_list = []
        self._delete_ethernet_if_cmd(cmd_list,
                                     eth_if_id,
                                     if_ip_address,
                                     self._ROUTER_INTERFACE_DESCR)

        # Check the cache for router interface
        router_if_subnet = self._get_subnet_from_ip_address(if_ip_address)
        if router_if_subnet in self._router_if_subnet_dict:
            # We need to delete the SNAT rule
            nat_rule = self._router_if_subnet_dict[router_if_subnet]
            if nat_rule is not None:
                self._delete_snat_rule_cmd(cmd_list, nat_rule)

        self.exec_cmd_batch(cmd_list)

        # Remove the router interface info from cache
        self._router_if_subnet_dict.pop(router_if_subnet, None)

    def update_interface(self, interface_info):
        if_name = self.get_ethernet_if_id(interface_info.mac_address)
        router_config = self.get_config()
        if_config = router_config.find_interface(if_name)

        old_addrs = set(netaddr.IPNetwork(ip)
                        for ip in if_config.getlist('address'))
        new_addrs = set(interface_info.ip_addresses)

        cmd_list = []

        for ip in old_addrs - new_addrs:
            self._delete_ethernet_ip_cmd(cmd_list, if_name, str(ip))
            # TODO(asaprykin): Configure SNAT

        for ip in new_addrs - old_addrs:
            self._set_ethernet_ip(cmd_list, if_name, str(ip))
            # TODO(asaprykin): Configure SNAT

        self.exec_cmd_batch(cmd_list)

    def assign_floating_ip(self, floating_ip, fixed_ip):
        """Creates SNAT and DNAT rules for given floating ip and fixed ip."""

        if self._external_gw_info is None:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='External gateway not configured')

        cmd_list = []

        ext_if_id = self._external_gw_info.get_ethernet_if_id()

        # Get the next NAT rule number and add the NAT rule
        nat_rule_num = self._get_next_nat_floating_ip_rule_num()
        self._add_snat_rule_cmd(cmd_list, nat_rule_num, ext_if_id,
                                fixed_ip, floating_ip)
        self._add_dnat_rule_cmd(cmd_list, nat_rule_num, ext_if_id,
                                floating_ip, fixed_ip)

        # Set the floating ip in external gateway interface
        gw_net = netaddr.IPNetwork(self._external_gw_info.get_ip_address())
        self._set_ethernet_ip(
            cmd_list, self._external_gw_info.get_ethernet_if_id(),
            '{0}/{1}'.format(floating_ip, gw_net.prefixlen))

        self.exec_cmd_batch(cmd_list)

        # Store SNAT and DNAT rule in cache
        dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
        self._floating_ip_dict[dict_key] = nat_rule_num

    def unassign_floating_ip(self, floating_ip, fixed_ip):
        """Deletes SNAT and DNAT rules for given floating ip and fixed ip."""

        if self._external_gw_info is None:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='External gateway not configured')

        cmd_list = []

        # Check the cache for nat rules
        dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
        if dict_key in self._floating_ip_dict:

            # Get the NAT rules from the cache and delete them
            nat_rule = self._floating_ip_dict[dict_key]
            self._delete_snat_rule_cmd(cmd_list, nat_rule)
            self._delete_dnat_rule_cmd(cmd_list, nat_rule)

            # Delete the floating ip in external gateway interface
            gw_net = netaddr.IPNetwork(self._external_gw_info.get_ip_address())
            self._delete_ethernet_ip_cmd(
                cmd_list, self._external_gw_info.get_ethernet_if_id(),
                '{0}/{1}'.format(floating_ip, gw_net.prefixlen))
        else:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='NAT rule not found for floating ip {0}'
                .format(floating_ip))

        self.exec_cmd_batch(cmd_list)

        if dict_key in self._floating_ip_dict:
            self._floating_ip_dict.pop(dict_key)

    def update_static_routes(self, routes_add, routes_del):

        def _get_route_type(dest):
            ip = netaddr.IPNetwork(rule.dest_cidr)
            if ip.version == 4:
                return 'route'
            else:
                return 'route6'

        cmd_list = []
        for rule in routes_add:
            cmd_list.append(SetCmd(
                'protocols/static/{0}/{1}/next-hop/{2}'.format(
                    _get_route_type(rule.dest_cidr),
                    urllib.quote_plus(rule.dest_cidr),
                    urllib.quote_plus(rule.next_hop))))

        for rule in routes_del:
            cmd_list.append(DeleteCmd(
                'protocols/static/{0}/{1}'.format(
                    _get_route_type(rule.dest_cidr),
                    urllib.quote_plus(rule.dest_cidr))))

        self.exec_cmd_batch(cmd_list)

    def disconnect(self):
        self.address = None

    def _rest_call(self, action, uri, custom_headers=None, session=None):
        LOG.debug('Vyatta Router REST Request: {0} {1}'.format(action, uri))
        if session is None:
            session = requests

        auth = tuple(config.VROUTER.vrouter_credentials.split(':'))
        if len(auth) != 2:
            raise v_exc.InvalidParameter(
                cause=_("Invalid vrouter_credentials %s") % len(auth))

        headers = {'Accept': 'application/json',
                   'Content-Length': 0}

        if custom_headers:
            headers.update(custom_headers)

        try:
            uri = 'https://{0}{1}'.format(self.address, uri)
            return session.request(action, uri, auth=auth,
                                   headers=headers, verify=False)
        except requests.ConnectionError:
            LOG.error(_LE('Vyatta vRouter REST API: '
                          'Could not establish HTTP connection to %s'),
                      self.address)
            with excutils.save_and_reraise_exception():
                raise v_exc.VRouterConnectFailure(ip_address=self.address)

    def _get_ethernet_if_info(self, interface_info):
        gw_mac_address = interface_info[self.IF_MAC_ADDRESS]
        gw_ip_address = interface_info[self.IF_IP_ADDRESS]
        gw_if_id = self.get_ethernet_if_id(gw_mac_address)

        return gw_ip_address, gw_if_id

    def _get_gw_interface_info(self, external_gateway_info):
        (gw_ip_address,
         gw_if_id) = self._get_ethernet_if_info(external_gateway_info)
        gw_gateway_ip = external_gateway_info[self.IF_GATEWAY_IP]

        given_gw_info = InterfaceInfo(gw_if_id, gw_ip_address, gw_gateway_ip)
        return given_gw_info

    def _update_gw_config_on_change(self, given_gw_info, cmd_list):
        # Check if the external gw info is already cached.
        # If the given external gw info is not equal to cached gw info
        # then we need to update the existing gw info.
        # So, clear old gw info and set new gw info.
        if (self._external_gw_info is not None and
                given_gw_info != self._external_gw_info):
            LOG.debug("Vyatta vRouter REST API: Cached Gateway info is "
                      "not the same as given gateway info")
            self._delete_external_gateway_if_cmd(
                cmd_list, self._external_gw_info)

        nat_rules = self._set_external_gateway_if_cmd(
            cmd_list, given_gw_info)

        # Execute the configuration commands
        self.exec_cmd_batch(cmd_list)

        return nat_rules

    def _update_gw_cache_info(self, given_gw_info, nat_rules):
        # Cache the external gateway info
        self._external_gw_info = given_gw_info

        # Cache the nat rules
        for router_if_subnet, rule_num in nat_rules.iteritems():
            self._router_if_subnet_dict[router_if_subnet] = rule_num

    def _clear_gw_configuration(self, cmd_list):
        # If external gateway info was cached before
        # then clear the gateway router info
        if self._external_gw_info is not None:
            self._delete_external_gateway_if_cmd(
                cmd_list, self._external_gw_info)
        else:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='External gateway not already configured')

        # Execute the configuration commands
        self.exec_cmd_batch(cmd_list)

    def _clear_cached_gw_info(self):
        # Clear the external gateway info from the cache
        self._external_gw_info = None

        # Remove NAT rules for the existing router interfaces
        for router_if_subnet in self._router_if_subnet_dict.keys():
            self._router_if_subnet_dict[router_if_subnet] = None

    def _set_external_gateway_if_cmd(self, cmd_list, gw_info):
        """Sets the external gateway configuration.

        Adds SNAT rules and updates the cache.
        """

        # Set the external gateway ip address
        self._set_ethernet_if_cmd(cmd_list,
                                  gw_info.get_ethernet_if_id(),
                                  gw_info.get_ip_address(),
                                  self._EXTERNAL_GATEWAY_DESCR)

        self._set_system_gateway_cmd(cmd_list, gw_info.get_gateway_ip())

        # Add NAT rules for the existing router interfaces
        nat_rules = {}
        for router_if_subnet in self._router_if_subnet_dict.keys():
            if netaddr.IPNetwork(router_if_subnet).version != 4:
                continue

            rule_num = self._add_snat_rule_for_router_if_cmd(
                cmd_list, router_if_subnet, gw_info)
            nat_rules[router_if_subnet] = rule_num

        return nat_rules

    def _delete_external_gateway_if_cmd(self, cmd_list, gw_info):
        """Sets the external gateway configuration.

        Adds SNAT rules and updates the cache.
        """

        # Remove default gateway
        self._delete_system_gateway_cmd(cmd_list,
                                        gw_info.get_gateway_ip())

        # Delete the external gateway ip address
        self._delete_ethernet_if_cmd(cmd_list,
                                     gw_info.get_ethernet_if_id(),
                                     gw_info.get_ip_address(),
                                     self._EXTERNAL_GATEWAY_DESCR)

        # Remove NAT rules for the existing router interfaces
        for nat_rule in self._router_if_subnet_dict.values():
            self._delete_snat_rule_cmd(cmd_list, nat_rule)

    def _add_snat_rule_for_router_if_cmd(self, cmd_list,
                                         router_if_subnet,
                                         ext_gw_info):

        # Get the next SNAT rule number
        rule_num = self._get_next_nat_subnet_ip_rule_num()

        # Create the SNAT rule and store in the cache
        self._add_snat_rule_cmd(cmd_list,
                                rule_num,
                                ext_gw_info.get_ethernet_if_id(),
                                router_if_subnet,
                                ext_gw_info.get_ip_addr_without_cidr())

        return rule_num

    def _get_snat_exclude_cache_entry(self, src_addr, dest_addr):
        # TODO(sridhar): do we need to support same VPN
        # src-remote pair for multiple
        # external GWs?
        return src_addr + "-" + dest_addr

    def add_snat_exclude_rule(self, cmd_list,
                              ext_if_id, src_addr, dest_addr):

        """Appends vRouter cmds to add a NAT exclude rule
         and caches the rule number in the local 'nat-exclude' dict
         """

        cache_entry = self._get_snat_exclude_cache_entry(src_addr, dest_addr)
        try:
            # if an entry already exist, the nat exclude is already in vRouter
            rule_num = self._router_subnet_nat_exclude_dict[cache_entry]
            LOG.info(_LI('Vyatta vRouter Reuse existing EXCLUDE'
                         ' rule_num : %d'), rule_num)
        except KeyError:
            # Get the next SNAT exclude rule number
            rule_num = self._get_next_nat_exclude_rule_num()
            LOG.info(_LI('Vyatta vRouter Prepare new EXCLUDE'
                         ' rule_num : %d'), rule_num)

        # Create the SNAT rule and store in the cache
        # TODO(sridhar): Unconditionally add for now due client dict bug
        self._add_snat_exclude_rule_cmd(cmd_list,
                                        rule_num,
                                        ext_if_id,
                                        src_addr,
                                        dest_addr)

        LOG.info(_LI('Vyatta vRouter Add Cache EXCLUDE rule_num : %d at %s'),
                 rule_num, cache_entry)
        self._router_subnet_nat_exclude_dict[cache_entry] = rule_num

        return rule_num

    def delete_snat_exclude_rule(self, cmd_list,
                                 ext_if_id, src_addr, dest_addr):
        """Appends vRouter cmds to delete a NAT exclude rule
        and remove the rule number from the local 'nat-exclude' dict
        """

        cache_entry = self._get_snat_exclude_cache_entry(src_addr, dest_addr)
        try:
            nat_rule = self._router_subnet_nat_exclude_dict[cache_entry]
            if nat_rule is not None:
                LOG.info(_LI('Vyatta vRouter: Delete Cache EXCLUDE'
                             ' rule_num : %d at %s'),
                         nat_rule, cache_entry)
                self._delete_snat_rule_cmd(cmd_list, nat_rule)
            else:
                LOG.info(_LI('Vyatta vRouter: Delete Cache EXCLUDE'
                             ' entry at %s doesnt exist'),
                         nat_rule, cache_entry)
        except KeyError:
                LOG.info(_LI('Vyatta vRouter: Delete Cache EXCLUDE:'
                             ' COULD NOT find rule_num at cache entry'
                             ' at %s'), cache_entry)

    def _get_subnet_from_ip_address(self, ip_address):

        ip_network = netaddr.IPNetwork(ip_address)
        # Return subnet with CIDR format
        ip_subnet = str(ip_network.cidr)

        return ip_subnet

    def _get_floating_ip_key(self, floating_ip, fixed_ip):
        """Returns the key to store floating ip and fixed ip combination."""

        return "{0}.{1}".format(floating_ip, fixed_ip)

    def _get_next_nat_floating_ip_rule_num(self):
        """Returns the next NAT rule number for floating ip."""

        if (self._nat_floating_ip_rule_num >=
                self._MAX_NAT_FLOATING_IP_RULE_NUM):
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='Max NAT Floating IP rule count reached')

        self._nat_floating_ip_rule_num += 1
        return self._nat_floating_ip_rule_num

    def _get_next_nat_exclude_rule_num(self):
        """Returns the next NAT exclude rule number for VPN purposes"""

        if self._nat_exclude_rule_num >= self._MAX_NAT_EXCLUDE_RULE_NUM:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='Max NAT Exclude rule count reached')

        self._nat_exclude_rule_num += 1
        return self._nat_exclude_rule_num

    def _get_next_nat_subnet_ip_rule_num(self):
        """Returns the next NAT rule number for subnet ip."""

        if self._nat_subnet_ip_rule_num >= self._MAX_NAT_SUBNET_IP_RULE_NUM:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='Max NAT Subnet IP rule count reached')

        self._nat_subnet_ip_rule_num += 1
        return self._nat_subnet_ip_rule_num

    def _get_admin_state(self):
        """Retrieves Admin State."""
        output = self._show_cmd("ip/forwarding")
        LOG.info(_LI('Vyatta vRouter status : %s'), output)
        return "IP forwarding is on" in output

    def _get_nat_cmd(self):

        return 'service/nat' if (self._vrouter_model ==
                                 self._VROUTER_VR_MODEL) else 'nat'

    def _add_snat_rule_cmd(self, cmd_list, rule_num, ext_if_id,
                           src_addr, translation_addr):
        """Creates SNAT rule with the given parameters."""

        nat_cmd = self._get_nat_cmd()

        # Execute the commands
        cmd_list.append(
            SetCmd("{0}/source/rule/{1}".format(nat_cmd, rule_num)))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/outbound-interface/{2}"
                               .format(nat_cmd, rule_num, ext_if_id)))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/source/address/{2}"
                               .format(nat_cmd, rule_num,
                                       urllib.quote_plus(src_addr))))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/translation/address/{2}"
                               .format(nat_cmd, rule_num,
                                       urllib.quote_plus(translation_addr))))

    def _add_snat_exclude_rule_cmd(self, cmd_list, rule_num, ext_if_id,
                                   src_addr, dest_addr):
        """Create SNAT exclude rule between tenant networks and
        remote VPN CIDR
        """

        nat_cmd = self._get_nat_cmd()

        LOG.info(_LI('Vyatta vRouter Adding EXCLUDE rule_num'
                     ' : %s, ext_if_id %s, src_addr %s, dest_addr %s'),
                 rule_num, ext_if_id, src_addr, dest_addr)

        # Execute the commands
        cmd_list.append(SetCmd("{0}/source/rule/{1}"
                               .format(nat_cmd, rule_num)))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/exclude"
                               .format(nat_cmd, rule_num)))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/outbound-interface/{2}"
                               .format(nat_cmd, rule_num, ext_if_id)))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/source/address/{2}"
                               .format(nat_cmd, rule_num,
                                       urllib.quote_plus(src_addr))))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/destination/address/{2}"
                               .format(nat_cmd, rule_num,
                                       urllib.quote_plus(dest_addr))))

    def _add_dnat_rule_cmd(self, cmd_list, rule_num, ext_if_id,
                           dest_addr, translation_addr):
        """Creates DNAT rule with the given parameters."""

        nat_cmd = self._get_nat_cmd()

        # Execute the commands
        cmd_list.append(
            SetCmd("{0}/destination/rule/{1}".format(nat_cmd, rule_num)))
        cmd_list.append(SetCmd("{0}/destination/rule/{1}/inbound-interface/{2}"
                               .format(nat_cmd, rule_num, ext_if_id)))
        cmd_list.append(SetCmd("{0}/destination/rule/{1}/destination/"
                               "address/{2}".format(
                                   nat_cmd, rule_num,
                                   urllib.quote_plus(dest_addr))))
        cmd_list.append(SetCmd("{0}/destination/rule/{1}/translation/"
                               "address/{2}".format(
                                   nat_cmd, rule_num,
                                   urllib.quote_plus(translation_addr))))

    def _delete_snat_rule_cmd(self, cmd_list, rule_num):
        """Deletes the given SNAT rule."""

        cmd_list.append(DeleteCmd("{0}/source/rule/{1}".
                                  format(self._get_nat_cmd(), rule_num)))

    def _delete_dnat_rule_cmd(self, cmd_list, rule_num):
        """Deletes the given DNAT rule."""

        cmd_list.append(DeleteCmd("{0}/destination/rule/{1}".
                                  format(self._get_nat_cmd(), rule_num)))

    def _set_admin_state_cmd(self, cmd_list, admin_state):
        """Sets Admin State using command."""

        if admin_state:
            if not self._get_admin_state():
                cmd_list.append(DeleteCmd("system/ip/disable-forwarding"))
        else:
            if self._get_admin_state():
                cmd_list.append(SetCmd("system/ip/disable-forwarding"))

    def get_vrouter_configuration(self, mode=CFG_FMT_GENERIC):
        cmd = ['configuration']
        if mode == self.CFG_FMT_GENERIC:
            pass
        elif mode == self.CFG_FMT_COMMANDS:
            cmd.append('commands')
        else:
            raise v_exc.InvalidParameter(
                cause='unsupported configuration dump format')

        cmd = '/'.join(cmd)
        return self._show_cmd(cmd)

    def get_vpn_ipsec_sa(self, peer=None, tunnel=None):
        assert not tunnel or peer

        cmd = ['vpn', 'ipsec', 'sa']
        if peer:
            cmd.append('peer')
            cmd.append(urllib.quote_plus(peer))
        if tunnel:
            cmd.append('tunnel')
            cmd.append(urllib.quote_plus(tunnel))
        cmd = '/'.join(cmd)
        return self._show_cmd(cmd)

    def get_ethernet_if_id(self, mac_address):
        """Uses show command output to find the ethernet interface."""

        LOG.debug('Vyatta vRouter:get_ethernet_if_id. Given MAC {0}'
                  .format(repr(mac_address)))
        iface = self._find_interface(mac_address)
        return iface['name']

    def get_config(self):
        raw_config = self._show_cmd('configuration/all')
        return vrouter_config.RouterConfig.from_string(raw_config)

    def _get_interface_cmd(self):
        if self._vrouter_model == self._VROUTER_VR_MODEL:
            return "dataplane"
        else:
            return "ethernet"

    def _set_ethernet_ip(self, cmd_list, if_id, ip_address):
        """Sets ip address to an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        cmd_list.append(SetCmd("interfaces/{0}/{1}/address/{2}"
                               .format(if_cmd, if_id,
                                       urllib.quote_plus(ip_address))))

    def _set_ethernet_if_cmd(self, cmd_list, if_id,
                             ip_address, descr):
        """Sets ip address and description of an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        # Execute the commands
        cmd_list.append(SetCmd("interfaces/{0}/{1}/address/{2}"
                               .format(if_cmd, if_id,
                                       urllib.quote_plus(ip_address))))
        cmd_list.append(SetCmd("interfaces/{0}/{1}/description/{2}"
                               .format(if_cmd, if_id,
                                       urllib.quote_plus(descr))))

    def _delete_ethernet_ip_cmd(self, cmd_list, if_id, ip_address):
        """Deletes ip address from an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        cmd_list.append(DeleteCmd("interfaces/{0}/{1}/address/{2}"
                                  .format(if_cmd, if_id,
                                          urllib.quote_plus(ip_address))))

    def _delete_ethernet_if_cmd(self, cmd_list, if_id,
                                ip_address, descr):
        """Deletes ip address and description of an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        # Execute the commands
        cmd_list.append(DeleteCmd("interfaces/{0}/{1}/address/{2}"
                                  .format(if_cmd, if_id,
                                          urllib.quote_plus(ip_address))))
        cmd_list.append(DeleteCmd("interfaces/{0}/{1}/description/{2}"
                                  .format(if_cmd, if_id,
                                          urllib.quote_plus(descr))))
        cmd_list.append(DeleteCmd("interfaces/{0}/{1}".
                                  format(if_cmd, if_id)))

    def _set_router_name_cmd(self, cmd_list, router_name):
        """Configures router name using command."""
        if '_' in router_name:
            router_name = router_name.replace('_', '-')

        cmd_list.append(SetCmd("system/host-name/{0}".
                               format(urllib.quote_plus(router_name))))

    def _set_system_gateway_cmd(self, cmd_list, gateway_ip):

        cmd_list.append(SetCmd("protocols/static/route/{0}/next-hop/{1}".
                               format(urllib.quote_plus('0.0.0.0/0'),
                                      urllib.quote_plus(gateway_ip))))

    def _delete_system_gateway_cmd(self, cmd_list, gateway_ip):

        cmd_list.append(DeleteCmd("protocols/static/route/{0}".
                                  format(urllib.quote_plus('0.0.0.0/0'))))

    def _configure_cmd(self, cmd_type, cmd):
        """Executes the given configuration command.

        Commits and Saves the configuration changes to the startup config.
        """

        self.configure_cmd_list(cmd_type, [cmd])

    def exec_cmd_batch(self, user_cmd_list):
        """Executes the given configuration command list.

        Commits and Saves the configuration changes to the startup config.
        """
        response = self._rest_call("POST", "/rest/conf")
        self._check_response(response)

        config_url = response.headers['Location']
        if config_url is None:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='REST API configuration URL is null')

        config_url = "/" + config_url
        for user_cmd in user_cmd_list:
            url = user_cmd.make_url(config_url)
            LOG.debug(
                "Vyatta vRouter REST API: Config command %s", url)
            response = self._rest_call("PUT", url)
            self._check_response(response, config_url)

        response = self._rest_call(
            "POST", config_url + "/commit")
        LOG.debug("Vyatta vRouter REST API: %s/commit", config_url)
        self._check_response(response, config_url)

        response = self._rest_call(
            "POST", config_url + "/save")
        LOG.debug("Vyatta vRouter REST API: %s/save", config_url)
        self._check_response(response, config_url)

        response = self._rest_call("DELETE", config_url)
        self._check_response(response)

    def _check_response(self, response, config_url=None, session=None):

        if session is None:
            session = requests

        if response.status_code not in (requests.codes.OK,
                                        requests.codes.CREATED):
            LOG.error(_LE('Vyatta vRouter REST API: Response Status : '
                      '%(status)s Reason: %(reason)s') %
                      {'status': response.status_code,
                       'reason': response.reason})

            if config_url is not None:
                self._rest_call("DELETE", config_url, session=session)

            raise v_exc.VRouterOperationError(
                ip_address=self.address, reason=response.reason)

    def _get_config_cmd(self, user_cmd):
        """Executes the given "get config" command."""

        response = self._rest_call("POST", "/rest/conf")
        self._check_response(response)

        config_url = response.headers['Location']
        if config_url is None:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='REST API Configuration URL is None')
        config_url = "/" + config_url
        config_cmd = '{0}/{1}/'.format(config_url, user_cmd)
        response = self._rest_call("GET", config_cmd)
        self._check_response(response)
        data = jsonutils.loads(response.text)
        self._rest_call("DELETE", config_url)
        return data

    def _show_cmd(self, user_cmd):
        # TODO(asaprykin): Need to verify error handling

        op_cmd = '/rest/op/show/{0}'.format(user_cmd)
        response = self._rest_call("POST", op_cmd)
        self._check_response(response)

        op_url = response.headers['Location']
        if op_url is None:
            raise v_exc.VRouterOperationError(
                ip_address=self.address, reason='REST API Op URL is None')

        op_url = "/" + op_url

        output = []

        while True:
            response = self._rest_call('GET', op_url)
            if response.status_code == requests.codes.GONE:
                break

            if response.text:
                output.append(response.text)

        self._rest_call("DELETE", op_url)
        return ''.join(output)

    def _process_model(self):

        model = None
        show_output = self._show_cmd("version")
        LOG.debug('Vyatta vRouter REST API: Version output : %s',
                  show_output)
        if show_output is not None:
            ma = re.compile(".+Description.+Brocade Vyatta\D+(\d+).+",
                            re.DOTALL)
            result = ma.match(show_output)
            LOG.debug('Vyatta vRouter REST API: Result : %s', result)
            if result is not None:
                model_str = result.group(1)
                LOG.debug('Vyatta vRouter REST API: Result : %s',
                          model_str)
                model = int(model_str) / 100
                LOG.debug('Vyatta vRouter REST API: Result : %s',
                          model)
                if model in (self._VROUTER_VSE_MODEL, self._VROUTER_VR_MODEL):
                    self._vrouter_model = model

        LOG.debug('Vyatta vRouter REST API: Version : %s',
                  self._vrouter_model)
        if self._vrouter_model is None:
            raise v_exc.VRouterOperationError(
                ip_address=self.address,
                reason='Unable to process vRouter model info: {0}'
                .format(model))

    def _sync_cache(self):

        show_output = self._show_cmd("configuration/all")

        system_gw = None
        gateway_str = self._get_config_block("protocols", show_output)
        if gateway_str is not None:
            system_gw = self._parse_system_gateway(gateway_str)

        interfaces_str = self._get_config_block("interfaces", show_output)
        if interfaces_str is not None:
            self._process_interfaces(interfaces_str, system_gw)

        if self._vrouter_model == self._VROUTER_VR_MODEL:
            show_output = self._get_config_block("service", show_output)

        nat_str = self._get_config_block("nat", show_output)
        if nat_str is not None:
            self._process_source_nat_rules(nat_str)

        LOG.info(_LI("Vyatta vRouter cache ext gw %s"),
                 self._external_gw_info)
        LOG.info(_LI("Vyatta vRouter cache router if dict %s"),
                 self._router_if_subnet_dict)
        LOG.info(_LI("Vyatta vRouter cache floating ip dict %s"),
                 self._floating_ip_dict)
        LOG.info(_LI("Vyatta vRouter cache router nat-exclude dict %s"),
                 self._router_subnet_nat_exclude_dict)
        LOG.info(_LI("Vyatta vRouter cache NAT floating ip %s"),
                 self._nat_floating_ip_rule_num)
        LOG.info(_LI("Vyatta vRouter cache NAT subnet ip %s"),
                 self._nat_subnet_ip_rule_num)
        LOG.info(_LI("Vyatta vRouter cache NAT exclude rule num %s"),
                 self._nat_exclude_rule_num)

    def _parse_system_gateway(self, search_str):

        system_gw_ip = None
        ma = re.compile(".+static.+route.+next-hop ([^ \n]+).+", re.DOTALL)
        result = ma.match(search_str)
        if result is not None:
            system_gw_ip = result.group(1)
        return system_gw_ip

    def _process_interfaces(self, search_str, system_gw_ip):

        for paragraph in search_str.split('}'):
            ma = re.compile(
                ".+ethernet (eth\d+).+address ([^ \n]+).+description ([^ \n]+)"
                ".+", re.DOTALL)
            result = ma.match(paragraph)
            if result is not None:
                eth_if_id = result.group(1)
                ip_address = result.group(2)
                description = result.group(3)
                if description == self._EXTERNAL_GATEWAY_DESCR:
                    ext_gw_info = InterfaceInfo(eth_if_id,
                                                ip_address, system_gw_ip)
                    self._external_gw_info = ext_gw_info
                elif description == self._ROUTER_INTERFACE_DESCR:
                    # Cache the router interface info using subnet
                    router_if_subnet = self._get_subnet_from_ip_address(
                        ip_address)
                    self._router_if_subnet_dict[router_if_subnet] = None

    def _process_source_nat_rules(self, search_str):

        for paragraph in search_str.split('rule'):
            ma = re.compile(
                ".(\d+).+outbound-interface.+source.+address ([^ \n]+)"
                ".+translation.+address ([^ \n]+).+", re.DOTALL)
            result = ma.match(paragraph)
            if result is not None:
                rule_num = int(result.group(1))
                src_addr = result.group(2)
                translation_addr = result.group(3)
                if (self._MAX_NAT_EXCLUDE_RULE_NUM < rule_num <
                   self._MAX_NAT_SUBNET_IP_RULE_NUM and
                   src_addr in self._router_if_subnet_dict):
                    # Cache the SNAT rule for router interface
                    self._router_if_subnet_dict[src_addr] = rule_num
                    self._nat_subnet_ip_rule_num = rule_num
                elif (self._MAX_NAT_FLOATING_IP_RULE_NUM < rule_num <
                    self._MAX_NAT_EXCLUDE_RULE_NUM and
                    src_addr in self._router_if_subnet_dict):
                    # TODO(sridhar): Add parsing code for exclude nat rule
                    pass
                elif rule_num < self._MAX_NAT_FLOATING_IP_RULE_NUM:
                    self._nat_floating_ip_rule_num = rule_num
                    floating_ip = translation_addr
                    fixed_ip = src_addr
                    # Store SNAT and DNAT rule in cache
                    dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
                    self._floating_ip_dict[dict_key] = rule_num

    def _get_config_block(self, input_str, search_str):

        if search_str is not None:
            index = search_str.find(input_str)
            if index >= 0:
                block_start = search_str[index + len(input_str):]
                block_str = []
                for line in block_start.split('\n'):
                    if line.startswith('}'):
                        break
                    block_str.append(line)
                return ''.join(block_str)

        return None

    def _get_interfaces(self):
        output = self._show_cmd('interfaces/detail')
        return parsers.parse_interfaces(output)

    def _find_interface(self, mac_address):
        mac_address = mac_address.strip().lower()
        ifaces = self._get_interfaces()
        for iface in ifaces:
            if iface['mac_address'] == mac_address:
                return iface

        raise v_exc.VRouterOperationError(
            ip_address=self.address,
            reason='Ethernet interface with Mac-address {0} does not exist'
            .format(mac_address))


class ClientsPool(object):
    _client_factory = VRouterRestAPIClient

    def __init__(self, compute_client):
        # TODO(dbogun): avoid dependency from nova client
        self._compute_client = compute_client
        self._active_connections = dict()

    def get_by_address(self, router_id, address):
        try:
            client = self._active_connections[router_id]
        except KeyError:
            self._active_connections[router_id] = client = \
                self._client_factory()
            client.connect(address)
        return client

    def get_by_db_lookup(self, router_id, context):
        try:
            client = self._active_connections[router_id]
        except KeyError:
            self._active_connections[router_id] = client = \
                self._make_connection(context, router_id)
        return client

    def _make_connection(self, context, router_id):
        LOG.debug('Vyatta vRouter Driver::Get router driver')

        try:
            router = self._compute_client.servers.get(router_id)
        except nova_exc.ClientException as ex:
            LOG.error(_LE(
                'Unable to find Vyatta vRouter instance {0}. '
                'Exception {1}').format(router_id, ex))
            raise v_exc.InvalidVRouterInstance(router_id=router_id)

        network = vyatta_globals.get_management_network(context)
        network = context.session.merge(network)
        if network in context.session.new:
            raise v_exc.InvalidInstanceConfiguration(
                cause='Unable to find management network')

        LOG.debug('Vyatta vRouter Management network: {0}'.format(
            network['name']))
        try:
            address_map = router.addresses[network['name']]
            address = address_map[0]['addr']
        except (KeyError, IndexError):
            raise v_exc.InvalidVRouterInstance(router_id=router_id)

        return self._client_by_address(address)

    def _client_by_address(self, address):
        # Initialize vRouter API
        try:
            client = self._client_factory()
            client.connect(address)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Vyatta vRouter Driver: vRouter {0} '
                              'Connection exception {1}').format(
                    address, ex))
            raise
        return client


# REST API commands
class UserCmd(object):

    def __init__(self, cmd_type, cmd):
        self.cmd_type = cmd_type
        self.cmd = cmd

    def __repr__(self):
        return '{0} {1!r}'.format(self.cmd_type, self.cmd)

    def __eq__(self, other):
        if not isinstance(other, UserCmd):
            return NotImplemented
        return (self.cmd_type, self.cmd) == (other.cmd_type, other.cmd)

    def __ne__(self, other):
        return not self.__eq__(other)

    def make_url(self, prefix):
        url = (prefix, self.cmd_type, self.cmd)
        return '/'.join(url)


class SetCmd(UserCmd):

    def __init__(self, cmd):
        super(SetCmd, self).__init__("set", cmd)


class DeleteCmd(UserCmd):

    def __init__(self, cmd):
        super(DeleteCmd, self).__init__("delete", cmd)


class InterfaceInfo(object):

    """Class for storing interface related info."""
    def __init__(self, ethernet_if_id, ip_address,
                 gateway_ip=None):
        self._ethernet_if_id = ethernet_if_id
        self._ip_address = ip_address
        self._gateway_ip = gateway_ip
        self._ip_addr_without_cidr = None

    def get_ethernet_if_id(self):
        return self._ethernet_if_id

    def get_ip_address(self):
        return self._ip_address

    def get_ip_addr_without_cidr(self):
        if self._ip_addr_without_cidr is None:
            # Find the subnet
            ip_network = netaddr.IPNetwork(self._ip_address)
            # Without CIDR format
            self._ip_addr_without_cidr = str(ip_network.ip)

        return self._ip_addr_without_cidr

    def get_gateway_ip(self):
        return self._gateway_ip

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return 'Eth if:{0} IP:{1} GW:{2}'.format(self._ethernet_if_id,
                                                 self._ip_address,
                                                 self._gateway_ip)

    def __repr(self):
        return self.__str__()
