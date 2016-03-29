# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2016 Brocade Networks Inc.
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
from networking_brocade._i18n import _LE
from networking_brocade._i18n import _LW
from networking_brocade.vdx.non_ampp.ml2driver.nos import (
    nctemplates as template)
from networking_brocade.vdx.non_ampp.ml2driver.nos import (
    nosdriver as driver)
from networking_brocade.vdx.non_ampp.ml2driver import utils
from neutron_fwaas.services.firewall.drivers import fwaas_base
import os.path
from oslo_log import log as logging
from oslo_serialization import jsonutils

ACL_BATCH_SIZE = 510
LOG = logging.getLogger(__name__)


class BrocadeFwaasDriver(fwaas_base.FwaasDriverBase):

    def __init__(self):
        LOG.debug("Initializing fwaas Brocade driver")
        self._driver = None
        self._seq_id_low = None
        self._seq_id_high = None
        self.brocade_init()

    def brocade_init(self):
        """Brocade specific initialization."""
        LOG.debug("brocade init BrocadeFwaas Drivers")
        self._switch = utils.get_brocade_credentials()
        self._svi = utils.get_brocade_l3_config()
        self._switch['rbridge_ids'] = self._svi['rbridge_ids']
        self._fwaas = utils.get_brocade_fwaas_config()
        LOG.debug("FWAAS PARAMETERS seq_ids %s direction %s count %s"
                  " log %s", self._fwaas['seq_ids'],
                  self._fwaas['direction'],
                  self._fwaas['count'],
                  self._fwaas['log'])

        if not ((self._fwaas['direction'] == 'both') or
                (self._fwaas['direction'] == 'in') or
                (self._fwaas['direction'] == 'out')):
            LOG.warning(_LW("invalid direction %s intializing"
                        " todirection both"),
                        self._fwaas['direction'])
            self._fwaas['direction'] = 'both'
        self._seq_id_low, self._seq_id_high = utils.get_seq_ids(
            self._fwaas['seq_ids'])
        self.seq_id_bm = utils.SeqIdBitmap(int(self._seq_id_low),
                                           int(self._seq_id_high))
        self._driver = driver.NOSdriver(self._switch['address'],
                                        self._switch['username'],
                                        self._switch['password'])
        self._pre_acls, self._post_acls = self.open_file_if_exists(
            self._fwaas['acl_file'])
        self.req = []
        self._driver.close_session()

    def open_file_if_exists(self, fname):
        pre_acls = []
        post_acls = []
        if os.path.isfile(fname):
            with open(fname, "r") as acl_file:
                try:
                    data = jsonutils.load(acl_file)
                    if 'pre_acls' in data:
                        pre_acls = data['pre_acls']
                    if 'post_acls' in data:
                        post_acls = data['post_acls']
                    LOG.debug("pre acls : %s", pre_acls)
                    LOG.debug("post acls : %s", post_acls)
                except Exception:
                    LOG.warning(_LW("Error Loadng %s file(may be empty file)"),
                                fname)
                    return pre_acls, post_acls
        else:
            LOG.warning(_LW("%s file doesn't exists"), fname)

        return pre_acls, post_acls

    def create_firewall(self, apply_list, firewall):
        LOG.debug('create_firewall (%s)', firewall['id'])
        # update firewall would take lock so no lock here
        return self.update_firewall(apply_list, firewall)

    def update_firewall(self, apply_list, firewall):
        LOG.debug("update_firewall (%s)", firewall['id'])

        if firewall['admin_state_up']:
            return self._update_firewall(apply_list, firewall)
        else:
            return self.apply_default_policy(apply_list, firewall)

    def delete_firewall(self, apply_list, firewall):
        LOG.debug("delete_firewall (%s)", firewall['id'])

        return self.apply_default_policy(apply_list, firewall)

    def apply_default_policy(self, apply_list, firewall):
        LOG.debug("apply_default_policy (%s)", firewall['id'])

        self._clear_policy(apply_list, firewall)
        return True

    def _update_firewall(self, apply_list, firewall):
        LOG.debug("Updating firewall (%s)", firewall['id'])
        self._clear_policy(apply_list, firewall)
        try:
            self._setup_policy(apply_list, firewall)
        except Exception as e:
            LOG.error(_LE("_update_firewall::Error creating ACL policy :"
                        "Error: %s"), e)
            raise e
        return True

    def _apply_policy_on_interface(self, policy_name, svi):
        LOG.debug("brocade_fwaas:_setup_policy svi %s", svi)
        if(self._fwaas['direction'] == 'both' or
           self._fwaas['direction'] == 'in'):
            for rbridge_id in self._switch['rbridge_ids']:
                self._driver.configure_policy_on_interface(rbridge_id,
                                                           svi,
                                                           policy_name,
                                                           "in")
        if(self._fwaas['direction'] == 'both' or
           self._fwaas['direction'] == 'out'):
            for rbridge_id in self._switch['rbridge_ids']:
                self._driver.configure_policy_on_interface(rbridge_id,
                                                           svi,
                                                           policy_name,
                                                           "out")

    def _is_policy_exists(self, policy_name):
        return self._driver.is_ip_acl_exists(policy_name)

    def merge_and_replay_acls(self, name):
        if self.req:
            all_rules = "".join(self.req)
            acl_header = template.IP_ACL_RULE_BULKING_START.format(name=name)
            acl_footer = template.IP_ACL_RULE_BULKING_END.format()
            acl_netconf = acl_header + all_rules + acl_footer
            LOG.debug("merge_and_replay_acls netconf %s", acl_netconf)
            self._driver.create_acl_rule(acl_netconf)
            del self.req[:]

    def _config_replay_acls(self, policy_name, rule, seq_id):
        try:
            req = self._make_policy(policy_name, rule, seq_id)
            self.req.append(req)
            if len(self.req) >= ACL_BATCH_SIZE:
                self.merge_and_replay_acls(policy_name)
        except Exception as e:
            LOG.error(_LE("error creating rule %s"), e)
            raise e
        return

    def _config_replay_acls_file(self, policy_name, acl_file, seq_ids, index):
        for rule in acl_file:
            rule = rule['acl']
            try:
                self._config_replay_acls(
                    policy_name, rule, str(seq_ids[index]))
            except Exception as e:
                LOG.error(_LE("error _config_replay_acls_file %s"), e)
                raise e
            index = index + 1
        return index

    def _setup_policy(self, apply_list, fw):
        # create zones no matter if they exist. Interfaces are added by router
        policy_name = utils.get_firewall_object_prefix(fw)
        num_seq_id = len(fw['firewall_rule_list']) + len(self._pre_acls) +\
            len(self._post_acls)
        seq_ids = self.seq_id_bm.get_seq_ids(policy_name, num_seq_id)
        index = 0
        try:
            if not self._driver.is_ip_acl_exists(policy_name):
                index = self._config_replay_acls_file(policy_name,
                                                      self._pre_acls,
                                                      seq_ids, index)
                for rule in fw['firewall_rule_list']:
                    if not rule['enabled']:
                        continue
                    if rule['ip_version'] == 4:
                        self._config_replay_acls(policy_name, rule,
                                                 str(seq_ids[index]))
                        index = index + 1
                    else:
                        LOG.warning(_LW("Unsupported IP version rule."))
                index = self._config_replay_acls_file(policy_name,
                                                      self._post_acls,
                                                      seq_ids, index)
                self.merge_and_replay_acls(policy_name)

            for ri in apply_list:
                for svi in ri.router['svis']:
                    self._apply_policy_on_interface(policy_name, svi)
        except Exception as e:
            LOG.error(_LE("Error creating ACL policy :Error: %s"), e)
            self._clear_policy(apply_list, fw)
            raise e

    def _clear_policy(self, apply_list, fw):
        policy = utils.get_firewall_object_prefix(fw)
        for ri in apply_list:
            for svi in ri.router['svis']:
                LOG.debug("brocade_fwaas:_clear_policy svi %s", svi)
                if(self._fwaas['direction'] == 'both' or
                   self._fwaas['direction'] == 'in'):
                    for rbridge_id in self._switch['rbridge_ids']:
                        self._driver.remove_policy_on_interface(rbridge_id,
                                                                svi,
                                                                policy,
                                                                "in")
                if(self._fwaas['direction'] == 'both' or
                   self._fwaas['direction'] == 'out'):
                    for rbridge_id in self._switch['rbridge_ids']:
                        self._driver.remove_policy_on_interface(rbridge_id,
                                                                svi,
                                                                policy,
                                                                "out")

        for rbridge_id in self._switch['rbridge_ids']:
            self._driver.delete_policy(rbridge_id, policy)

    def _make_policy(self, name, rule, seq_id):
        src_ip = 'any'
        dst_ip = 'any'
        src_mask = ''
        dst_mask = ''
        sport_operator = None
        sport_low = None
        sport_high = None
        dport_operator = None
        dport_low = None
        dport_high = None
        dscp = None
        if rule.get('action') == 'allow':
            action = 'permit'
        else:
            action = 'deny'

        protocol = rule.get('protocol')
        if((protocol == 'any') or (protocol is None)):
            protocol = 'ip'
        if ((protocol == 'tcp') or (protocol == 'udp')):
            if 'source_port' in rule:
                sport = rule['source_port']
                sport_low, sport_high = utils.get_ports(sport)
                sport_operator = utils.get_port_operator(sport_low, sport_high)
            if 'destination_port' in rule:
                dport = rule['destination_port']
                dport_low, dport_high = utils.get_ports(dport)
                dport_operator = utils.get_port_operator(dport_low,
                                                         dport_high)

        src_address = rule.get('source_ip_address') or 'any'
        if src_address != 'any':
            src_ip, src_mask = utils.cidr_2_nwm(src_address)
        dst_address = rule.get('destination_ip_address') or 'any'
        if dst_address != 'any':
            dst_ip, dst_mask = utils.cidr_2_nwm(dst_address)

        if 'dscp' in rule:
            dscp = str(rule.get('dscp'))
        try:
            xml_request = utils.make_rule(
                name, seq_id, action, protocol, src_ip,
                src_mask, dst_ip, dst_mask, sport_operator, sport_low,
                sport_high, dport_operator, dport_low, dport_high,
                self._fwaas['count'], self._fwaas['log'], dscp)
        except Exception as e:
            LOG.error(_LE("error _make_policy %s"), e)
            raise e

        LOG.debug("xml request %s", xml_request)

        return xml_request
