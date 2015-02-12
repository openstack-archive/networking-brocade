# Copyright 2015 Brocade Communications Systems, Inc.
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

"""
Parses the brocade ethernet configuration template
"""

from oslo_config import cfg

SWITCHES = [
    cfg.StrOpt(
        'switch_names',
        default='',
        help=('Switches connected to the compute nodes'))]

ML2_BROCADE = [cfg.StrOpt('address', default='',
                          help=('The address of the host to SSH to')),
               cfg.StrOpt('username', default='admin',
                          help=('The SSH username to use')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=('The SSH password to use')),
               cfg.StrOpt('physical_networks', default='',
                          help=('Allowed physical networks')),
               cfg.StrOpt('ports', default='',
                          help=('Ports')),
               cfg.StrOpt('transport', default='SSH',
                          help=('Protocol used to communicate with Switch')),
               cfg.StrOpt('ostype', default=None,
                          help=('OS type of the device. NI or FI')),
               ]


class ML2BrocadeConfig(object):

    """
    Parse the configuration template for Brocade Ethernet ML2 plugin
    """

    def __init__(self):
        self._brocade_switches = None
        self._brocade_dict = {}
        self._physnet_dict = {}

    def create_brocade_dictionary(self, isL2=True):
        """
        Create the brocade dictionary.
        Read data from the ml2_conf_brocade.ini.

        :returns: Two dictionaries, one contains device details with device
            name as key and the details as value. Second dictionary contains
            physical_network as key and list of device names as value
        :param:isL2: Boolean value based on the router type L2 or L3
        """
        if isL2:
            cfg.CONF.register_opts(SWITCHES, 'ml2_brocade_fi_ni')
            self._brocade_switches = (cfg.CONF.ml2_brocade_fi_ni.
                                      switch_names)
        else:
            cfg.CONF.register_opts(SWITCHES, 'l3_brocade_fi_ni')
            self._brocade_switches = (cfg.CONF.l3_brocade_fi_ni.
                                      switch_names)
        switches = self._brocade_switches.split(',')
        for switch in switches:
            switch_info = {}
            switch = switch.strip()
            cfg.CONF.register_opts(ML2_BROCADE, switch)
            for key, value in cfg.CONF._get(switch).items():
                value = value.strip()
                switch_info.update({key: value})
                if "physical_networks" in key:
                    switch_names = self._physnet_dict.get(value)
                    if switch_names is None:
                        switch_names = []
                        switch_names.append(switch)
                    else:
                        switch_names.append(switch)

                    self._physnet_dict.update({value: switch_names})

            self._brocade_dict.update({switch: switch_info})
        return self._brocade_dict, self._physnet_dict
