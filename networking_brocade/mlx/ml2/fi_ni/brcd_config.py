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
                          help=('The IP address of the MLX or ICX switch')),
               cfg.StrOpt('username', default='admin',
                          help=('The SSH username of the switch')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=('The SSH password of the switch')),
               cfg.StrOpt('physical_networks', default='',
                          help=('Allowed physical networks where VLAN can '
                                'be configured on this switch')),
               cfg.StrOpt('ports', default='',
                          help=('Ports to be tagged in the VLAN being '
                                'configured on the switch')),
               cfg.StrOpt('transport', default='SSH',
                          choices=('SSH', 'TELNET'),
                          help=('Protocol used to communicate with switch')),
               cfg.StrOpt('ostype', default='NI', choices=('NI', 'FI'),
                          help=('OS type of the device.  NI is NetIron '
                                'for MLX switches. FI is FastIron for '
                                'ICX switches.')),
               cfg.StrOpt('enable_username', default='admin',
                          help=('The username for enable config prompt')),
               cfg.StrOpt('enable_password', default='password', secret=True,
                          help=('The password for enable config prompt')),
               ]
L3_BROCADE = [cfg.StrOpt('address', default='',
                         help=('The IP address of the MLX switch')),
              cfg.StrOpt('username', default='admin',
                         help=('The SSH username of the switch')),
              cfg.StrOpt('password', default='password', secret=True,
                         help=('The SSH password of the switch')),
              cfg.StrOpt('physical_networks', default='',
                         help=('Allowed physical networks where VLAN can '
                               'be configured on this switch')),
              cfg.StrOpt('ports', default='',
                         help=('Ports to be tagged in the VLAN being '
                               'configured on the switch')),
              cfg.StrOpt('enable_username', default='admin',
                         help=('The username for enable config prompt')),
              cfg.StrOpt('enable_password', default='password', secret=True,
                         help=('The password for enable config prompt')),
              ]
cfg.CONF.register_opts(SWITCHES, 'ml2_brocade_fi_ni')
cfg.CONF.register_opts(ML2_BROCADE, 'ML2_BROCADE_MLX_EXAMPLE')
cfg.CONF.register_opts(L3_BROCADE, 'L3_BROCADE_MLX_EXAMPLE')


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
            self._brocade_switches = (cfg.CONF.l3_brocade_mlx.
                                      switch_names)
        switches = self._brocade_switches.split(',')
        for switch in switches:
            switch_info = {}
            switch = switch.strip()
            if isL2:
                cfg.CONF.register_opts(ML2_BROCADE, switch)
            else:
                cfg.CONF.register_opts(L3_BROCADE, switch)
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
            if not isL2:
                switch_info.update({'transport': 'SSH'})
                switch_info.update({'ostype': 'NI'})
            self._brocade_dict.update({switch: switch_info})
        return self._brocade_dict, self._physnet_dict
