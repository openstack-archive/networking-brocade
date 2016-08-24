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
from lxml import etree
from networking_brocade.vdx.non_ampp.ml2driver.nos import(
    nctemplates as template)
from neutron.i18n import _
from neutron.i18n import _LE
from neutron.i18n import _LI
from oslo_config import cfg
from oslo_log import log as logging
from six import moves
import sys
# we will not use this for now
wellknown_dscp = {'af11': 11, 'af12': 12, 'af13': 14,
                  'af21': 18, 'af22': 20, 'af23': 22,
                  'af31': 26, 'af32': 28, 'af33': 30,
                  'af41': 38, 'af42': 36, 'af43': 38,
                  'cs1': 8, 'cs2': 16, 'cs3': 24,
                  'cs4': 32, 'cs5': 40, 'cs6': 48,
                  'cs7': 56, 'default': 0, 'ef': 46}

LOG = logging.getLogger(__name__)
OBJ_PREFIX_LEN = 8

DEFAULT_TOPOLOGY = []
DEFAULT_MTU = []
DEFAULT_NATIVE_VLAN = []
DEFAULT_RBRIDGE_RANGE = []
ML2_BROCADE = [cfg.StrOpt('address', default='',
                          help=_('The address of the host to SSH to')),
               cfg.StrOpt('username', default='admin',
                          help=_('The SSH username to use')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=_('The SSH password to use')),
               cfg.StrOpt('physical_networks', default='',
                          help=_('Allowed physical networks')),
               cfg.BoolOpt('initialize_vcs', default='True',
                           help=_('initialize vcs')),
               cfg.StrOpt('ostype', default='NOS',
                          help=_('OS Type of the switch')),
               # cfg.StrOpt('osversion', default='autodetect',
               #    help=_('OS Version number')),
               cfg.IntOpt('nretries', default=5,
                          help=_(
                              'Number of retries when retieable'
                              'exception occurs')),
               cfg.IntOpt('ndelay', default=10,
                          help=_('Number of seconds to sleep')),
               cfg.IntOpt('nbackoff', default=2,
                          help=_('backoff interval')),
               cfg.BoolOpt('fqdn', default=False,
                           help=_(
                               'Fully qualified Domain names will be used')),
               cfg.BoolOpt('lacp_enabled', default=False,
                           help=_('lacp enabled')),
               cfg.BoolOpt('remove_ch_grp', default=False,
                           help=_(
                               'initialization stage remove channel group')),
               cfg.StrOpt('port_channels', default='1024:1152',
                          help=_('Allowed port channel number for openstack')),
               cfg.StrOpt('po_speed', default='10000',
                          help=_('port channel speed')),
               cfg.StrOpt('port_channel_mode', default='on',
                          help=_('port-channel mode')),
               cfg.StrOpt('port_channel_type', default='type',
                          help=_('port-channel type')),
               cfg.StrOpt('port_channel_lb_mode',
                          default='src-dst-ip-mac-vid-port',
                          help=_('port-channel LB mode')),
               ]

TOPOLOGY_OPTS = [cfg.ListOpt('connections', default=DEFAULT_TOPOLOGY,
                             help=_('topology info <compute-hostname>:'
                                    '<physical_network>:'
                                    '<interface_speed>:<port>')),
                 cfg.ListOpt('bond_mappings', default=DEFAULT_TOPOLOGY,
                             help=_('bond mapping to port-channel'
                                    '<compute-hostname>:<physical_network>:'
                                    '<port-channel-num>')),
                 cfg.ListOpt('mtu', default=DEFAULT_MTU,
                             help=_('MTU options to interface'
                                    '<interface_speed>:<port>:<mtu>')),
                 cfg.ListOpt('native_vlans', default=DEFAULT_NATIVE_VLAN,
                             help=_('native for interface'
                                    '<interface_speed>:<port>:<native-vlan>'))
                 ]

RBRIDGE_OPTS = [cfg.ListOpt('rbridge_ids', default=DEFAULT_RBRIDGE_RANGE,
                            help=_('rbridges range 1,2,3')),
                cfg.StrOpt('redundancy', default='disabled',
                           help=_('enable/disable L3 redundancy')),
                cfg.BoolOpt('is_vrf_required', default=True,
                            help=_('VRFs will be created if True')),
                cfg.StrOpt('vrrp_version', default='2',
                           help=_('vrrp version to be used')),
                cfg.StrOpt('vrrp_group_id', default='100',
                           help=_('vrrp group to be used')),
                cfg.IntOpt('vrrp_advertisement_interval', default=1,
                           help=_('vrrp advertisement interval'))
                ]

FWAAS = [cfg.StrOpt('seq_ids', default='1:50000',
                    help=_('seq ids to be used in acl rule')),
         cfg.StrOpt('direction', default='both',
                    help=_('direction for acl to be applied')),
         cfg.BoolOpt('count', default=False,
                     help=_('count the number of times acls are hit')),
         cfg.BoolOpt('log', default=False,
                     help=_('count the number of times acls are hit')),
         cfg.StrOpt('acl_file', default='/etc/neutron/acl.json',
                    help=_('pre acls and post acls on svi'))
         ]


def register_brocade_credentials():
    cfg.CONF.register_opts(ML2_BROCADE, "ml2_brocade")


def reigister_brocade_topology():
    cfg.CONF.register_opts(TOPOLOGY_OPTS, "TOPOLOGY")


def register_brocade_l3_config():
    cfg.CONF.register_opts(RBRIDGE_OPTS, "svi")


def register_brocade_fwaas_config():
    cfg.CONF.register_opts(FWAAS, "fwaas")


def get_brocade_fwaas_config():
    register_brocade_fwaas_config()
    fwaas = {'seq_ids': cfg.CONF.fwaas.seq_ids,
             'direction': cfg.CONF.fwaas.direction,
             'count': cfg.CONF.fwaas.count,
             'log': cfg.CONF.fwaas.log,
             'acl_file': cfg.CONF.fwaas.acl_file
             }
    return fwaas


def get_acl_files():
    fwaas = get_brocade_fwaas_config()
    return fwaas['acl_file']


def get_brocade_credentials():
    register_brocade_credentials()
    switch = {'address': cfg.CONF.ml2_brocade.address,
              'username': cfg.CONF.ml2_brocade.username,
              'password': cfg.CONF.ml2_brocade.password,
              'os': cfg.CONF.ml2_brocade.ostype,
              'osversion': '5.0.0'}
    return switch


def get_lacp_args():
    register_brocade_credentials()
    po = cfg.CONF.ml2_brocade.port_channels
    po_lo, po_hi = po.split(':')
    lacp = {'lacp_enabled': cfg.CONF.ml2_brocade.lacp_enabled,
            'po_lo': po_lo,
            'po_hi': po_hi,
            'po_mode': cfg.CONF.ml2_brocade.port_channel_mode,
            'po_type': cfg.CONF.ml2_brocade.port_channel_type,
            'po_lb_mode': cfg.CONF.ml2_brocade.port_channel_lb_mode,
            'po_speed': cfg.CONF.ml2_brocade.po_speed,
            'remove_ch_grp': cfg.CONF.ml2_brocade.remove_ch_grp}
    return lacp


def _is_lacp_enabled():
    return get_lacp_args()['lacp_enabled']


def get_port_channel_lo_hi():
    lacp = get_lacp_args()
    return int(lacp['po_lo']), int(lacp['po_hi'])


def is_fqdn_supported():
    register_brocade_credentials()
    return cfg.CONF.ml2_brocade.fqdn


def get_vcs_initialize():
    register_brocade_credentials()
    return cfg.CONF.ml2_brocade.initialize_vcs


def get_retry_args():
    register_brocade_credentials()
    return cfg.CONF.ml2_brocade.nretries,\
        cfg.CONF.ml2_brocade.ndelay,\
        cfg.CONF.ml2_brocade.nbackoff


def get_physical_networks():
    register_brocade_credentials()
    return cfg.CONF.ml2_brocade.physical_networks


def get_brocade_l3_config():
    register_brocade_l3_config()
    svi = {'rbridge_ids': cfg.CONF.svi.rbridge_ids,
           'redundancy': True if ((cfg.CONF.svi.redundancy == 'enabled') and
                                  (len(cfg.CONF.svi.rbridge_ids) > 1))
           else False,
           'vrrp_version': cfg.CONF.svi.vrrp_version,
           'vrrp_group_id': cfg.CONF.svi.vrrp_group_id,
           'vrrp_advertisement_interval':
           cfg.CONF.svi.vrrp_advertisement_interval,
           'is_vrf_required': cfg.CONF.svi.is_vrf_required
           }

    if not svi['redundancy'] and len(svi['rbridge_ids']) > 1:
        # redundancy disabled consider only first rbride configured
        del svi['rbridge_ids'][1:]
    LOG.info(_LI("rbridge_ids %(rbridge_ids)s"
                 " redundancy %(redundancy)s"
                 " vrrp_version %(vrrp_version)s"
                 " vrrp_group_id %(vrrp_group_id)s") %
             {'rbridge_ids': svi['rbridge_ids'],
              'redundancy': svi['redundancy'],
              'vrrp_version': svi['vrrp_version'],
              'vrrp_group_id': svi['vrrp_group_id']})

    return svi


def is_vrf_required():
    register_brocade_l3_config()
    return cfg.CONF.svi.is_vrf_required


def remove_from_xml_tree(the_config, tag):
    """removed unused xml tag"""
    for elt in the_config.iterdescendants():
        if tag in elt.tag:
            elt.getparent().remove(elt)


def add_text_to_ele(elt, text):
    """add text to xml tag"""
    elt.text = text


def remove_unused_tags(the_config, name, action, protocol, src_ip, dst_ip,
                       sport_operator, src_port, dport_operator, dst_port,
                       count, log, dscp):
    """This function removes unused xml tags gor the given paramaters"""
    if not dscp or dscp == '':
        remove_from_xml_tree(the_config, 'dscp')
# handle count and log tags
    if not count:
        remove_from_xml_tree(the_config, 'count')

    if not log:
        remove_from_xml_tree(the_config, 'log')
# handle ip tags
    if src_ip == 'any':
        remove_from_xml_tree(the_config, 'src-mask')

    if dst_ip == 'any':
        remove_from_xml_tree(the_config, 'dst-mask')

# handle protocol tags
    if protocol == 'tcp':
        remove_from_xml_tree(the_config, 'udp')
    elif protocol == 'udp':
        remove_from_xml_tree(the_config, 'tcp')

    if ((src_port == '') & (dst_port == '')):
        remove_from_xml_tree(the_config, 'port')
    elif (src_port == ''):
        remove_from_xml_tree(the_config, 'sport')
    elif (dst_port == ''):
        remove_from_xml_tree(the_config, 'dport')

    if (sport_operator == 'range'):
        remove_from_xml_tree(the_config, 'sport-number-eq-neq')
    elif (sport_operator == 'eq'):
        remove_from_xml_tree(the_config, 'sport-number-range')
    else:
        remove_from_xml_tree(the_config, 'sport')

    if (dport_operator == 'range'):
        remove_from_xml_tree(the_config, 'dport-number-eq-neq')
    elif (dport_operator == 'eq'):
        remove_from_xml_tree(the_config, 'dport-number-range')
    else:
        remove_from_xml_tree(the_config, 'dport')


class SeqIdBitmap(object):

    """This class manages generating sequence ids for ip acls"""

    def __init__(self, min_search_seqid, max_search_seqid):
        self._min_search_seqid = min_search_seqid
        self._max_search_seqid = max_search_seqid

    def get_seq_ids(self, acl, howmany):
        """Try to get a specific vlan if requested or get the next vlan."""
        ids = []
        it = 0
        for seq_id in moves.range(self._min_search_seqid,
                                  self._max_search_seqid):
            ids.append(seq_id)
            it += 1
            if(it >= howmany):
                break
        return ids


def get_firewall_object_prefix(fw):
    """Get Acl policy name using firewal id and tenant_id"""
    policy_name = template.ROUTER_OBJ_PREFIX +\
        fw['tenant_id'][:OBJ_PREFIX_LEN] +\
        fw['id'][:OBJ_PREFIX_LEN]
    return policy_name


def make_rule(name, seq_id, action, protocol, src_ip, src_mask, dst_ip,
              dst_mask, sport_operator, sport_low, sport_high,
              dport_operator, dport_low, dport_high, count, log, dscp):
    """create xml template to create acl rule on VDX"""
    xml_tring = template.IP_ACL_RULE.format()
    the_config = etree.fromstring(xml_tring)
    remove_unused_tags(the_config, name, action, protocol, src_ip, dst_ip,
                       sport_operator, (sport_low, sport_high), dport_operator,
                       (dport_low, dport_high), count, log, dscp)

    for elt in the_config.iterdescendants():
        if elt.tag == ('seq-id'):
            add_text_to_ele(elt, seq_id)
        elif elt.tag == ('action'):
            add_text_to_ele(elt, action)
        elif elt.tag == ('protocol-type'):
            add_text_to_ele(elt, protocol)
        elif elt.tag == ('src-host-any-sip'):
            add_text_to_ele(elt, src_ip)
        elif elt.tag == ('src-mask'):
            add_text_to_ele(elt, src_mask)
        elif elt.tag == ('dst-host-any-dip'):
            add_text_to_ele(elt, dst_ip)
        elif elt.tag == ('dst-mask'):
            add_text_to_ele(elt, dst_mask)
        elif elt.tag == ('sport'):
            add_text_to_ele(elt, sport_operator)
        elif "sport-number-eq-neq" in elt.tag:
            add_text_to_ele(elt, sport_low)
        elif "sport-number-range-lower" in elt.tag:
            add_text_to_ele(elt, sport_low)
        elif "sport-number-range-higher" in elt.tag:
            add_text_to_ele(elt, sport_high)
        elif elt.tag == ('dport'):
            add_text_to_ele(elt, dport_operator)
        elif "dport-number-eq-neq" in elt.tag:
            add_text_to_ele(elt, dport_low)
        elif "dport-number-range-lower" in elt.tag:
            add_text_to_ele(elt, dport_low)
        elif "dport-number-range-higher" in elt.tag:
            add_text_to_ele(elt, dport_high)
        elif "dscp" in elt.tag:
            add_text_to_ele(elt, dscp)

    xml_request = etree.tostring(the_config, pretty_print=True)
    return xml_request


def len_to_wild_mask(len):
    """Convert a bit length to a dotted netmask (aka. CIDR to netmask)"""
    mask = ''
    if not isinstance(len, int) or len < 0 or len > 32:
        return None

    for t in range(4):
        if len > 7:
            mask += '0.'
        else:
            dec = ((255 - (2 ** (8 - len) - 1)) ^ 255)
            mask += str(dec) + '.'
        len -= 8
        if len < 0:
            len = 0

    return mask[:-1]


def cidr_2_nwm(addr):
    """Get network address prefix and wild mask from a given address."""
    if addr is None:
        return (None, None)
    nw_addr, nw_len = addr.split('/')
    nw_len = len_to_wild_mask(int(nw_len))
    return nw_addr, nw_len


def get_seq_ids(seq_ids):
    if seq_ids:
        if ':' in seq_ids:
            seq_id_low, seq_id_high = seq_ids.split(':')
            return seq_id_low, seq_id_high
    return None, None


def get_ports(port):
    port_low = ''
    port_high = ''
    if ((port is None) | (port == '')):
        return (port_low, port_high)
    if ':' in port:
        port_low, port_high = port.split(':')
    else:
        port_low, port_high = port, port_high
    return port_low, port_high


def get_port_operator(port_low, port_high):
    """detect if user has entered single port or range of ports"""

    if ((port_low) and (port_high)):
        return "range"
    elif((port_low) or (port_high)):
        return "eq"
    else:
        return None


def _parse_info_entry(info):
    """parses string <speed>:<port>:info"""
    entry = info.strip()
    if ':' in entry:
        try:
            speed, port, info = entry.split(':')
            speed = _get_long_speed(speed)
            speed_port = (speed, port)
            return speed_port, info
        except Exception:
            raise Exception("Brocade Plugin raised exception parsing port info"
                            "Failed")
    return entry, None


def _parse_connection_entry(connection):
    """parses string <host-name>:<physical-network>:<speed>:<port>"""
    entry = connection.strip()
    if ':' in entry:
        try:
            host, network, speed, port = entry.split(':')
            speed = _get_long_speed(speed)
            speed_port = (speed, port)
            return (host, network), speed_port
        except Exception:
            raise Exception("Brocade Plugin raised exception parsing topology"
                            "Failed")
    return entry, None


def _parse_connection_info():
    """parses connection info"""
    reigister_brocade_topology()
    connections_info = cfg.CONF.TOPOLOGY.connections
    mtu_info = cfg.CONF.TOPOLOGY.mtu
    native_vlan_info = cfg.CONF.TOPOLOGY.native_vlans
    device_dict = {}
    bond_mappings = {}
    mtu_dict = {}
    native_vlans_dict = {}
    for entry in connections_info:
        host_physnet, speed_port = _parse_connection_entry(entry)
        device_dict.setdefault(host_physnet, []).append(speed_port)

    for entry in native_vlan_info:
        try:
            speed_port, native_vlan = _parse_info_entry(entry)
            native_vlans_dict[speed_port] = native_vlan
        except Exception:
            raise Exception("parsing native vlan Failed")

    for entry in mtu_info:
        try:
            speed_port, mtu = _parse_info_entry(entry)
            mtu_dict[speed_port] = mtu
        except Exception:
            raise Exception("parsing MTU Failed")

    if _is_lacp_enabled():
        bond_info = cfg.CONF.TOPOLOGY.bond_mappings
        for entry in bond_info:
            entry = entry.strip()
            if ':' in entry:
                try:
                    host, network, port_channel = entry.split(':')
                    bond_mappings.setdefault((host, network), []).append(
                        port_channel)
                except Exception:
                    raise Exception("parsing bond to portchannel"
                                    " mapping failed")
    return device_dict, bond_mappings, mtu_dict, native_vlans_dict


def _aggregate_nics_to_support_lacp(topology, bond_info):
    device_dict = {}
    lacp_ports = {}
    if not bond_info:
        po_lo, po_hi = get_port_channel_lo_hi()
    for host_physnet in topology.keys():
        if len(topology[host_physnet]) >= 1:
            for item in topology[host_physnet]:
                if ((not bond_info) and (po_hi >= po_lo)):
                    lacp_ports.setdefault(po_lo, []).append(item)
                    LOG.debug("po lo %d po_hi %d", po_lo, po_hi)
                elif bond_info:
                    # only one port-channel
                    po_lo = bond_info[host_physnet][0]
                    lacp_ports.setdefault(po_lo, []).append(item)
                else:
                    LOG.error(_LE("exhausted all port-channels increase"
                                  "port-channel range or bond mappings"
                                  " not provided"))
                    sys.exit(0)

            device_dict.setdefault(host_physnet, []).append(("port-channel",
                                                             str(po_lo)))
            if not bond_info:
                po_lo = po_lo + 1
    LOG.debug("device_dict %s lacp_ports %s", device_dict, lacp_ports)
    return device_dict, lacp_ports


def _get_interface_speed_name(topology, physical_network):
    """given a physical network return interface speed and name"""
    interfaces = []
    for key in topology.keys():
        host, network = key
        if network == physical_network:
            interfaces.append(topology[key])
    return interfaces


def _is_valid_three_tupple(interface):
    """verify if given interface is threee tupple"""
    if '/' in interface:
        s = interface.split('/')
        # Length is checked against three because of rbridge,slot,port
        if len(s) != 3:
            LOG.error(_LE("_is_valid_three_tupple:"
                          "invalid interface %s configure"
                          "valid interface"), interface)
            return False
        return True
    return False


def _get_long_speed(short_speed):
    if 'Te' in short_speed:
        return "tengigabitethernet"

    elif 'Gi' in short_speed:
        return "gigabitethernet"

    elif 'Fo' in short_speed:
        return "fortyGigabitEthernet"

    elif 'Hu' in short_speed:
        return "hundredGigabitEthernet"
    else:
        return "unknown"


def _is_valid_interface_speed(speed):
    """Check if given speed is valid"""
    if 'ten' in speed:
        speed = "tengigabitethernet"
        return True
    elif 'gig' in speed:
        speed = "gigabitEthernet"
        return True
    elif 'for' in speed:
        speed = "fortyGigabitEthernet"
        return True
    elif 'hun' in speed:
        speed = "hundredGigabitEthernet"
        return True
    else:
        LOG.error(_LE("_is_valid_interface_speed:invalid speed parameter %s"
                      " configure valid speed"), speed)
        return False


def _get_interface_speed_and_name(interface_full_name):
    """Converts full name to speed and name"""
    entry = interface_full_name.strip()
    if ':' in entry:
        try:
            speed, name = entry.split(':')
            speed = _get_long_speed(speed)
            return speed, name
        except Exception as e:
            raise e
    return interface_full_name, None


def _is_valid_nos_interface(speed, interface):
    """validate interface name to be three tupple"""
    if not _is_valid_three_tupple(interface):
        return False
    if not _is_valid_interface_speed(speed):
        return False
    return True


def _is_valid_interface(device, switch, nos_driver):
    """validate if given interfaces are valid"""
    for key in device.keys():
        for (speed, interface) in device[key]:
            if not _is_valid_nos_interface(speed, interface):
                return False
    return True
