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

from neutron_lib.api.definitions import portbindings
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api
import oslo_i18n
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import re

LOG = logging.getLogger(__name__)
RANGE_DEFINITION = re.compile(r'(\d)-(\d)')
_translators = oslo_i18n.TranslatorFactory(domain="fj")
_LI = _translators.log_info
_LW = _translators.log_warning
_LE = _translators.log_error
_LC = _translators.log_critical


def eliminate_val(definition, target):
    """Eliminate specified value from range value.

    @param definition a string of range definition separated with ","
           ex. "1,2,3" or "1-5"
    @param target an integer of the target to eliminate
    @return eliminated a string of eliminated value
    """
    if definition is None:
        return []
    targets = definition.split(',')
    rejected = targets
    val = str(target)
    LOG.info(_LI("Before rejected:%s"), targets)
    for t in targets:
        m = RANGE_DEFINITION.match(t)
        if m:
            low = m.group(1)
            high = m.group(2)
            if val in t:
                rejected.remove(t)
                # matches the lowest one
                if (val == low):
                    # Case: definition is "1-2" and target is "1"
                    if ((int(val) + 1) == int(high)):
                        rejected.append(high)
                    else:
                        rejected.append(str(int(val) + 1) + "-" + high)
                        LOG.info(_LI("Rejected result:%s"), rejected)
                        return ','.join(rejected)
                # matches the highest one
                else:
                    # Ex. definition is "1-2" and target is "2"
                    if ((int(val) - 1) == int(low)):
                        rejected.append(low)
                    else:
                        rejected.append(low + "-" + str(int(val) - 1))
                    LOG.info(_LI("Rejected result:%s"), rejected)
                    return ','.join(rejected)
            # matches between lower one and higher one
            elif (int(low) < int(val) and int(val) < int(high)):
                rejected.remove(t)
                # Ex. definition is "1-n" and target is "2"
                if ((int(val) - 1) == int(low)):
                    rejected.append(low)
                    # Ex. definition is "1-3" and target is "2"
                    if ((int(val) + 1) == int(high)):
                        rejected.append(high)
                    # Ex. definition is "1-4" and target is "2"
                    else:
                        rejected.append(str(int(val) + 1) + "-" + high)
                # Ex. definition is "n-5" and target is "4"(n is NOT "3")
                elif ((int(val) + 1) == int(high)):
                    rejected.append(high)
                    rejected.append(low + "-" + str(int(val) - 1))
                # Ex. definition is "1-5" and target is "3"
                else:
                    rejected.append(low + "-" + str(int(val) - 1))
                    rejected.append(str(int(val) + 1) + "-" + high)
                LOG.info(_LI("Rejected result:%s"), rejected)
                return ','.join(rejected)
        elif val == t:
            rejected.remove(t)
            LOG.info(_LI('Rejected result:%s'), rejected)
            return ','.join(rejected)
    LOG.info(_LI('target for eliminate doesn\'t exist.'))
    return ','.join(rejected)


def get_network_segments(network):
    """Get network_type and segmentation_id from specified network.

    @param network a network object
    @return network_type a string of network type(ex. "vlan" or "vxlan")
            segmentation_id a integer of segmentation_id
    """

    _validate_network(network)
    segment = network.network_segments[0]
    network_type = segment[driver_api.NETWORK_TYPE]
    segmentation_id = segment[driver_api.SEGMENTATION_ID]
    LOG.info(_LI("network_type = %s") % network_type)
    LOG.info(_LI("segmentation_id = %s") % segmentation_id)
    return network_type, segmentation_id


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


def get_physical_connectivity(port):
    """Get local_link_information from specified port.

    @param port a port object
    @return lli a list of following dict
                {"switch_id": "MAC_of_switch", "port_id": "Te:1/0/1",
                 "switch_info": "switch_name"}
    """

    link_infos = []
    binding_profile = port['binding:profile']
    lli = binding_profile.get("local_link_information", {})
    is_all_specified = True if lli else False
    for i in lli:
        if not (i.get('switch_id') and i.get('port_id') and
                i.get('switch_info')):
            is_all_specified = False

        else:
            p = i.get('port_id')
            speed, port = p.split(':')
            speed = _get_long_speed(speed)
            speed_port = (speed, port)
            i['port_id'] = speed_port
            link_infos.append(i)

    if is_all_specified:
        return link_infos
    LOG.error(_LE("Some physical network param is missing:%s"), lli)
    raise ml2_exc.MechanismDriverError(method="get_physical_connectivity")


def is_baremetal_deploy(port):
    """Judge a specified port is for baremetal or not.

    @param port a port object
    @return True/False a boolean baremetal:True, otherwise:False
    """

    vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
    if (vnic_type == portbindings.VNIC_BAREMETAL):
        return True
    else:
        return False


def is_lag(local_link_information):
    """Judge a specified port param is for LAG(linkaggregation) or not.

    @param local_link_information a list of dict
    @return True/False a boolean LAG:True, otherwise:False
    """

    return True if len(local_link_information) > 1 else False


def _validate_network(network):
    """Validate network parameter(network_type and segmentation_id).

    @param a network object
    @return None if both network_type and segmentation_id are included
    """

    segment = network.network_segments[0]
    vlan_id = segment[driver_api.SEGMENTATION_ID]
    if (segment[driver_api.NETWORK_TYPE] == 'vlan' and vlan_id):
        return
    LOG.error(_LE("Fujitsu Mechanism: only network type vlan is supported"))
    raise ml2_exc.MechanismDriverError(method="_validate_network_type")


@log_helpers.log_method_call
def validate_physical_net_params(mech_context):
    """Validate physical network parameters for baremetal deployment.

    Validates network & port params and returns dictionary.
    'local_link_information' is a dictionary from Ironic-port.  This value
    includes as follows:
        'switch_id': A string of switch's MAC address
                     This value is equal to 'chassis_id' from LLDP TLV.
        'port_id': A string of switch interface name.
                     This value is equal to 'port_id' from LLDP TLV.
        'switch_info': A string of switch name.
                     This value is equal to 'system_name' from LLDP TLV.

    @param  mech_context  a Context instance
    @return  A dictionary parameters for baremetal deploy
    """

    port = mech_context.current
    _validate_network(mech_context.network)

    # currently supports only one segment per network
    segment = mech_context.network.network_segments[0]
    vlan_id = segment[driver_api.SEGMENTATION_ID]
    local_link_information = get_physical_connectivity(port)
    return {
        "local_link_information": local_link_information,
        "vlan_id": vlan_id,
        "lag": is_lag(local_link_information)
    }
