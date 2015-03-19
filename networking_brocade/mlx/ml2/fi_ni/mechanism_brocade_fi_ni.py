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


"""Implementation of Brocade ML2 Mechanism driver for ICX and MLX."""

from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api
from oslo_log import log as logging
from oslo_utils import importutils

MECHANISM_VERSION = 0.1
BROCADE_CONFIG = ("networking_brocade.mlx.ml2.fi_ni.brcd_config."
                  "ML2BrocadeConfig")
DRIVER_FACTORY = ("networking_brocade.mlx.ml2.fi_ni."
                  "driver_factory.BrocadeDriverFactory")
LOG = logging.getLogger(__name__)


class BrocadeFiNiMechanism(driver_api.MechanismDriver):

    """
    ML2 Mechanism driver for Brocade ICX and MLX devices. This is the upper
    layer driver class that interfaces to lower layer (SSH/TELNET) below.

    """

    def __init__(self):
        self._driver = None
        self._physical_networks = None
        self._switch = None
        self._driver_map = {}
        self._devices = {}
        self.initialize()

    def initialize(self):
        """Initialize of variables needed by this class."""

        self._devices, self._physical_networks = importutils.import_object(
            BROCADE_CONFIG).create_brocade_dictionary()

    def create_network_precommit(self, mech_context):
        """No-op."""
        pass

    def create_network_postcommit(self, mech_context):
        """Create VLAN on the switch.

        :param:mech_context: Details about the network to be created
        :raise: Exception
        """

        LOG.debug("create_network_postcommit: called")
        network = mech_context.current
        network_id = network['id']
        tenant_id = network['tenant_id']
        segments = mech_context.network_segments
        network_type = segments[0]['network_type']
        vlan_id = segments[0]['segmentation_id']
        physical_network = segments[0]['physical_network']
        if physical_network not in self._physical_networks:
            LOG.exception(_LE("BrocadeFiNiMechanism: Failed to create network."
                              " Network cannot be created in the configured "
                              "physical network %(physnet)s"),
                          {'physnet': physical_network})
            raise ml2_exc.MechanismDriverError(method='create_network_postcomm'
                                               'it')
        if network_type != 'vlan':
            LOG.exception(_LE("BrocadeFiNiMechanism: Failed to create network "
                              "for network type %(nw_type)s. Only network type"
                              " vlan is supported"), {'nw_type': network_type})
            raise ml2_exc.MechanismDriverError(method='create_network_postcomm'
                                               'it')
        try:
            devices = self._physical_networks.get(physical_network)
            for device in devices:
                device_info = self._devices.get(device)
                address = device_info.get('address')
                driver = None
                try:
                    driver = self._get_driver(device)
                except Exception as e:
                    LOG.exception(_LE("BrocadeFiNiMechanism: create_network"
                                      "_postcommit failed while configuring "
                                      "device %(host)s exception=%(error)s"),
                                  {'host': address,
                                   'error': e.args})
                    raise ml2_exc.MechanismDriverError(method='create_network_'
                                                       'postcommit')
                # Proceed only if the driver is not None
                if driver is not None:
                    driver.create_network(
                        vlan_id,
                        device_info.get("ports").split(","))
        except Exception as e:
            LOG.exception(
                _LE("Brocade FI/NI driver: create_network_postcommit failed"
                    "Error = %(error)s"), {'error': e.args})
            raise ml2_exc.MechanismDriverError(method='create_network_postcomm'
                                               'it')
        LOG.info(_LI("BrocadeFiNiMechanism:created_network_postcommit: "
                     "%(network_id)s of network type = %(network_type)s with "
                     "vlan = %(vlan_id)s for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'network_type': network_type,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def delete_network_precommit(self, mech_context):
        """No-op."""
        pass

    def delete_network_postcommit(self, mech_context):
        """Delete network which translates to removing vlan
        from the switch.

        :param:mech_context: Details about the network to be created
        :raise: MechanismDriverError
        """

        LOG.debug("delete_network_postcommit: called")
        network = mech_context.current
        network_id = network['id']
        vlan_id = network['provider:segmentation_id']
        tenant_id = network['tenant_id']
        segments = mech_context.network_segments
        segment = segments[0]
        network_type = segment['network_type']
        physical_network = segment['physical_network']
        if physical_network not in self._physical_networks:
            LOG.exception(_LE("BrocadeFiNiMechanism: Failed to delete network."
                              " Network cannot be deleted in the configured "
                              "physical network %(physnet)s"),
                          {'physnet': physical_network})
            raise ml2_exc.MechanismDriverError(method='delete_network_postcomm'
                                               'it')
        if network_type != 'vlan':
            LOG.exception(_LE("BrocadeFiNiMechanism: Failed to delete network "
                              "for network type %(nw_type)s. Only network type"
                              " vlan is supported"), {'nw_type': network_type})
            raise ml2_exc.MechanismDriverError(method='delete_network_postcomm'
                                               'it')
        try:
            devices = self._physical_networks.get(physical_network)
            for device in devices:
                driver = self._get_driver(device)
                driver.delete_network(vlan_id)
        except Exception:
            LOG.exception(
                _LE("BrocadeFiNiMechanism: failed to delete network"))
            raise ml2_exc.MechanismDriverError(method='delete_network_postcomm'
                                               'it')

        LOG.info(_LI("BrocadeFiNiMechanism: delete network (postcommit): "
                     "%(network_id)s with vlan = %(vlan_id)s for tenant "
                     "%(tenant_id)s"), {'network_id': network_id,
                                        'vlan_id': vlan_id,
                                        'tenant_id': tenant_id})

    def update_network_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def update_network_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def create_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def create_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def delete_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def delete_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def update_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_port_precommit(self: called")

    def update_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_port_postcommit: called")

    def create_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("create_subnetwork_precommit: called")

    def create_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("create_subnetwork_postcommit: called")

    def delete_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("delete_subnetwork_precommit: called")

    def delete_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("delete_subnetwork_postcommit: called")

    def update_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_subnet_precommit(self: called")

    def update_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_subnet_postcommit: called")

    def _get_driver(self, device):
        """
        Gets the driver based on the firmware version of the device

        :param:device: A dictionary which contains details of all the devices
            parsed from the configuration template
        :raise: Exception
        """
        driver = self._driver_map.get(device)
        if driver is None:
            driver_factory = importutils.import_object(DRIVER_FACTORY)
            device_info = self._devices.get(device)
            address = device_info.get('address')
            try:
                driver = driver_factory.get_driver(device_info)
            except Exception as e:
                LOG.exception(_LE("BrocadeFiNiMechanism:_get_driver failed for"
                                  "device %(host)s: Error = %(error)s"),
                              {'host': address,
                               'error': e.args})
                raise Exception(_("BrocadeFiNiMechanism: "
                                  "Failed to get driver"))
            self._driver_map.update({device: driver})
        return driver
