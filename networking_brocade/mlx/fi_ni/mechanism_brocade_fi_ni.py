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


"""Implementation of Brocade ML2 Mechanism driver for ICX and MLX."""

from oslo_utils import importutils

from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers.brocade.db import models as brocade_db

MECHANISM_VERSION = 0.1
BROCADE_CONFIG = "neutron.plugins.ml2.drivers.brocade.fi_ni.brcd_config."
    ("ML2BrocadeConfig")
DRIVER_FACTORY = "neutron.plugins.ml2.drivers.brocade.fi_ni."
    ("driver_factory.BrocadeDriverFactory")
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
            BROCADE_CONFIG).create_ml2_brocade_dictionary()

    def create_network_precommit(self, mech_context):
        """Create Network in the mechanism specific database table."""

        network = mech_context.current
        context = mech_context._plugin_context
        tenant_id = network['tenant_id']
        network_id = network['id']

        segments = mech_context.network_segments
        # currently supports only one segment per network
        segment = segments[0]

        network_type = segment['network_type']
        vlan_id = segment['segmentation_id']
        segment_id = segment['id']

        if segment['physical_network'] not in self._physical_networks:
            raise Exception(
                _("Brocade Mechanism: failed to create network, "
                  "network cannot be created in the configured "
                  "physical network"))

        if network_type != 'vlan':
            raise Exception(
                _("Brocade Mechanism: failed to create network, "
                  "only network type vlan is supported"))
        try:
            brocade_db.create_network(context, network_id, vlan_id,
                                      segment_id, network_type, tenant_id)
        except Exception:
            LOG.exception(
                _LE("Brocade FI/NI Mechanism:"
                  " failed to create network in db"))
            raise Exception(
                _("Brocade FI/NI Mechanism: "
                  "create_network_precommit failed"))
        LOG.info(_LI("create network (precommit): %(network_id)s "
                   "of network type = %(network_type)s "
                   "with vlan = %(vlan_id)s "
                   "for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'network_type': network_type,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def create_network_postcommit(self, mech_context):
        """Create VLAN on the switch."""

        LOG.debug("create_network_postcommit: called")
        network = mech_context.current
        # use network_id to get the network attributes
        # ONLY depend on our db for getting back network attributes
        # this is so we can replay postcommit from db
        context = mech_context._plugin_context

        network_id = network['id']
        network = brocade_db.get_network(context, network_id)
        network_type = network['network_type']
        tenant_id = network['tenant_id']
        vlan_id = network['vlan']
        segments = mech_context.network_segments
        segment = segments[0]
        physical_network = segment['physical_network']
        try:
            devices = self._physical_networks.get(physical_network)
            for device in devices:
                device_info = self._devices.get(device)
                driver = None
                try:
                    driver = self._get_driver(device)
                except Exception as e:
                    LOG.exception(_LE("Unsupported device=%(device)s "
                                      "exception=%(error)s"),
                                  {'device': device_info.get('address'),
                                   'error': e.args})
                    raise Exception(_("Brocade FI/NI Mechanism:"
                                      " create_network_postcommmit failed"
                                      "Unsupported Device"))
                # Proceed only if the driver is not None
                if driver is not None:
                    driver.create_network(
                        vlan_id,
                        device_info.get("ports").split(","))
        except Exception:
            LOG.exception(
                _LE("Brocade FI/NI driver: failed in create network"))
            brocade_db.delete_network(context, network_id)
            raise Exception(
                _("Brocade FI/NI Mechanism:"
                  " create_network_postcommmit failed"))
        LOG.info(_LI("created network (postcommit): %(network_id)s"
                   " of network type = %(network_type)s"
                   " with vlan = %(vlan_id)s"
                   " for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'network_type': network_type,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""

        LOG.debug("delete_network_precommit: called")

        network = mech_context.current
        network_id = network['id']
        vlan_id = network['provider:segmentation_id']
        tenant_id = network['tenant_id']

        context = mech_context._plugin_context

        try:
            brocade_db.delete_network(context, network_id)
        except Exception:
            LOG.exception(
                _LE("Brocade FI/NI Mechanism:"
                  " failed to delete network in db"))
            raise Exception(
                _("Brocade FI/NI Mechanism:"
                  " delete_network_precommit failed"))

        LOG.info(_LI("delete network (precommit): %(network_id)s"
                   " with vlan = %(vlan_id)s"
                   " for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def delete_network_postcommit(self, mech_context):
        """Delete network which translates to removing vlan
        from the switch.
        """

        LOG.debug("delete_network_postcommit: called")
        network = mech_context.current
        network_id = network['id']
        vlan_id = network['provider:segmentation_id']
        tenant_id = network['tenant_id']
        segments = mech_context.network_segments
        segment = segments[0]
        physical_network = segment['physical_network']
        try:
            devices = self._physical_networks.get(physical_network)
            for device in devices:
                driver = self._get_driver(device)
                driver.delete_network(vlan_id)
        except Exception:
            LOG.exception(
                _LE("Brocade FI/NI driver: failed to delete network"))
            raise Exception(
                _("Brocade switch exception, "
                  "delete_network_postcommit failed"))

        LOG.info(_LI("delete network (postcommit): %(network_id)s"
                   " with vlan = %(vlan_id)s"
                   " for tenant %(tenant_id)s"),
                 {'network_id': network_id,
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
        """
        driver = self._driver_map.get(device)
        if driver is None:
            driver_factory = importutils.import_object(DRIVER_FACTORY)
            device_info = self._devices.get(device)
            try:
                driver = driver_factory.get_driver(device_info)
            except Exception:
                LOG.exception(_LE("Device is not supported"))
                raise Exception(_("Unsupported Device Found"))
            self._driver_map.update({device: driver})
        return driver
