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

import os
import time

from eventlet import greenthread
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy.orm import exc as orm_exception

from neutron.common import log
from neutron.db import models_v2
from neutron.i18n import _LE, _LI
from novaclient import exceptions as nova_exc
from novaclient.v1_1 import client as novaclient

from networking_brocade.vyatta.common import config
from networking_brocade.vyatta.common import exceptions as v_exc
from networking_brocade.vyatta.vrouter import client as vyatta_client


LOG = logging.getLogger(__name__)


class VyattaVRouterDriver(object):

    def __init__(self):
        self._vrouter_instance_map = {}
        self._management_network_id = config.VROUTER.management_network_id

        self._nova_client = novaclient.Client(
            config.VROUTER.tenant_admin_name,
            config.VROUTER.tenant_admin_password,
            auth_url=config.CONF.nova_admin_auth_url,
            service_type="compute",
            tenant_id=config.VROUTER.tenant_id)

    def create_router(self, context):
        LOG.debug("Vyatta vRouter Driver::Create Router")
        # Launch the vRouter VM. Method takes care of vRouter VM cleanup
        # when we encounter nova spawn or vRouter boot issues
        router = self._launch_routerVM(context)
        return router.id

    def init_router(self, context, router):
        LOG.debug("Vyatta vRouter Driver::Initialize router")
        try:
            vrouter_api = self._get_router_api(context, router['id'])
            vrouter_api.init_router(router.get('name', 'vyatta-router'),
                                    router.get('admin_state_up', False))
        except (v_exc.InvalidVRouterInstance,
                v_exc.InvalidInstanceConfiguration,
                v_exc.VRouterConnectFailure,
                v_exc.VRouterOperationError) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Vyatta vRouter Driver::Initialize"
                              " router failed. Exception %s"), ex)
                self._delete_routerVM(context, router['id'])

    def delete_router(self, context, router_id):
        LOG.debug("Vyatta vRouter Driver::Deinitialize router")
        try:
            vrouter_api = self._get_router_api(context, router_id)
            vrouter_api.disconnect()
        finally:
            self._delete_routerVM(context, router_id)

    def attach_interface(self, context, router_id, port_id):
        LOG.debug("Vyatta vRouter Driver::Attach interface")
        router = self._nova_client.servers.get(router_id)
        router.interface_attach(port_id, None, None)

    def detach_interface(self, context, router_id, port_id):
        LOG.debug("Vyatta vRouter Driver::Deattach interface")
        router = self._nova_client.servers.get(router_id)
        router.interface_detach(port_id)

    def configure_interface(self, context, router_id, interface_infos):
        LOG.debug("Vyatta vRouter Driver::Configure interface")
        vrouter_api = self._get_router_api(context, router_id)
        for interface_info in interface_infos:
            vrouter_api.add_interface_to_router(interface_info)

    @log.log
    def update_interface(self, context, router_id, interface_info):
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.update_interface(interface_info)

    def deconfigure_interface(self, context, router_id, interface_infos):
        LOG.debug("Vyatta vRouter Driver::Deconfigure interface")
        vrouter_api = self._get_router_api(context, router_id)
        for interface_info in interface_infos:
            vrouter_api.remove_interface_from_router(interface_info)

    def configure_gateway(self, context, router_id, interface_infos):
        LOG.debug("Vyatta vRouter Driver::Configure gateway")
        if len(interface_infos) != 1:
            raise v_exc.InvalidParameter(
                cause=_("Only one external gateway interface expected. "
                        "Given interfaces = %s") % len(interface_infos))
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.update_router(external_gateway_info=interface_infos[0])

    def clear_gateway(self, context, router_id):
        LOG.debug("Vyatta vRouter Driver::Clear gateway")
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.update_router(external_gateway_info=None)

    def assign_floating_ip(self, context, router_id, floating_ip, fixed_ip):
        LOG.debug("Vyatta vRouter Driver::Assign Floating IP")
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.assign_floating_ip(floating_ip, fixed_ip)

    def unassign_floating_ip(self, context, router_id, floating_ip, fixed_ip):
        LOG.debug("Vyatta vRouter Driver::Unassign Floating IP")
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.unassign_floating_ip(floating_ip, fixed_ip)

    def update_static_routes(self, context, router_id, route_add, route_del):
        LOG.debug('Vyatta vRouter Driver::Update static routes')
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.update_static_routes(route_add, route_del)

    def _launch_routerVM(self, context):
        LOG.debug("Vyatta vRouter Driver::Launch router")
        router_name = 'vrouter_{0}'.format(os.urandom(6).encode('hex'))
        LOG.info(
            _LI("Vyatta vRouter Driver::Creating the vRouter instance %s"),
            router_name)

        try:
            router = self._nova_client.servers.create(
                router_name, config.VROUTER.image_id,
                config.VROUTER.flavor,
                nics=[{'net-id': self._management_network_id}])
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound, nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception):
            with excutils.save_and_reraise_exception():
                LOG.error(
                    _LE("Vyatta vRouter Driver::Create server %s failed"),
                    router_name)
                raise v_exc.InstanceSpawnError()

        LOG.info(_LI("Vyatta vRouter Driver::Waiting for the vRouter "
                     "instance %s to start"), router_name)

        def _router_spawn():
            while True:
                try:
                    instance = self._nova_client.servers.get(router.id)
                except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                        nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                        nova_exc.AuthSystemNotFound,
                        nova_exc.NoTokenLookupException,
                        nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                        nova_exc.ConnectionRefused, nova_exc.ClientException,
                        Exception):
                    yield config.VROUTER.nova_poll_interval
                    continue
                LOG.debug("Vyatta vRouter Driver::vRouter instance {0} "
                          "Spawn Status: {1}".format(router_name,
                                                     instance.status))
                if instance.status not in ('ACTIVE', 'ERROR'):
                    yield config.VROUTER.nova_poll_interval
                elif instance.status == 'ERROR':
                    raise v_exc.InstanceSpawnError()
                else:
                    break

        try:
            # Wait for Nova to spawn VM instance
            self._wait(_router_spawn,
                       timeout=config.VROUTER.nova_spawn_timeout)
        except (v_exc.InstanceSpawnError, v_exc.WaitTimeoutError) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE(
                    "Vyatta vRouter Driver::vRouter {0} spawn issue. "
                    "Exception {1}").format(router_name, ex))
                self._delete_routerVM(context, router.id)

        try:
            ifs = router.interface_list()
            if len(ifs) != 1:
                raise v_exc.InvalidParameter(
                    cause=_("Management interface expected "
                            "in router: %s") % router.id)
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound,
                nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                v_exc.InvalidParameter, Exception):
            with excutils.save_and_reraise_exception():
                self._delete_routerVM(context, router.id)

        def _router_boot():
            router_api = None
            while router_api is None:
                try:
                    router_api = self._get_router_api(context, router.id)
                except (v_exc.VRouterConnectFailure,
                        v_exc.VRouterOperationError):
                    yield config.VROUTER.vrouter_poll_interval
                    continue
                if router_api is not None:
                    break

        LOG.info(_LI("Vyatta vRouter Driver::Waiting for the vRouter {0} "
                     "to boot.").format(router_name))
        try:
            # Now wait for router to boot
            self._wait(_router_boot,
                       timeout=config.VROUTER.vrouter_boot_timeout)
        except (v_exc.WaitTimeoutError,
                v_exc.VRouterConnectFailure,
                v_exc.VRouterOperationError,
                v_exc.InvalidVRouterInstance,
                v_exc.InvalidInstanceConfiguration) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Vyatta vRouter Driver::vRouter {0} boot issue. "
                              "Exception: {1}").format(router_name, ex))
                self._delete_routerVM(context, router.id)

        LOG.info(_LI("Vyatta vRouter Driver::vRouter instance %s is ready"),
                 router_name)

        return router

    def _wait(self, query_fn, timeout=0):
        end = time.time() + timeout
        for interval in query_fn():
            greenthread.sleep(interval)
            if timeout > 0 and time.time() >= end:
                raise v_exc.WaitTimeoutError()

    def _delete_routerVM(self, context, router_id):
        LOG.info(
            _LI("Vyatta vRouter Driver::Deleting the vRouter VM instance %s"),
            router_id)
        self._vrouter_instance_map.pop(router_id, None)

        try:
            self._nova_client.servers.delete(router_id)
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound,
                nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception):
            with excutils.save_and_reraise_exception:
                LOG.error(
                    _LE("Vyatta vRouter Driver::Failed to delete the vRouter"
                        " VM instance %s"),
                    router_id)

    def _get_router_api(self, context, router_id):
        LOG.debug("Vyatta vRouter Driver::Get router driver")

        try:
            return self._vrouter_instance_map[router_id]
        except KeyError:

            try:
                query = context.session.query(models_v2.Network)
                network = query.filter_by(
                    id=self._management_network_id).one()
            except orm_exception.NoResultFound as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Unable to find Vyatta vRouter "
                                  "management network %s"), ex)
                    raise v_exc.InvalidInstanceConfiguration(
                        cause="Unable to find management network")

            try:
                vrouter_instance = self._nova_client.servers.get(router_id)
            except nova_exc.ClientException as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE(
                        "Unable to find Vyatta vRouter instance {0}. "
                        "Exception {1}").format(router_id, ex))
                    raise v_exc.InvalidVRouterInstance(router_id=router_id)

            LOG.debug("Vyatta vRouter Management network: %s",
                      network['name'])
            address_map = vrouter_instance.addresses[network['name']]
            if address_map is None:
                raise v_exc.InvalidVRouterInstance(router_id=router_id)
            address = address_map[0]["addr"]

            # Initialize vRouter API
            try:
                vrouter_api = vyatta_client.VRouterRestAPIClient()
                vrouter_api.connect(address)
            except Exception as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Vyatta vRouter Driver: vRouter {0} "
                              "Connection exception {1}").format(address, ex))

            self._vrouter_instance_map[router_id] = vrouter_api
            return vrouter_api
