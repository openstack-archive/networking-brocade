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

from neutron.common import exceptions


class CorruptedSystemError(exceptions.NeutronException):
    message = _('System contain conflicts: %(description)s.')


class VRouterConnectFailure(exceptions.NeutronException):
    """Couldn't connect to instance."""
    message = _("Couldn't connect to Vyatta vRouter [%(ip_address)s].")


class VRouterOperationError(exceptions.NeutronException):
    """Internal Vyatta vRouter exception."""
    message = _("Internal Vyatta vRouter exception [%(ip_address)s]:"
                "%(reason)s.")


class InvalidVRouterInstance(exceptions.NeutronException):
    """Couldn't find the vrouter instance."""
    message = _("Couldn't find Vyatta vRouter instance %(router_id)s.")


class InvalidInstanceConfiguration(exceptions.NeutronException):
    """Invalid vRouter VM instance configuration."""
    message = _("Invalid Vyatta vRouter configuration: %(cause)s.")


class InvalidParameter(exceptions.NeutronException):
    """Invalid configuration parameter."""
    message = _("Invalid Parameter: %(cause)s.")


class InvalidResponseFormat(exceptions.NeutronException):
    message = _('Unparsable vRouter API response: %(details)s')


class WaitTimeoutError(exceptions.NeutronException):
    """Timeout error after waiting for Vyatta vRouter VM creation."""
    message = _("Timeout waiting for Vyatta vRouter instance creation.")


class InstanceSpawnError(exceptions.NeutronException):
    """vRouter VM instance spawning error."""
    message = _("Failed to spawn Vyatta vRouter VM instance.")


class InvalidL3AgentStateError(exceptions.NeutronException):
    message = _('Invalid L3 agent state: %(description)s')


class InvalidVPNServiceError(exceptions.NeutronException):
    message = _('Invalid or incomplete VPN service data')


class VPNResourceMappingNotFound(exceptions.NotFound):
    message = _('There is no VPN resource mapping for %(kind)s key=%(key)s')


class ResourceNotFound(exceptions.NotFound):
    message = _('Resource not found.')


class TableCellNotFound(exceptions.NotFound):
    message = _('There is no cell in vRouter status table.')


class DvrOrHaRouterNotSupported(exceptions.NeutronException):
    message = _('DVR or HA routers are not supported.')
