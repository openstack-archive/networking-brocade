# Copyright 2015 Brocade Communications System, Inc..
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

from oslo_config import cfg


cfg.CONF.register_opts([
    cfg.StrOpt('tenant_admin_name', help=_('Name of tenant admin user.')),
    cfg.StrOpt('tenant_admin_password', secret=True,
               help=_('Tenant admin password.')),
    cfg.StrOpt('tenant_id',
               help=_('UUID of tenant that holds Vyatta vRouter instances.')),
    cfg.StrOpt('image_id',
               help=_('Nova image id for instances of Vyatta vRouter.')),
    cfg.StrOpt('flavor', default=2,
               help=_('Nova VM flavor for instances of Vyatta vRouter.')),
    cfg.StrOpt('management_network_id',
               help=_('Vyatta vRouter management network id.')),
    cfg.StrOpt('vrouter_credentials', default="vyatta:vyatta",
               help=_('Vyatta vRouter login credentials')),
    cfg.IntOpt('nova_poll_interval', default=5,
               help=_('Number of seconds between consecutive Nova queries '
                      'when waiting for router instance status change.')),
    cfg.IntOpt('nova_spawn_timeout', default=300,
               help=_('Number of seconds to wait for Nova to activate '
                      'instance before setting resource to error state.')),
    cfg.IntOpt('vrouter_poll_interval', default=5,
               help=_('Number of seconds between consecutive Vyatta vRouter '
                      'queries when waiting for router instance boot.')),
    cfg.IntOpt('vrouter_boot_timeout', default=300,
               help=_('Number of seconds to wait for Vyatta vRouter to boot '
                      'before setting resource to error state.')),
    cfg.StrOpt('keystone_url', help=_('Keystone URL.')),
], "VROUTER")


# setup shortcuts
CONF = cfg.CONF
VROUTER = cfg.CONF.VROUTER
