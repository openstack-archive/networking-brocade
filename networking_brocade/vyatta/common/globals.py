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

import abc
import six

from sqlalchemy.orm import exc as orm_exc

from neutron.db import model_base
from neutron.db import models_v2

from networking_brocade.vyatta.common import config as vyatta_config
from networking_brocade.vyatta.common import exceptions as v_exc


@six.add_metaclass(abc.ABCMeta)
class FetcherAbstract(object):
    value = _unset = object()

    def __call__(self, context):
        if self.value is self._unset:
            self.value = self._lookup(context)
            if isinstance(self.value, model_base.BASEV2):
                context.session.expunge(self.value)
        return self.value

    def reset(self):
        try:
            del self.value
        except AttributeError:
            pass

    @abc.abstractmethod
    def _lookup(self, context):
        pass


class ManageNetworkFetcher(FetcherAbstract):
    def _lookup(self, context):
        q = context.session.query(models_v2.Network)
        q = q.filter_by(
            id=vyatta_config.VROUTER.management_network_id)
        try:
            value = q.one()
        except orm_exc.NoResultFound:
            raise v_exc.InvalidParameter(
                cause=_('Management network {0} specified in vRouter plugin '
                        'configuration file does not exist').format(
                    vyatta_config.VROUTER.management_network_id))
        return value


get_management_network = ManageNetworkFetcher()
