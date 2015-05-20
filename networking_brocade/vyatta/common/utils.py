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

import collections

from eventlet import greenthread
import netaddr
import six


RouteRule = collections.namedtuple('RouteRule', 'dest_cidr, next_hop')


def retry(fn, args=None, kwargs=None, exceptions=None, limit=1, delay=0):
    args = args or []
    kwargs = kwargs or {}

    while limit > 0:
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if not exceptions or not isinstance(e, exceptions):
                raise
        if delay:
            greenthread.sleep(delay)
        limit -= 1
    raise


class MultiDict(collections.MutableMapping):

    def __init__(self, mapping=None):
        self._items = {}

        if isinstance(mapping, MultiDict):
            for key, value in mapping.lists():
                self._items[key] = value[:]
        elif isinstance(mapping, dict):
            for key, value in six.iteritems(mapping):
                self._items[key] = [value]
        elif mapping is not None:
            for key, value in mapping:
                self._items.setdefault(key, []).append(value)

    def __getitem__(self, key):
        return self._items[key][0]

    def __setitem__(self, key, value):
        self._items[key] = [value]

    def __delitem__(self, key):
        del self._items[key]

    def __len__(self):
        return len(self._items)

    def __iter__(self):
        return six.iterkeys(self._items)

    def __repr__(self):
        items = []
        for key, lst in six.iteritems(self._items):
            for item in lst:
                items.append((key, item))
        return 'MultiDict {0!r}'.format(items)

    def add(self, key, value):
        self._items.setdefault(key, []).append(value)

    def getlist(self, key, default=None):
        try:
            return self._items[key]
        except KeyError:
            return default or []

    def setlist(self, key, value):
        self._items[key] = list(value)

    def setlistdefault(self, key, default_list=None):
        if key in self._items:
            default_list = self._items[key]
        else:
            if default_list is None:
                default_list = []
            else:
                default_list = list(default_list)
            self._items[key] = default_list

        return default_list

    def copy(self):
        return self.__class__(self)

    def lists(self):
        return six.iteritems(self._items)

    def listvalues(self):
        return six.itervalues(self._items)


class InterfaceInfo(object):

    def __init__(self, name=None, ip_addresses=None,
                 mac_address=None, gateway=None):

        self.name = name
        self.mac_address = mac_address
        self.gateway = gateway

        self.ip_addresses = []
        for addr in ip_addresses:
            if isinstance(addr, str):
                addr = netaddr.IPNetwork(addr)
            elif not isinstance(addr, netaddr.IPNetwork):
                raise TypeError('IP address {0!r} should be '
                                'str or netaddr.IPNetwork')
            self.ip_addresses.append(addr)
