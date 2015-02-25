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
import collections
import itertools
import logging
import urllib
import uuid

from oslo_utils import excutils
import six

from neutron.i18n import _LE, _LI
from networking_brocade.vyatta.common import exceptions as v_exc
from networking_brocade.vyatta.common import parsers as v_parsers
from networking_brocade.vyatta.vrouter import client as vyatta_client


LOG = logging.getLogger(__name__)

_KEY_CONNECTIONS = 'ipsec_site_connections'
_KEY_IKEPOLICY = 'ikepolicy'
_KEY_ESPPOLICY = 'ipsecpolicy'


def connect_setup_commands(vrouter, iface, svc, conn, resources):
        LOG.info(_LI('Vyatta vRouter: _connect_setup_commands:  '))
        SCmd = vyatta_client.SetCmd
        batch = list()

        if resources.iface_alloc(conn, iface):
            batch.append(
                SCmd('vpn/ipsec/ipsec-interfaces/interface/{0}'.format(iface)))

        ike_name, need_create = resources.ike_group_alloc(conn)
        if need_create:
            batch.extend(ike_setup_commands(conn, ike_name))

        esp_name, need_create = resources.esp_group_alloc(conn)
        if need_create:
            batch.extend(esp_setup_commands(conn, esp_name))

        link_id = [uuid.UUID(x).get_hex() for x in svc['id'], conn['id']]
        link_id.insert(0, 'os-id')
        link_id = ':'.join(link_id)
        remote_peer = conn['peer_address']
        p = 'vpn/ipsec/site-to-site/peer/{0}'.format(remote_peer)
        batch.extend([
            SCmd('{0}/description/{1}'.format(p, link_id)),
            SCmd('{0}/authentication/mode/pre-shared-secret'.format(p)),
            SCmd('{0}/authentication/pre-shared-secret/{1}'.format(
                p, conn['psk'])),
            SCmd('{0}/ike-group/{1}'.format(p, ike_name)),
            SCmd('{0}/default-esp-group/{1}'.format(p, esp_name)),
            SCmd('{0}/local-address/{1}'.format(
                p, urllib.quote_plus(svc['external_ip'])))])
        for remote_cidr in conn['peer_cidrs']:
            idx = resources.tunnel_alloc(conn, remote_peer)
            batch.append(SCmd(
                '{0}/tunnel/{1}/allow-public-networks/enable'.format(p, idx)))
            batch.append(SCmd('{0}/tunnel/{1}/local/prefix/{2}'.format(
                p, idx, urllib.quote_plus(svc['subnet']['cidr']))))
            batch.append(SCmd('{0}/tunnel/{1}/remote/prefix/{2}'.format(
                p, idx, urllib.quote_plus(remote_cidr))))
            LOG.info(_LI('Vyatta vRouter: _connect_setup_commands: '
                         'add snat-exclude for remote_cidr %s'), remote_cidr)
            vrouter.add_snat_exclude_rule(batch, iface,
                svc['subnet']['cidr'], remote_cidr)

        # TODO(dbogun): static routing for remote networks
        return batch


def ike_setup_commands(conn, name):
        policy = conn[_KEY_IKEPOLICY]

        SCmd = vyatta_client.SetCmd

        ike_prefix = 'vpn/ipsec/ike-group/{0}'.format(urllib.quote_plus(name))
        return [
            SCmd('{0}/proposal/1'.format(ike_prefix)),
            SCmd('{0}/proposal/1/encryption/{1}'.format(
                ike_prefix, policy['encryption_algorithm'])),
            SCmd('{0}/proposal/1/hash/{1}'.format(
                ike_prefix, policy['auth_algorithm'])),
            SCmd('{0}/lifetime/{1}'.format(
                ike_prefix, policy['lifetime_value'])),
            SCmd('{0}/dead-peer-detection/action/{1}'.format(
                ike_prefix, conn['dpd_action'])),
            SCmd('{0}/dead-peer-detection/interval/{1}'.format(
                ike_prefix, conn['dpd_interval'])),
            SCmd('{0}/dead-peer-detection/timeout/{1}'.format(
                ike_prefix, conn['dpd_timeout']))
        ]


def esp_setup_commands(conn, name):
        policy = conn[_KEY_ESPPOLICY]

        SCmd = vyatta_client.SetCmd

        esp_prefix = 'vpn/ipsec/esp-group/{0}'.format(urllib.quote_plus(name))
        return [
            SCmd('{0}/proposal/1'.format(esp_prefix)),
            SCmd('{0}/proposal/1/encryption/{1}'.format(
                esp_prefix, policy['encryption_algorithm'])),
            SCmd('{0}/proposal/1/hash/{1}'.format(
                esp_prefix, policy['auth_algorithm'])),
            SCmd('{0}/lifetime/{1}'.format(
                esp_prefix, policy['lifetime_value'])),
            SCmd('{0}/pfs/{1}'.format(
                esp_prefix, policy['pfs'])),
            SCmd('{0}/mode/{1}'.format(
                esp_prefix, policy['encapsulation_mode']))
        ]


def connect_remove_commands(vrouter, iface, svc, conn, resources):
        LOG.info(_LI('Vyatta vRouter: _connect_setup_commands:  '))

        DCmd = vyatta_client.DeleteCmd

        batch = [
            DCmd('vpn/ipsec/site-to-site/peer/{0}'.format(
                conn['peer_address']))]

        name, need_remove = resources.ike_group_release(conn)
        if need_remove:
            batch.append(
                DCmd('vpn/ipsec/ike-group/{0}'.format(
                    urllib.quote_plus(name))))
        name, need_remove = resources.esp_group_release(conn)
        if need_remove:
            batch.append(
                DCmd('vpn/ipsec/esp-group/{0}'.format(
                    urllib.quote_plus(name))))

        if resources.iface_release(conn, iface):
            # FIXME(dbogun): vrouter failed to complete this command
            # batch.append(
            #     DCmd('vpn/ipsec/ipsec-interfaces/interface/{0}'.format(
            #         iface)))
            pass

        for remote_cidr in conn['peer_cidrs']:
            LOG.info(_LI('Vyatta vRouter: _connect_setup_commands: '
                         'delete snat-exclude for remote_cidr %s'),
                     remote_cidr)
            vrouter.delete_snat_exclude_rule(batch, iface,
                svc['subnet']['cidr'], remote_cidr)

        resources.tunnel_release(conn, svc['external_ip'])
        return batch


def compare_vpn_services(vrouter, gw_iface, old, new):
    if old.get('_reversed', False):
        old_conn_by_id = dict((x['id'], x) for x in old[_KEY_CONNECTIONS])
        for conn_new in new[_KEY_CONNECTIONS]:
            try:
                old_conn = old_conn_by_id[conn_new['id']]
            except KeyError:
                continue
            old_conn['psk'] = conn_new['psk']

    batch_old = set()
    batch_new = set()
    for svc, batch in (
            (old, batch_old), (new, batch_new)):
        for conn in svc[_KEY_CONNECTIONS]:
            patch = RouterResources(
                svc['id']).make_patch()
            commands = connect_setup_commands(
                vrouter, gw_iface, svc, conn, patch)
            commands = tuple((x.make_url('_dummy_') for x in commands))
            batch.add(commands)
    return batch_old == batch_new


VPN_STATE_MAP = {
    'up': True,
    'down': False
}


def parse_vpn_connections(ipsec_sa, resources):
    parser = v_parsers.TableParser()
    parser(ipsec_sa)
    assert not (len(parser) % 2)

    conn_status = collections.defaultdict(list)
    parser_iter = iter(parser)
    for endpoints, tunnels in itertools.izip(parser_iter, parser_iter):
        endpoints = iter(endpoints)
        try:
            peer = next(endpoints)
            peer = peer.cell_by_idx(0)
        except StopIteration:
            raise ValueError('Invalid VPN IPSec status report.')

        for tunn in tunnels:
            tunn_idx = tunn.cell_by_name('Tunnel')
            try:
                tunn_idx = int(tunn_idx)
            except ValueError:
                raise v_exc.InvalidResponseFormat(
                    details=('expect integer on place of tunnel index '
                             'got {!r}').format(tunn_idx))

            try:
                conn_id = resources.get_connect_by_tunnel(
                    peer, tunn_idx)
            except v_exc.ResourceNotFound:
                continue

            state = tunn.cell_by_name('State')
            state = state.lower()
            try:
                state = VPN_STATE_MAP[state]
            except KeyError:
                raise v_exc.InvalidResponseFormat(
                    details='unsupported tunnel state {!r}'.format(
                        state))
            conn_status[conn_id].append(state)

    conn_ok = set(key for key, value in six.iteritems(conn_status)
                  if all(value))

    return conn_ok


def validate_svc_connection(conn):
    # NOTE(asaprykin): Maybe it's better to move code into
    # separate function to avoid long try..except blocks
    try:
        map_encryption = {
            '3des': '3des',
            'aes-128': 'aes128',
            'aes-256': 'aes256'}
        map_pfs = {
            'group2': 'dh-group2',
            'group5': 'dh-group5'}

        allowed_pfs = map_pfs.values() + ['enable', 'disable']

        if conn['dpd_action'] not in ('hold', 'clear', 'restart'):
            raise ValueError('invalid dpd_action {0}'.format(
                conn['dpd_action']))

        ike_policy = conn[_KEY_IKEPOLICY]
        ike_policy['encryption_algorithm'] = \
            map_encryption[ike_policy['encryption_algorithm']]
        if ike_policy['lifetime_units'] != 'seconds':
            raise ValueError(
                'invalid "lifetime_units"=="{}" in ike_policy'.format(
                    ike_policy['lifetime_units']))

        esp_policy = conn[_KEY_ESPPOLICY]
        esp_policy['encryption_algorithm'] = \
            map_encryption[esp_policy['encryption_algorithm']]
        if esp_policy['lifetime_units'] != 'seconds':
            raise ValueError(
                'invalid "lifetime_units"=="{}" in esp_policy'.format(
                    esp_policy['lifetime_units']))
        if esp_policy['transform_protocol'] != 'esp':
            raise ValueError(
                'invalid "transform_protocol"=="{}" in esp_policy'.format(
                    esp_policy['transform_protocol']))
        pfs = esp_policy['pfs']
        esp_policy['pfs'] = map_pfs.get(pfs, pfs)
        if esp_policy['pfs'] not in allowed_pfs:
            raise ValueError(
                'invalid "pfs"=="{}" in esp_policy'.format(pfs))
        if esp_policy['encapsulation_mode'] not in ('tunnel', 'transport'):
            raise ValueError(
                'invalid "encapsulation_mode"=="{}" in esp_policy'.format(
                    esp_policy['encapsulation_mode']))
    except (ValueError, KeyError):
        with excutils.save_and_reraise_exception():
            raise v_exc.InvalidVPNServiceError()


# -- Tools ------------------------
class RouterResources(object):
    def __init__(self, router_id):
        self.router_id = router_id

        self.iface_to_conn = collections.defaultdict(set)
        self.ike_to_conn = collections.defaultdict(set)
        self.esp_to_conn = collections.defaultdict(set)
        self.conn_to_tunn = collections.defaultdict(set)
        self.peer_to_conn = dict()
        self.tunn_idx_factory = collections.defaultdict(itertools.count)

    def make_patch(self):
        return _RouteResourcePatch(self)

    def key_for_conn(self, conn):
        return ('connect', conn['id'])

    def key_for_tunnel(self, conn, remote_peer):
        key = list(self.key_for_conn(conn))
        key[0] = 'tunn'
        key.append(remote_peer)
        return tuple(key)

    def get_connect_by_tunnel(self, remote_peer, idx):
        key = (remote_peer, idx)
        try:
            conn_id = self.peer_to_conn[key]
        except KeyError:
            raise v_exc.ResourceNotFound
        return conn_id


class _RouteResourcePatch(object):
    NAME_LENGTH_LIMIT = 251

    def __init__(self, owner):
        self._owner = owner
        self._actions = list()
        self._tunn_factory_overlay = dict()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is not None:
            return

        self._apply()

    def iface_alloc(self, conn, name):
        key = self._owner.key_for_conn(conn)
        self._actions.append(_PatchSetAdd(
            self._owner.iface_to_conn[key], conn['id']))
        return not len(self._owner.iface_to_conn[key])

    def iface_release(self, conn, name):
        key = self._owner.key_for_conn(conn)
        self._actions.append(_PatchSetDel(
            self._owner.iface_to_conn[key], conn['id']))
        return self._owner.iface_to_conn[key] == {conn['id']}

    def ike_group_alloc(self, conn):
        return self._group_alloc(self._owner.ike_to_conn, conn, _KEY_IKEPOLICY)

    def esp_group_alloc(self, conn):
        return self._group_alloc(self._owner.esp_to_conn, conn, _KEY_ESPPOLICY)

    def _group_alloc(self, target, conn, policy_key):
        name = self._make_entity_name(conn[policy_key])
        self._actions.append(_PatchSetAdd(target[name], conn['id']))
        return name, not len(target[name])

    def ike_group_release(self, conn):
        return self._group_release(
            self._owner.ike_to_conn, conn, _KEY_IKEPOLICY)

    def esp_group_release(self, conn):
        return self._group_release(
            self._owner.esp_to_conn, conn, _KEY_ESPPOLICY)

    def _group_release(self, target, conn, policy_key):
        name = self._make_entity_name(conn[policy_key])
        self._actions.append(_PatchSetDel(target[name], conn['id']))
        return name, target[name] == {conn['id']}

    def tunnel_alloc(self, conn, remote_peer, idx=None):
        conn_key = self._owner.key_for_conn(conn)
        tunn_key = self._owner.key_for_tunnel(conn, remote_peer)
        if idx is None:
            idx = next(self._owner.tunn_idx_factory[tunn_key])
        else:
            try:
                max_idx, overlay = self._tunn_factory_overlay[tunn_key]
                max_idx = max(idx, max_idx)
                overlay.value = itertools.count(max_idx + 1)
            except KeyError:
                max_idx = idx
                overlay = _PatchDictAdd(
                    self._owner.tunn_idx_factory, tunn_key,
                    itertools.count(max_idx + 1))
                self._actions.append(overlay)
            self._tunn_factory_overlay[tunn_key] = max_idx, overlay

        self._actions.append(_PatchDictAdd(
            self._owner.peer_to_conn, (remote_peer, idx), conn['id']))
        self._actions.append(_PatchSetAdd(
            self._owner.conn_to_tunn[conn_key], idx))
        return idx

    def tunnel_release(self, conn, remote_peer, idx=None):
        key = self._owner.key_for_conn(conn)

        if idx is None:
            idx_seq = self._owner.conn_to_tunn[key]
        else:
            idx_seq = (idx, )

        for idx in idx_seq:
            self._actions.append(_PatchDictDel(
                self._owner.peer_to_conn, (remote_peer, idx)))
            self._actions.append(_PatchSetDel(
                self._owner.conn_to_tunn[key], idx))

    def _apply(self):
        for action in self._actions:
            action()

    def _make_entity_name(self, data):
        idnr = uuid.UUID(data['id'])
        name = data['name'].lower()
        name = ''.join((x if x.isalnum() else '') for x in name)
        name = '{0}-{1}'.format(name, idnr.get_hex())
        if self.NAME_LENGTH_LIMIT < len(name):
            raise v_exc.InvalidParameter(
                cause=('Can\'t make vyatta resource identifier, result exceed '
                       'length limit'))
        return name


@six.add_metaclass(abc.ABCMeta)
class _PatchActionAbstract(object):
    def __init__(self, target):
        self.target = target

    @abc.abstractmethod
    def __call__(self):
        pass


class _PatchDictAdd(_PatchActionAbstract):
    def __init__(self, target, key, value):
        _PatchActionAbstract.__init__(self, target)
        self.key = key
        self.value = value

    def __call__(self):
        self.target[self.key] = self.value


class _PatchDictDel(_PatchActionAbstract):
    def __init__(self, target, key, allow_missing=True):
        _PatchActionAbstract.__init__(self, target)
        self.key = key
        self.allow_missing = allow_missing

    def __call__(self):
        try:
            del self.target[self.key]
        except KeyError:
            if not self.allow_missing:
                raise v_exc.ResourceNotFound


class _PatchSetAdd(_PatchActionAbstract):
    def __init__(self, target, value):
        _PatchActionAbstract.__init__(self, target)
        self.value = value

    def __call__(self):
        self.target.add(self.value)


class _PatchSetDel(_PatchActionAbstract):
    def __init__(self, target, value, allow_missing=True):
        _PatchActionAbstract.__init__(self, target)
        self.value = value
        self.allow_missing = allow_missing

    def __call__(self):
        try:
            self.target.remove(self.value)
        except KeyError:
            if not self.allow_missing:
                raise v_exc.ResourceNotFound


def parse_vrouter_config(config, resources):
    try:
        config = config['vpn']
        config = config['ipsec']
        interfaces = config['ipsec-interfaces']
        site_to_site = config['site-to-site']
    except KeyError:
        return tuple()

    interfaces = interfaces.values()
    svc_set = collections.defaultdict(dict)

    key_prefix = 'peer '
    for peer in site_to_site:
        conn = site_to_site[peer]
        if not peer.startswith(key_prefix):
            continue
        peer = peer[len(key_prefix):]

        try:
            conn_data, svc_data = _parse_ipsec_site_to_site(
                peer, conn, config, resources)
        except v_exc.InvalidResponseFormat as e:
            LOG.error(
                _LE('process vRouter ipsec configuration: {0}').format(e))
            continue

        svc_id = svc_data['id']
        svc = svc_set[svc_id]
        svc.setdefault('_reversed', True)
        svc.update(svc_data)
        svc.setdefault('ipsec_site_connections', list()).append(conn_data)

        resources.ike_group_alloc(conn_data)
        resources.esp_group_alloc(conn_data)
        for iface in interfaces:
            resources.iface_alloc(conn_data, iface)
        for idx, remote in conn_data.pop('_tunn_and_cidr'):
            resources.tunnel_alloc(conn_data, remote, idx)

    return svc_set.values()


def _parse_ipsec_site_to_site(peer, conn, config, resources):
    result = dict()
    svc_upd = dict()

    try:
        idnr_set = conn['description'].split(':')
        if idnr_set.pop(0) != 'os-id':
            raise ValueError

        svc_id, conn_id = [str(uuid.UUID(x)) for x in idnr_set]
    except (KeyError, TypeError, ValueError):
        raise v_exc.InvalidResponseFormat(
            details='vpn connection does not contain neutron connection id')

    try:
        auth = conn['authentication']

        result['id'] = conn_id
        result['peer_address'] = peer
        result['psk'] = auth['pre-shared-secret']

        svc_upd['id'] = svc_id
        svc_upd['external_ip'] = conn['local-address']
    except KeyError:
        raise v_exc.InvalidResponseFormat(
            details='incomplete connection config')

    svc_upd['subnet'] = subnet = dict()

    key_prefix = 'tunnel '
    peer_cidr = list()
    for key in (x for x in conn if x.startswith(key_prefix)):
        idx, local, remote = _parse_ipsec_tunnel(key, conn)
        peer_cidr.append((idx, remote))
        subnet['cidr'] = local
    peer_cidr.sort(key=lambda x: x[0])
    result['_tunn_and_cidr'] = peer_cidr
    result['peer_cidrs'] = [x[1] for x in peer_cidr]

    ike, upd = _parse_ipsec_ike_group(conn, config, resources)
    result['ikepolicy'] = ike
    result.update(upd)

    esp, upd = _parse_ipsec_esp_group(conn, config, resources)
    result['ipsecpolicy'] = esp
    result.update(upd)

    return result, svc_upd


def _parse_ipsec_ike_group(conn, config, resources):
    result = dict()
    conn_upd = dict()

    try:
        name = conn['ike-group']
        policy = config['ike-group ' + name]
    except KeyError:
        raise v_exc.InvalidResponseFormat(details='ike group missing')

    name, idnr = _unpack_ipsec_group_name(name)

    try:
        dpd = policy['dead-peer-detection']
        proposal = policy['proposal 1']

        result['id'] = idnr
        result['name'] = name
        result['encryption_algorithm'] = proposal['encryption']
        result['auth_algorithm'] = proposal['hash']
        result['lifetime_value'] = policy['lifetime']

        conn_upd['dpd_action'] = dpd['action']
        conn_upd['dpd_interval'] = dpd['interval']
        conn_upd['dpd_timeout'] = dpd['timeout']
    except KeyError:
        raise v_exc.InvalidResponseFormat(
            details='incomplete IKE group config')

    return result, conn_upd


def _parse_ipsec_esp_group(conn, config, resources):
    result = dict()
    try:
        name = conn['default-esp-group']
        policy = config['esp-group ' + name]
    except KeyError:
        raise v_exc.InvalidResponseFormat(details='eps group missing')

    name, idnr = _unpack_ipsec_group_name(name)

    try:
        proposal = policy['proposal 1']

        result['id'] = idnr
        result['name'] = name
        result['encryption_algorithm'] = proposal['encryption']
        result['auth_algorithm'] = proposal['hash']
        result['lifetime_value'] = policy['lifetime']
        result['pfs'] = policy['pfs']
        result['encapsulation_mode'] = policy['mode']
    except KeyError:
        raise v_exc.InvalidResponseFormat(
            details='incomplete ESP group config')

    return result, dict()


def _parse_ipsec_tunnel(key, conn):
    try:
        peer = conn[key]
        idx = key.rsplit(' ', 1)[1]
        idx = int(idx)
    except (KeyError, IndexError, ValueError):
        raise v_exc.InvalidResponseFormat(
            details='invalid tunnel section "{0}"'.format(key))

    try:
        local = peer['local']
        local = local['prefix']

        remote = peer['remote']
        remote = remote['prefix']
    except KeyError:
        raise v_exc.InvalidResponseFormat(
            details='incomplete peer config')

    return idx, local, remote


def _unpack_ipsec_group_name(raw):
    try:
        name, idnr = raw.rsplit('-', 1)
        idnr = uuid.UUID(idnr)
        idnr = str(idnr)
    except (TypeError, ValueError):
        raise v_exc.InvalidResponseFormat(
            details='can\'t parse group name "{0}"'.format(raw))
    return name, idnr
