# Copyright 2015 Brocade Communications System, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
import functools
import itertools
import re

from networking_brocade.vyatta.common import exceptions as v_exc

HWADDR = r'(?:[a-zA-Z0-9]{2}:){5}[a-zA-Z0-9]{2}'
IPv4_ADDR = r'(?:\d+\.){3}\d+'


EMPTY_LINE = re.compile(r'^\s+$')
IFACE = re.compile(r'^(\w+):')
LINK_ETHER = re.compile(r'\s+link/ether\s+({0})'.format(HWADDR))
IP_ADDR = re.compile(r'\s+inet\s+({0})'.format(IPv4_ADDR))


def parse_interfaces(output):
    ifaces = []
    info = {}
    for line in output.splitlines():
        if not line or re.match(EMPTY_LINE, line):
            continue

        m = re.match(IFACE, line)
        if m:
            if info:
                ifaces.append(info)
            name = m.group(1)
            info = dict(name=name, ip_addrs=[], mac_address=None)
            continue

        m = re.match(LINK_ETHER, line)
        if m:
            info['mac_address'] = m.group(1).lower()

        m = re.match(IP_ADDR, line)
        if m:
            info['ip_addrs'].append(m.group(1))

    if info:
        ifaces.append(info)

    return ifaces


class TableParser(collections.Iterable, collections.Sized):
    idx_generator = itertools.count()
    _S_EMPTY = next(idx_generator)
    _S_TITLE_SEPARATOR_INTRO = next(idx_generator)
    _S_TITLE_SEPARATOR_FIELD = next(idx_generator)
    _S_TITLE_SEPARATOR_SPACE = next(idx_generator)
    _S_EXTRACT_HEADERS = next(idx_generator)
    _S_VALUE_LINE = next(idx_generator)
    _S_STORE_RESULT = next(idx_generator)
    del idx_generator

    def __init__(self):
        collections.Iterable.__init__(self)
        self.results = list()

    def __iter__(self):
        return iter(self.results)

    def __len__(self):
        return len(self.results)

    def __call__(self, stream):
        stream = TableTokenizer(stream)

        result = None
        lines_buffer = list()
        fields = list()
        offs = 0

        state = self._S_EMPTY

        for chunk in stream:
            if state == self._S_EMPTY:
                stream.revert(chunk)
                chunk = self._read_until_eol(stream)
                chunk = ''.join(chunk)
                if not chunk or chunk.isspace():
                    lines_buffer = list()
                    continue

                offs = 0
                fields = list()
                lines_buffer.append(chunk)

                state = self._S_TITLE_SEPARATOR_INTRO
                continue

            elif state == self._S_TITLE_SEPARATOR_INTRO:
                if chunk == '\n':
                    lines_buffer = list()
                    state = self._S_EMPTY
                    continue

                if chunk.isspace():
                    offs += len(chunk)
                    continue

                stream.revert(chunk)
                state = self._S_TITLE_SEPARATOR_FIELD
                continue

            elif state == self._S_TITLE_SEPARATOR_FIELD:
                if chunk == '\n':
                    stream.revert(None)
                    state = self._S_EXTRACT_HEADERS
                    continue

                if set(chunk) != set('-'):
                    raise ValueError((
                        'Unexpected chunk: {0}. Expect sequence of \'-\' '
                        'characters').format(chunk))

                fields.append((offs, len(chunk)))
                offs += len(chunk)
                state = self._S_TITLE_SEPARATOR_SPACE
                continue

            elif state == self._S_TITLE_SEPARATOR_SPACE:
                if chunk == '\n':
                    stream.revert(None)
                    state = self._S_EXTRACT_HEADERS
                    continue

                if not chunk.isspace():
                    raise ValueError((
                        'Unexpected chunk: {0}. Expect '
                        'whitespace.').format(chunk))

                offs += len(chunk)
                state = self._S_TITLE_SEPARATOR_FIELD
                continue

            elif state == self._S_EXTRACT_HEADERS:
                if not fields:
                    lines_buffer = list()
                    state = self._S_EMPTY
                    continue

                result = self._extract_field_titles(lines_buffer, fields)
                lines_buffer = list()
                state = self._S_VALUE_LINE
                continue

            elif state == self._S_VALUE_LINE:
                stream.revert(chunk)
                chunk = self._read_until_eol(stream)
                chunk = ''.join(chunk)
                if not chunk:
                    stream.revert(None)
                    state = self._S_STORE_RESULT
                    continue

                self._extract_field_values([chunk], fields, result)
                state = self._S_VALUE_LINE
                continue

            elif state == self._S_STORE_RESULT:
                self.results.append(result)

                result = None
                lines_buffer = list()
                state = self._S_EMPTY
                continue

            else:
                raise RuntimeError('Reach unreachable point.')

    def _extract_field_titles(self, buffer, ranges):
        return _Table(self._extract_data_by_ranges(buffer, ranges))

    def _extract_field_values(self, buffer, ranges, table):
        values = self._extract_data_by_ranges(buffer, ranges)
        table.add(values)

    def _read_until_eol(self, stream):
        result = list()
        try:
            while True:
                chunk = next(stream)
                if chunk == '\n':
                    break
                result.append(chunk)
        except StopIteration:
            pass
        return result

    def _extract_data_by_ranges(self, buffer, ranges):
        result = list()
        for offs, length in ranges:
            offs_end = offs + length

            if offs < 0 or offs_end <= offs:
                raise ValueError(
                    'Invalid extract range offs {0} end {1}'.format(
                        offs, offs_end))

            value = list()
            for line in buffer:
                if len(line) < offs:
                    raise ValueError(
                        'Unable to extract value from {0}, offs {1} end {2}: '
                        'payload too short'.format(line, offs, offs_end))
                # Ignore offs_end, instead use delimiter to extract value
                # Fix for mangled ip-addr values from 'sh vpn ipsec sa'
                # parsing
                value.append(line[offs:].split()[0])
            value = ''.join(value)
            value = value.strip()
            result.append(value)

        return tuple(result)


class _ReversibleIterator(collections.Iterator):
    def __init__(self):
        collections.Iterator.__init__(self)
        self._reverse_storage = list()

    def next(self):
        if self._reverse_storage:
            return self._reverse_storage.pop(0)
        return self._next()

    @abc.abstractmethod
    def _next(self):
        raise StopIteration

    def revert(self, *items):
        self._reverse_storage[:0] = reversed(items)


class TableTokenizer(_ReversibleIterator):
    def __init__(self, stream):
        _ReversibleIterator.__init__(self)
        self.character_stream = _SourceWrapper(stream)

    def _next(self):
        chunk = list()
        char = next(self.character_stream)
        if char == '\n':
            return char

        value_type = type(char)
        if char.isspace():
            end_condition = lambda ch: ch != '\n' and ch.isspace()
        else:
            end_condition = lambda ch: not ch.isspace()

        while end_condition(char):
            chunk.append(char)
            try:
                char = next(self.character_stream)
            except StopIteration:
                break
        else:
            self.character_stream.revert(char)

        return value_type('').join(chunk)


class _SourceWrapper(_ReversibleIterator):
    _chunk = iter(tuple())

    def __init__(self, stream):
        _ReversibleIterator.__init__(self)
        self._stream = iter(stream)

    def _next(self):
        while True:
            try:
                return next(self._chunk)
            except StopIteration:
                chunk = next(self._stream)
                self._chunk = iter(chunk)


class _Table(collections.Iterable):
    def __init__(self, headers):
        collections.Iterable.__init__(self)
        self.headers = tuple(headers)
        self.rows = list()

    def __iter__(self):
        row_factory = functools.partial(_TableRow, self.headers)
        return itertools.imap(row_factory, self.rows)

    def __len__(self):
        return len(self.rows)

    def add(self, payload):
        payload = tuple(payload)
        assert len(payload) == len(self.headers)
        self.rows.append(payload)


class _TableRow(collections.Iterable):
    def __init__(self, headers, payload):
        collections.Iterable.__init__(self)
        if len(headers) != len(payload):
            raise ValueError(
                'Invalid table row: fields number is not equal headers '
                'number.')
        self.headers = headers
        self.payload = payload

    def __iter__(self):
        return itertools.izip(self.headers, self.payload)

    def cell_by_idx(self, idx):
        try:
            value = self.payload[idx]
        except IndexError:
            raise v_exc.TableCellNotFound
        return value

    def cell_by_name(self, name):
        idx = self.headers.index(name)
        return self.cell_by_idx(idx)

    def get_column(self, idx_or_name):
        try:
            if not isinstance(idx_or_name, (int, long)):
                raise ValueError
            value = self.cell_by_idx(idx_or_name)
        except (ValueError, v_exc.TableCellNotFound):
            value = self.cell_by_name(idx_or_name)
        return value
