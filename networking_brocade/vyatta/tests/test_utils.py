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

import testtools

from networking_brocade.vyatta.common import utils


class TestMultiDict(testtools.TestCase):

    def setUp(self):
        super(TestMultiDict, self).setUp()
        # Create from list of tuples
        mapping = [('a', 1), ('b', 2), ('a', 2), ('d', 3),
                   ('a', 1), ('a', 3), ('d', 4), ('c', 3)]
        self.md = utils.MultiDict(mapping)

    def test_init(self):
        md = utils.MultiDict()
        self.assertIsInstance(md, collections.MutableMapping)

        # Create from dict
        mapping = {'a': 1, 'b': 2, 'c': 3}
        md = utils.MultiDict(mapping)
        self.assertEqual(md['a'], 1)
        self.assertEqual(md.getlist('a'), [1])

    def test_getitem(self):
        # __getitem__
        self.assertEqual(self.md['a'], 1)
        self.assertEqual(self.md['c'], 3)
        with testtools.ExpectedException(KeyError):
            self.md['e']

        # get
        self.assertEqual(self.md.get('a'), 1)
        self.assertEqual(self.md.get('e'), None)

        # getlist
        self.assertEqual(self.md.getlist('a'), [1, 2, 1, 3])
        self.assertEqual(self.md.getlist('d'), [3, 4])
        self.assertEqual(self.md.getlist('x'), [])

    def test_setitem(self):
        # __setitem__
        self.md['a'] = 42
        self.assertEqual(self.md['a'], 42)
        self.assertEqual(self.md.getlist('a'), [42])

        # setlist
        self.md.setlist('a', [1, 2, 3])
        self.assertEqual(self.md['a'], 1)
        self.assertEqual(self.md.getlist('a'), [1, 2, 3])

        # check that setlist does not affects initial list
        lst = [1, 2, 3]
        self.md.setlist('a', lst)
        self.md.add('a', 42)
        self.assertEqual(lst, [1, 2, 3])

        # setdefault
        # TODO(asaprykin): Check setdefault without arg
        self.assertEqual(self.md.setdefault('u', 32), 32)
        self.assertEqual(self.md.getlist('u'), [32])

    def test_delitem(self):
        # __delitem__
        del self.md['a']
        self.assertNotIn('a', self.md)
        with testtools.ExpectedException(KeyError):
            del self.md['x']

    def test_setlistdefault(self):

        self.assertEqual(self.md.setlistdefault('a'), [1, 2, 1, 3])
        self.assertEqual(self.md.setlistdefault('d'), [3, 4])

        self.assertEqual(self.md.setlistdefault('u1'), [])
        self.assertEqual(self.md.setlistdefault('u3', [42]), [42])

        with testtools.ExpectedException(TypeError):
            self.md.setlistdefault('u2', False)
        with testtools.ExpectedException(TypeError):
            self.md.setlistdefault('u2', 32)
