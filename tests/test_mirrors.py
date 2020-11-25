#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program>
  test_mirrors.py

<Author>
  Konstantin Andrianov.

<Started>
  March 26, 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit test for 'mirrors.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import sys

import tuf.mirrors as mirrors
import tuf.unittest_toolbox as unittest_toolbox

from tests import utils

import securesystemslib
import securesystemslib.util


class TestMirrors(unittest_toolbox.Modified_TestCase):

  def setUp(self):

    unittest_toolbox.Modified_TestCase.setUp(self)

    self.mirrors = \
    {'mirror1': {'url_prefix' : 'http://mirror1.com',
                 'metadata_path' : 'metadata',
                 'targets_path' : 'targets'},
     'mirror2': {'url_prefix' : 'http://mirror2.com',
                 'metadata_path' : 'metadata',
                 'targets_path' : 'targets',
                 'confined_target_dirs' : ['targets/release/',
                                            'targets/release/']},
     'mirror3': {'url_prefix' : 'http://mirror3.com',
                 'targets_path' : 'targets',
                 'confined_target_dirs' : ['targets/release/v2/']},
     # confined_target_dirs = [] means that none of the targets on
     # that mirror is available.
     'mirror4': {'url_prefix' : 'http://mirror4.com',
                 'metadata_path' : 'metadata',
                 'confined_target_dirs' : []},
     # Make sure we are testing when confined_target_dirs is [''] which means
     # that all targets are available on that mirror.
     'mirror5': {'url_prefix' : 'http://mirror5.com',
                 'targets_path' : 'targets',
                 'confined_target_dirs' : ['']}
    }



  def test_get_list_of_mirrors(self):
    # Test: Normal case.

    # 1 match: a mirror without target directory confinement
    mirror_list = mirrors.get_list_of_mirrors('target', 'a.txt', self.mirrors)
    self.assertEqual(len(mirror_list), 2)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/targets/a.txt' in \
                    mirror_list)
    self.assertTrue(self.mirrors['mirror5']['url_prefix']+'/targets/a.txt' in \
                    mirror_list)

    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors)
    self.assertEqual(len(mirror_list), 2)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/targets/a/b' in \
                    mirror_list)
    self.assertTrue(self.mirrors['mirror5']['url_prefix']+'/targets/a/b' in \
                    mirror_list)

    # 2 matches: One with non-confined targets and one with matching confinement
    mirror_list = mirrors.get_list_of_mirrors('target', 'release/v2/c', self.mirrors)
    self.assertEqual(len(mirror_list), 3)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/targets/release/v2/c' in \
                    mirror_list)
    self.assertTrue(self.mirrors['mirror3']['url_prefix']+'/targets/release/v2/c' in \
                    mirror_list)
    self.assertTrue(self.mirrors['mirror5']['url_prefix']+'/targets/release/v2/c' in \
                    mirror_list)

    # 3 matches: Metadata found on 3 mirrors
    mirror_list = mirrors.get_list_of_mirrors('meta', 'release.txt', self.mirrors)
    self.assertEqual(len(mirror_list), 3)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/metadata/release.txt' in \
                    mirror_list)
    self.assertTrue(self.mirrors['mirror2']['url_prefix']+'/metadata/release.txt' in \
                    mirror_list)
    self.assertTrue(self.mirrors['mirror4']['url_prefix']+'/metadata/release.txt' in \
                    mirror_list)

    # No matches
    del self.mirrors['mirror1']
    del self.mirrors['mirror5']
    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors)
    self.assertFalse(mirror_list)


    # Test: Invalid 'file_type'.
    self.assertRaises(securesystemslib.exceptions.Error, mirrors.get_list_of_mirrors,
                      self.random_string(), 'a', self.mirrors)

    self.assertRaises(securesystemslib.exceptions.Error, mirrors.get_list_of_mirrors,
                      12345, 'a', self.mirrors)

    # Test: Improperly formatted 'file_path'.
    self.assertRaises(securesystemslib.exceptions.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 12345, self.mirrors)

    # Test: Improperly formatted 'mirrors_dict' object.
    self.assertRaises(securesystemslib.exceptions.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 'a', 12345)

    self.assertRaises(securesystemslib.exceptions.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 'a', ['a'])

    self.assertRaises(securesystemslib.exceptions.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 'a', {'a':'b'})



# Run the unittests
if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
