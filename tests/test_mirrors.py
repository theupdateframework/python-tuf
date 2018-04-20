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

import tuf
import tuf.mirrors as mirrors
import tuf.unittest_toolbox as unittest_toolbox

import securesystemslib
import securesystemslib.util
import six


class TestMirrors(unittest_toolbox.Modified_TestCase):

  def setUp(self):

    unittest_toolbox.Modified_TestCase.setUp(self)

    self.mirrors = \
    {'mirror1': {'url_prefix' : 'http://mirror1.com',
                 'metadata_path' : 'metadata',
                 'targets_path' : 'targets',
                 'confined_target_dirs' : ['']},
     'mirror2': {'url_prefix' : 'http://mirror2.com',
                 'metadata_path' : 'metadata',
                 'targets_path' : 'targets',
                 'confined_target_dirs' : ['targets/release/',
                                            'targets/release/']},
     'mirror3': {'url_prefix' : 'http://mirror3.com',
                 'metadata_path' : 'metadata',
                 'targets_path' : 'targets',
                 'confined_target_dirs' : ['targets/release/',
                                            'targets/release/']}}



  def test_get_list_of_mirrors(self):
    # Test: Normal case.
    mirror_list = mirrors.get_list_of_mirrors('meta', 'release.txt', self.mirrors)
    self.assertEqual(len(mirror_list), 3)
    for mirror, mirror_info in six.iteritems(self.mirrors):
      url = mirror_info['url_prefix'] + '/metadata/release.txt'
      self.assertTrue(url in mirror_list)

    mirror_list = mirrors.get_list_of_mirrors('target', 'a.txt', self.mirrors)
    self.assertEqual(len(mirror_list), 1)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/targets/a.txt' in \
                    mirror_list)

    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors)
    self.assertEqual(len(mirror_list), 1)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/targets/a/b' in \
                    mirror_list)

    mirror1 = self.mirrors['mirror1']
    del self.mirrors['mirror1']
    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors)
    self.assertFalse(mirror_list)
    self.mirrors['mirror1'] = mirror1

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
  unittest.main()
