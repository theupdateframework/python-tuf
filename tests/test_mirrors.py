#!/usr/bin/env python

"""
<Program>
  test_mirrors.py

<Author>
  Konstantin Andrianov.

<Started>
  March 26, 2012.

<Copyright>
  See LICENSE for licensing information.

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
import tuf.formats as formats
import tuf.mirrors as mirrors
import tuf.unittest_toolbox as unittest_toolbox

import six


class TestMirrors(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    
    unittest_toolbox.Modified_TestCase.setUp(self)


    self.mirrors = [
        'http://mirror1.com', 'http://mirror2.com', 'http://mirror3.com']

    # OLD:
    # self.mirrors = \
    # {'mirror1': {'url_prefix' : 'http://mirror1.com',
    #              'metadata_path' : 'metadata',
    #              'targets_path' : 'targets',
    #              'confined_target_dirs' : ['']},
    #  'mirror2': {'url_prefix' : 'http://mirror2.com',
    #              'metadata_path' : 'metadata',
    #              'targets_path' : 'targets',
    #              'confined_target_dirs' : ['targets/release/',
    #                                         'targets/release/']},
    #  'mirror3': {'url_prefix' : 'http://mirror3.com',
    #              'metadata_path' : 'metadata',
    #              'targets_path' : 'targets',
    #              'confined_target_dirs' : ['targets/release/',
    #                                         'targets/release/']}}



  def test_get_list_of_mirrors(self):
    # Test: Normal case.
    mirror_list = mirrors.get_list_of_mirrors('meta', 'release.txt', self.mirrors) 
    self.assertEqual(len(mirror_list), 3)
    for mirror_info in self.mirrors:
      url = mirror_info + '/metadata/release.txt'
      self.assertTrue(url in mirror_list)

    # mirror_list = mirrors.get_list_of_mirrors('target', 'a.txt', self.mirrors) 
    # self.assertEqual(len(mirror_list), 1)
    # self.assertTrue(self.mirrors[0] + '/targets/a.txt' in mirror_list)

    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors) 
    self.assertEqual(len(mirror_list), 3)
    self.assertTrue(self.mirrors[0] + '/targets/a/b' in mirror_list)

    mirror1 = self.mirrors[0]
    del self.mirrors[0]
    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors)
    self.assertEqual(len(mirror_list), 2)
    self.mirrors[0] = mirror1 

    # Test: Invalid 'file_type'.
    self.assertRaises(tuf.Error, mirrors.get_list_of_mirrors,
                      self.random_string(), 'a', self.mirrors)

    self.assertRaises(tuf.Error, mirrors.get_list_of_mirrors,
                      12345, 'a', self.mirrors)

    # Test: Improperly formatted 'file_path'.
    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 12345, self.mirrors)

    # Test: Improperly formatted 'mirrors_dict' object.
    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 'a', 12345)

    # self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
    #                   'meta', 'a', ['a'])

    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 'a', {'a':'b'})

    # Ensure that use of the old format raises an error.
    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
      'meta',
      'a',
      {'mirror1': {'url_prefix' : 'http://mirror1.com',
                  'metadata_path' : 'metadata',
                  'targets_path' : 'targets',
                  'confined_target_dirs' : ['']}})


# Run the unittests
if __name__ == '__main__':
  unittest.main()
