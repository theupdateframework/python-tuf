"""
<Program>
  test_mirrors.py

<Author>
  Konstantin Andrianov

<Started>
  March 26, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test mirrors.py module.

"""

import unittest

import tuf
import tuf.formats as formats
import tuf.mirrors as mirrors
import tuf.tests.unittest_toolbox



class TestMirrors(tuf.tests.unittest_toolbox.Modified_TestCase):

  def setUp(self):
    
    tuf.tests.unittest_toolbox.Modified_TestCase.setUp(self)

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
    self.assertEquals(len(mirror_list), 3)
    for mirror, mirror_info in self.mirrors.items():
      url = mirror_info['url_prefix']+'/metadata/release.txt'
      self.assertTrue(url in mirror_list)

    mirror_list = mirrors.get_list_of_mirrors('target', 'a.txt', self.mirrors) 
    self.assertEquals(len(mirror_list), 1)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/targets/a.txt' in \
                    mirror_list)

    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors) 
    self.assertEquals(len(mirror_list), 1)
    self.assertTrue(self.mirrors['mirror1']['url_prefix']+'/targets/a/b' in \
                    mirror_list)

    mirror1 = self.mirrors['mirror1']
    del self.mirrors['mirror1']
    mirror_list = mirrors.get_list_of_mirrors('target', 'a/b', self.mirrors)
    self.assertFalse(mirror_list)
    self.mirrors['mirror1'] = mirror1 

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

    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 'a', ['a'])

    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      'meta', 'a', {'a':'b'})



# Run the unittests
if __name__ == '__main__':
  unittest.main()
