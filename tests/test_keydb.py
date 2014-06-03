#!/usr/bin/env python

"""
<Program Name>
  test_keydb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'keydb.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import logging

import tuf
import tuf.formats
import tuf.keys
import tuf.keydb
import tuf.log

logger = logging.getLogger('tuf.test_keydb')


# Generate the three keys to use in our test cases.
KEYS = []
for junk in range(3):
  KEYS.append(tuf.keys.generate_rsa_key(2048))



class TestKeydb(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    tuf.keydb.clear_keydb()



  def test_clear_keydb(self):
    # Test condition ensuring 'clear_keydb()' clears the keydb database.
    # Test the length of the keydb before and after adding a key.
    self.assertEqual(0, len(tuf.keydb._keydb_dict))
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    tuf.keydb._keydb_dict[keyid] = rsakey
    self.assertEqual(1, len(tuf.keydb._keydb_dict))
    tuf.keydb.clear_keydb()
    self.assertEqual(0, len(tuf.keydb._keydb_dict))

    # Test condition for unexpected argument.
    self.assertRaises(TypeError, tuf.keydb.clear_keydb, 'unexpected_argument')



  def test_get_key(self):
    # Test conditions using valid 'keyid' arguments.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    tuf.keydb._keydb_dict[keyid] = rsakey
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    tuf.keydb._keydb_dict[keyid2] = rsakey2
    
    self.assertEqual(rsakey, tuf.keydb.get_key(keyid))
    self.assertEqual(rsakey2, tuf.keydb.get_key(keyid2))
    self.assertNotEqual(rsakey2, tuf.keydb.get_key(keyid))
    self.assertNotEqual(rsakey, tuf.keydb.get_key(keyid2))

    # Test conditions using invalid arguments.
    self.assertRaises(tuf.FormatError, tuf.keydb.get_key, None)
    self.assertRaises(tuf.FormatError, tuf.keydb.get_key, 123)
    self.assertRaises(tuf.FormatError, tuf.keydb.get_key, ['123'])
    self.assertRaises(tuf.FormatError, tuf.keydb.get_key, {'keyid': '123'})
    self.assertRaises(tuf.FormatError, tuf.keydb.get_key, '')

    # Test condition using a 'keyid' that has not been added yet.
    keyid3 = KEYS[2]['keyid']
    self.assertRaises(tuf.UnknownKeyError, tuf.keydb.get_key, keyid3)

    

  def test_add_key(self):
    # Test conditions using valid 'keyid' arguments.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    rsakey3 = KEYS[2]
    keyid3 = KEYS[2]['keyid']
    self.assertEqual(None, tuf.keydb.add_key(rsakey, keyid))
    self.assertEqual(None, tuf.keydb.add_key(rsakey2, keyid2))
    self.assertEqual(None, tuf.keydb.add_key(rsakey3))
    
    self.assertEqual(rsakey, tuf.keydb.get_key(keyid))
    self.assertEqual(rsakey2, tuf.keydb.get_key(keyid2))
    self.assertEqual(rsakey3, tuf.keydb.get_key(keyid3))

    # Test conditions using arguments with invalid formats.
    tuf.keydb.clear_keydb()
    rsakey3['keytype'] = 'bad_keytype'

    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, None, keyid)
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, '', keyid)
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, ['123'], keyid)
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, {'a': 'b'}, keyid)
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, rsakey, {'keyid': ''})
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, rsakey, 123)
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, rsakey, False)
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, rsakey, ['keyid'])
    self.assertRaises(tuf.FormatError, tuf.keydb.add_key, rsakey3, keyid3)
    rsakey3['keytype'] = 'rsa' 
    
    # Test conditions where keyid does not match the rsakey.
    self.assertRaises(tuf.Error, tuf.keydb.add_key, rsakey, keyid2)
    self.assertRaises(tuf.Error, tuf.keydb.add_key, rsakey2, keyid)

    # Test conditions using keyids that have already been added.
    tuf.keydb.add_key(rsakey, keyid)
    tuf.keydb.add_key(rsakey2, keyid2)
    self.assertRaises(tuf.KeyAlreadyExistsError, tuf.keydb.add_key, rsakey)
    self.assertRaises(tuf.KeyAlreadyExistsError, tuf.keydb.add_key, rsakey2)


  
  def test_remove_key(self):
    # Test conditions using valid keyids. 
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    rsakey3 = KEYS[2]
    keyid3 = KEYS[2]['keyid']
    tuf.keydb.add_key(rsakey, keyid)
    tuf.keydb.add_key(rsakey2, keyid2)
    tuf.keydb.add_key(rsakey3, keyid3)

    self.assertEqual(None, tuf.keydb.remove_key(keyid))
    self.assertEqual(None, tuf.keydb.remove_key(keyid2))
    
    # Ensure the keys were actually removed.
    self.assertRaises(tuf.UnknownKeyError, tuf.keydb.get_key, keyid)
    self.assertRaises(tuf.UnknownKeyError, tuf.keydb.get_key, keyid2)

    # Test for 'keyid' not in keydb.
    self.assertRaises(tuf.UnknownKeyError, tuf.keydb.remove_key, keyid)
    
    # Test condition for unknown key argument.
    self.assertRaises(tuf.UnknownKeyError, tuf.keydb.remove_key, '1')

    # Test conditions for arguments with invalid formats.
    self.assertRaises(tuf.FormatError, tuf.keydb.remove_key, None)
    self.assertRaises(tuf.FormatError, tuf.keydb.remove_key, '')
    self.assertRaises(tuf.FormatError, tuf.keydb.remove_key, 123)
    self.assertRaises(tuf.FormatError, tuf.keydb.remove_key, ['123'])
    self.assertRaises(tuf.FormatError, tuf.keydb.remove_key, {'bad': '123'})
    self.assertRaises(tuf.Error, tuf.keydb.remove_key, rsakey3) 



  def test_create_keydb_from_root_metadata(self):
    # Test condition using a valid 'root_metadata' argument.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    keydict = {keyid: rsakey, keyid2: rsakey2, keyid: rsakey}

    # Add a duplicate 'keyid' to log/trigger a 'tuf.KeyAlreadyExistsError'
    # block (loading continues). 
    roledict = {'Root': {'keyids': [keyid], 'threshold': 1},
                'Targets': {'keyids': [keyid2], 'threshold': 1}}
    version = 8
    consistent_snapshot = False
    expires = '1985-10-21T01:21:00Z'
    
    tuf.keydb.add_key(rsakey)
    root_metadata = tuf.formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot)
    self.assertEqual(None, tuf.keydb.create_keydb_from_root_metadata(root_metadata))
    
    tuf.keydb.create_keydb_from_root_metadata(root_metadata)
    
    # Ensure 'keyid' and 'keyid2' were added to the keydb database.
    self.assertEqual(rsakey, tuf.keydb.get_key(keyid))
    self.assertEqual(rsakey2, tuf.keydb.get_key(keyid2))

    # Test conditions for arguments with invalid formats.
    self.assertRaises(tuf.FormatError,
                      tuf.keydb.create_keydb_from_root_metadata, None)
    self.assertRaises(tuf.FormatError,
                      tuf.keydb.create_keydb_from_root_metadata, '')
    self.assertRaises(tuf.FormatError,
                      tuf.keydb.create_keydb_from_root_metadata, 123)
    self.assertRaises(tuf.FormatError,
                      tuf.keydb.create_keydb_from_root_metadata, ['123'])
    self.assertRaises(tuf.FormatError,
                      tuf.keydb.create_keydb_from_root_metadata, {'bad': '123'})

    # Test conditions for correctly formatted 'root_metadata' arguments but
    # containing incorrect keyids or key types.  In these conditions, the keys
    # should not be added to the keydb database and a warning should be logged.
    tuf.keydb.clear_keydb()
    
    # 'keyid' does not match 'rsakey2'.
    keydict[keyid] = rsakey2
    
    # Key with invalid keytype.
    rsakey3 = KEYS[2]
    keyid3 = KEYS[2]['keyid']
    rsakey3['keytype'] = 'bad_keytype'
    keydict[keyid3] = rsakey3
    version = 8
    expires = '1985-10-21T01:21:00Z' 
    
    root_metadata = tuf.formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot)
    self.assertEqual(None, tuf.keydb.create_keydb_from_root_metadata(root_metadata))

    # Ensure only 'keyid2' was added to the keydb database.  'keyid' and
    # 'keyid3' should not be stored.
    self.assertEqual(rsakey2, tuf.keydb.get_key(keyid2))
    self.assertRaises(tuf.UnknownKeyError, tuf.keydb.get_key, keyid)
    self.assertRaises(tuf.UnknownKeyError, tuf.keydb.get_key, keyid3)
    rsakey3['keytype'] = 'rsa'



# Run unit test.
if __name__ == '__main__':
  unittest.main()
