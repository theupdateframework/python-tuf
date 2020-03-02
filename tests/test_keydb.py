#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_keydb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

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
import securesystemslib.keys
import securesystemslib.settings
import tuf.keydb
import tuf.log

logger = logging.getLogger(__name__)


# Generate the three keys to use in our test cases.
KEYS = []
for junk in range(3):
  rsa_key = securesystemslib.keys.generate_rsa_key(2048)
  rsa_key['keyid_hash_algorithms'] = securesystemslib.settings.HASH_ALGORITHMS
  KEYS.append(rsa_key)



class TestKeydb(unittest.TestCase):
  def setUp(self):
    tuf.keydb.clear_keydb(clear_all=True)



  def tearDown(self):
    tuf.keydb.clear_keydb(clear_all=True)



  def test_create_keydb(self):
    # Test condition for normal behaviour.
    repository_name = 'example_repository'

    # The keydb dictionary should contain only the 'default' repository entry.
    self.assertTrue('default' in tuf.keydb._keydb_dict)
    self.assertEqual(1, len(tuf.keydb._keydb_dict))


    tuf.keydb.create_keydb(repository_name)
    self.assertEqual(2, len(tuf.keydb._keydb_dict))

    # Verify that a keydb cannot be created for a name that already exists.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.keydb.create_keydb, repository_name)

    # Ensure that the key database for 'example_repository' is deleted so that
    # the key database is returned to its original, default state.
    tuf.keydb.remove_keydb(repository_name)



  def test_remove_keydb(self):
    # Test condition for expected behaviour.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']

    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.keydb.remove_keydb, 'default')

    tuf.keydb.create_keydb(repository_name)
    tuf.keydb.remove_keydb(repository_name)

    # tuf.keydb.remove_keydb() logs a warning if a keydb for a non-existent
    # repository is specified.
    tuf.keydb.remove_keydb(repository_name)

    # Test condition for improperly formatted argument, and unexpected argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.remove_keydb, 123)
    self.assertRaises(TypeError, tuf.keydb.remove_keydb, rsakey, 123)



  def test_clear_keydb(self):
    # Test condition ensuring 'clear_keydb()' clears the keydb database.
    # Test the length of the keydb before and after adding a key.
    self.assertEqual(0, len(tuf.keydb._keydb_dict['default']))
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    tuf.keydb._keydb_dict['default'][keyid] = rsakey
    self.assertEqual(1, len(tuf.keydb._keydb_dict['default']))
    tuf.keydb.clear_keydb()
    self.assertEqual(0, len(tuf.keydb._keydb_dict['default']))

    # Test condition for unexpected argument.
    self.assertRaises(TypeError, tuf.keydb.clear_keydb, 'default', False, 'unexpected_argument')

    # Test condition for improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.clear_keydb, 0)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.clear_keydb, 'default', 0)

    # Test condition for non-existent repository name.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.keydb.clear_keydb, 'non-existent')

    # Test condition for keys added to a non-default key database.  Unlike the
    # test conditions above, this test makes use of the public functions
    # add_key(), create_keydb(), and get_key() to more easily verify
    # clear_keydb()'s behaviour.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    repository_name = 'example_repository'
    tuf.keydb.create_keydb(repository_name)
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid, repository_name)
    tuf.keydb.add_key(rsakey, keyid, repository_name)
    self.assertEqual(rsakey, tuf.keydb.get_key(keyid, repository_name))

    tuf.keydb.clear_keydb(repository_name)
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid, repository_name)

    # Remove 'repository_name' from the key database to revert it back to its
    # original, default state (i.e., only the 'default' repository exists).
    tuf.keydb.remove_keydb(repository_name)



  def test_get_key(self):
    # Test conditions using valid 'keyid' arguments.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    tuf.keydb._keydb_dict['default'][keyid] = rsakey
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    tuf.keydb._keydb_dict['default'][keyid2] = rsakey2

    self.assertEqual(rsakey, tuf.keydb.get_key(keyid))
    self.assertEqual(rsakey2, tuf.keydb.get_key(keyid2))
    self.assertNotEqual(rsakey2, tuf.keydb.get_key(keyid))
    self.assertNotEqual(rsakey, tuf.keydb.get_key(keyid2))

    # Test conditions using invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.get_key, None)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.get_key, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.get_key, ['123'])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.get_key, {'keyid': '123'})
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.get_key, '')
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.get_key, keyid, 123)

    # Test condition using a 'keyid' that has not been added yet.
    keyid3 = KEYS[2]['keyid']
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid3)

    # Test condition for a key added to a non-default repository.
    repository_name = 'example_repository'
    rsakey3 = KEYS[2]
    tuf.keydb.create_keydb(repository_name)
    tuf.keydb.add_key(rsakey3, keyid3, repository_name)

    # Test condition for a key added to a non-existent repository.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.keydb.get_key,
                      keyid, 'non-existent')

    # Verify that 'rsakey3' is added to the expected repository name.
    # If not supplied, the 'default' repository name is searched.
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid3)
    self.assertEqual(rsakey3, tuf.keydb.get_key(keyid3, repository_name))

    # Remove the 'example_repository' so that other test functions have access
    # to a default state of the keydb.
    tuf.keydb.remove_keydb(repository_name)



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

    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, None, keyid)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, '', keyid)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, ['123'], keyid)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, {'a': 'b'}, keyid)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, rsakey, {'keyid': ''})
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, rsakey, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, rsakey, False)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, rsakey, ['keyid'])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, rsakey3, keyid3)
    rsakey3['keytype'] = 'rsa'
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.add_key, rsakey3, keyid3, 123)

    # Test conditions where keyid does not match the rsakey.
    self.assertRaises(securesystemslib.exceptions.Error, tuf.keydb.add_key, rsakey, keyid2)
    self.assertRaises(securesystemslib.exceptions.Error, tuf.keydb.add_key, rsakey2, keyid)

    # Test conditions using keyids that have already been added.
    tuf.keydb.add_key(rsakey, keyid)
    tuf.keydb.add_key(rsakey2, keyid2)
    self.assertRaises(tuf.exceptions.KeyAlreadyExistsError, tuf.keydb.add_key, rsakey)
    self.assertRaises(tuf.exceptions.KeyAlreadyExistsError, tuf.keydb.add_key, rsakey2)

    # Test condition for key added to the keydb of a non-default repository.
    repository_name = 'example_repository'
    tuf.keydb.create_keydb(repository_name)
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid3, repository_name)
    tuf.keydb.add_key(rsakey3, keyid3, repository_name)
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid3)
    self.assertEqual(rsakey3, tuf.keydb.get_key(keyid3, repository_name))

    # Test condition for key added to the keydb of a non-existent repository.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.keydb.add_key,
                      rsakey3, keyid3, 'non-existent')

    # Reset the keydb to its original, default state.  Other test functions
    # expect only the 'default' repository to exist.
    tuf.keydb.remove_keydb(repository_name)



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
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid)
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid2)

    # Test for 'keyid' not in keydb.
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.remove_key, keyid)

    # Test condition for unknown key argument.
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.remove_key, '1')

    # Test condition for removal of keys from a non-default repository.
    repository_name = 'example_repository'
    tuf.keydb.create_keydb(repository_name)
    tuf.keydb.add_key(rsakey, keyid, repository_name)
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.keydb.remove_key, keyid, 'non-existent')
    tuf.keydb.remove_key(keyid, repository_name)
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.remove_key, keyid, repository_name)

    # Reset the keydb so that subsequent tests have access to the original,
    # default keydb.
    tuf.keydb.remove_keydb(repository_name)

    # Test conditions for arguments with invalid formats.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.remove_key, None)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.remove_key, '')
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.remove_key, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.remove_key, ['123'])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.remove_key, keyid, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.keydb.remove_key, {'bad': '123'})
    self.assertRaises(securesystemslib.exceptions.Error, tuf.keydb.remove_key, rsakey3)



  def test_create_keydb_from_root_metadata(self):
    # Test condition using a valid 'root_metadata' argument.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']

    keydict = {keyid: rsakey, keyid2: rsakey2}

    roledict = {'Root': {'keyids': [keyid], 'threshold': 1},
                'Targets': {'keyids': [keyid2, keyid], 'threshold': 1}}
    version = 8
    consistent_snapshot = False
    expires = '1985-10-21T01:21:00Z'

    root_metadata = tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.ROOT_SCHEMA,
        _type='root',
        spec_version='1.0.0',
        version=version,
        expires=expires,
        keys=keydict,
        roles=roledict,
        consistent_snapshot=consistent_snapshot)

    self.assertEqual(None, tuf.keydb.create_keydb_from_root_metadata(root_metadata))
    tuf.keydb.create_keydb_from_root_metadata(root_metadata)

    # Ensure 'keyid' and 'keyid2' were added to the keydb database.
    self.assertEqual(rsakey, tuf.keydb.get_key(keyid))
    self.assertEqual(rsakey2, tuf.keydb.get_key(keyid2))

    # Verify that the keydb is populated for a non-default repository.
    repository_name = 'example_repository'
    tuf.keydb.create_keydb_from_root_metadata(root_metadata, repository_name)

    # Test conditions for arguments with invalid formats.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        tuf.keydb.create_keydb_from_root_metadata, None)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        tuf.keydb.create_keydb_from_root_metadata, '')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        tuf.keydb.create_keydb_from_root_metadata, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        tuf.keydb.create_keydb_from_root_metadata, ['123'])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        tuf.keydb.create_keydb_from_root_metadata, {'bad': '123'})
    self.assertRaises(securesystemslib.exceptions.FormatError,
        tuf.keydb.create_keydb_from_root_metadata, root_metadata, 123)

    # Verify that a keydb cannot be created for a non-existent repository name.
    tuf.keydb.create_keydb_from_root_metadata(root_metadata, 'non-existent')

    # Remove the 'non-existent' and 'example_repository' key database so that
    # subsequent test functions have access to a default keydb.
    tuf.keydb.remove_keydb(repository_name)
    tuf.keydb.remove_keydb('non-existent')


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

    root_metadata = tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.ROOT_SCHEMA,
        _type='root',
        spec_version='1.0.0',
        version=version,
        expires=expires,
        keys=keydict,
        roles=roledict,
        consistent_snapshot=consistent_snapshot)

    self.assertEqual(None, tuf.keydb.create_keydb_from_root_metadata(root_metadata))

    # Ensure only 'keyid2' was added to the keydb database.  'keyid' and
    # 'keyid3' should not be stored.
    self.assertEqual(rsakey2, tuf.keydb.get_key(keyid2))
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid)
    self.assertRaises(tuf.exceptions.UnknownKeyError, tuf.keydb.get_key, keyid3)
    rsakey3['keytype'] = 'rsa'



# Run unit test.
if __name__ == '__main__':
  unittest.main()
