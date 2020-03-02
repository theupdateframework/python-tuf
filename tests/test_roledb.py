#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_roledb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit test for 'roledb.py'.
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
import tuf.roledb
import tuf.exceptions
import tuf.log

import securesystemslib
import securesystemslib.keys

logger = logging.getLogger(__name__)


# Generate the three keys to use in our test cases.
KEYS = []
for junk in range(3):
  KEYS.append(securesystemslib.keys.generate_rsa_key(2048))



class TestRoledb(unittest.TestCase):
  def setUp(self):
    tuf.roledb.clear_roledb(clear_all=True)



  def tearDown(self):
    tuf.roledb.clear_roledb(clear_all=True)



  def test_create_roledb(self):
    # Verify that a roledb is created for a named repository.
    self.assertTrue('default' in tuf.roledb._roledb_dict)
    self.assertEqual(1, len(tuf.roledb._roledb_dict))

    repository_name = 'example_repository'
    tuf.roledb.create_roledb(repository_name)
    self.assertEqual(2, len(tuf.roledb._roledb_dict))
    self.assertTrue(repository_name in tuf.roledb._roledb_dict)

    # Test for invalid and improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.create_roledb, 123)
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.create_roledb, 'default')

    # Reset the roledb so that subsequent test functions have access to the
    # original, default roledb.
    tuf.roledb.remove_roledb(repository_name)



  def test_remove_roledb(self):
    # Verify that the named repository is removed from the roledb.
    repository_name = 'example_repository'

    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}

    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.remove_roledb, 'default')
    tuf.roledb.create_roledb(repository_name)

    tuf.roledb.remove_roledb(repository_name)

    # remove_roledb() should not raise an excepion if a non-existent
    # 'repository_name' is specified.
    tuf.roledb.remove_roledb(repository_name)

    # Ensure the roledb is reset to its original, default state.  Subsequent
    # test functions expect only the 'default' repository to exist in the roledb.
    tuf.roledb.remove_roledb(repository_name)



  def test_clear_roledb(self):
    # Test for an empty roledb, a length of 1 after adding a key, and finally
    # an empty roledb after calling 'clear_roledb()'.
    self.assertEqual(0, len(tuf.roledb._roledb_dict['default']))
    tuf.roledb._roledb_dict['default']['Root'] = {'keyids': ['123'], 'threshold': 1}
    self.assertEqual(1, len(tuf.roledb._roledb_dict['default']))
    tuf.roledb.clear_roledb()
    self.assertEqual(0, len(tuf.roledb._roledb_dict['default']))

    # Verify that the roledb can be cleared for a non-default repository.
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}

    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.clear_roledb, repository_name)
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertEqual(roleinfo['keyids'], tuf.roledb.get_role_keyids(rolename, repository_name))
    tuf.roledb.clear_roledb(repository_name)
    self.assertFalse(tuf.roledb.role_exists(rolename, repository_name))

    # Reset the roledb so that subsequent tests have access to the original,
    # default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test condition for invalid and unexpected arguments.
    self.assertRaises(TypeError, tuf.roledb.clear_roledb, 'default', False, 'unexpected_argument')
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.clear_roledb, 123)



  def test_add_role(self):
    # Test conditions where the arguments are valid.
    self.assertEqual(0, len(tuf.roledb._roledb_dict['default']))
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    rolename2 = 'role1'
    self.assertEqual(None, tuf.roledb.add_role(rolename, roleinfo))
    self.assertEqual(1, len(tuf.roledb._roledb_dict['default']))
    tuf.roledb.clear_roledb()
    self.assertEqual(None, tuf.roledb.add_role(rolename, roleinfo))
    self.assertEqual(1, len(tuf.roledb._roledb_dict['default']))

    # Verify that a role can be added to a non-default repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.clear_roledb,
                                            repository_name)
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertEqual(roleinfo['keyids'], tuf.roledb.get_role_keyids(rolename,
                                         repository_name))

    # Reset the roledb so that subsequent tests have access to a default
    # roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.add_role, None, roleinfo)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.add_role, 123, roleinfo)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.add_role, [''], roleinfo)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.add_role, rolename, None)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.add_role, rolename, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.add_role, rolename, [''])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.add_role, rolename, roleinfo, 123)


    # Test condition where the rolename already exists in the role database.
    self.assertRaises(tuf.exceptions.RoleAlreadyExistsError, tuf.roledb.add_role,
                      rolename, roleinfo)

    # Test where the repository name does not exist in the role database.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.add_role,
                      'new_role', roleinfo, 'non-existent')

    # Test conditions for invalid rolenames.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.add_role, ' badrole ',
                      roleinfo)
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.add_role, '/badrole/',
                      roleinfo)





  def test_role_exists(self):
    # Test conditions where the arguments are valid.
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    rolename2 = 'role1'

    self.assertEqual(False, tuf.roledb.role_exists(rolename))
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    self.assertEqual(True, tuf.roledb.role_exists(rolename))
    self.assertEqual(True, tuf.roledb.role_exists(rolename2))

    # Verify that a role can be queried for a non-default repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.clear_roledb, repository_name)
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.role_exists, rolename, repository_name)

    tuf.roledb.create_roledb(repository_name)
    self.assertEqual(False, tuf.roledb.role_exists(rolename, repository_name))
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertTrue(tuf.roledb.role_exists(rolename, repository_name))

    # Reset the roledb so that subsequent tests have access to the original,
    # default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.role_exists, None)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.role_exists, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.role_exists, ['rolename'])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.role_exists, rolename, 123)

    # Test conditions for invalid rolenames.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.role_exists, '')
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.role_exists, ' badrole ')
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.role_exists, '/badrole/')





  def test_remove_role(self):
    # Test conditions where the arguments are valid.
    rolename = 'targets'
    rolename2 = 'release'
    rolename3 = 'django'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    roleinfo2 = {'keyids': ['123'], 'threshold': 1, 'delegations':
      {'roles': [{'name': 'django', 'keyids': ['456'], 'threshold': 1}],
       'keys': {'456': {'keytype': 'rsa', 'keyval': {'public': '456'}},
      }}}

    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)
    tuf.roledb.add_role(rolename3, roleinfo)

    self.assertEqual(None, tuf.roledb.remove_role(rolename))
    self.assertEqual(True, rolename not in tuf.roledb._roledb_dict)

    # Verify that a role can be removed from a non-default repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.remove_role, rolename, repository_name)
    tuf.roledb.create_roledb(repository_name)

    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertEqual(roleinfo['keyids'], tuf.roledb.get_role_keyids(rolename, repository_name))
    self.assertEqual(None, tuf.roledb.remove_role(rolename, repository_name))

    # Verify that a role cannot be removed from a non-existent repository name.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.remove_role, rolename, 'non-existent')

    # Reset the roledb so that subsequent test have access to the original,
    # default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where removing a role does not cause the removal of its
    # delegated roles.  The 'django' role should now only exist (after the
    # removal of 'targets' in the previous test condition, and the removal
    # of 'release' in the remove_role() call next.
    self.assertEqual(None, tuf.roledb.remove_role(rolename2))
    self.assertEqual(1, len(tuf.roledb._roledb_dict['default']))

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.remove_role)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.remove_role, rolename, 123)




  def test_get_rolenames(self):
    # Test conditions where the arguments are valid.
    rolename = 'targets'
    rolename2 = 'role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    self.assertEqual([], tuf.roledb.get_rolenames())
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    self.assertEqual(set(['targets', 'role1']),
                     set(tuf.roledb.get_rolenames()))

    # Verify that rolenames can be retrieved for a role in a non-default
    # repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_rolenames, repository_name)
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    tuf.roledb.add_role(rolename2, roleinfo, repository_name)

    self.assertEqual(set(['targets', 'role1']),
                     set(tuf.roledb.get_rolenames()))

    # Reset the roledb so that subsequent tests have access to the original,
    # default repository.
    tuf.roledb.remove_roledb(repository_name)

    # Test for invalid or improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_rolenames, 123)



  def test_get_role_info(self):
    # Test conditions where the arguments are valid.
    rolename = 'targets'
    rolename2 = 'role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    roleinfo2 = {'keyids': ['456', '789'], 'threshold': 2}
    self.assertRaises(tuf.exceptions.UnknownRoleError, tuf.roledb.get_roleinfo, rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)

    self.assertEqual(roleinfo, tuf.roledb.get_roleinfo(rolename))
    self.assertEqual(roleinfo2, tuf.roledb.get_roleinfo(rolename2))

    # Verify that a roleinfo can be retrieved for a role in a non-default
    # repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_roleinfo,
                                            rolename, repository_name)

    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertEqual(roleinfo, tuf.roledb.get_roleinfo(rolename, repository_name))

    # Verify that a roleinfo cannot be retrieved for a non-existent repository
    # name.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_roleinfo, rolename,
                      'non-existent')

    # Reset the roledb so that subsequent tests have access to the original,
    # default roledb
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where the arguments are improperly formatted, contain
    # invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_roleinfo)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_roleinfo, rolename, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_roleinfo, 123)



  def test_get_role_keyids(self):
    # Test conditions where the arguments are valid.
    rolename = 'targets'
    rolename2 = 'role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    roleinfo2 = {'keyids': ['456', '789'], 'threshold': 2}
    self.assertRaises(tuf.exceptions.UnknownRoleError, tuf.roledb.get_role_keyids, rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)

    self.assertEqual(['123'], tuf.roledb.get_role_keyids(rolename))
    self.assertEqual(set(['456', '789']),
                     set(tuf.roledb.get_role_keyids(rolename2)))

    # Verify that the role keyids can be retrieved for a role in a non-default
    # repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_role_keyids,
                                            rolename, repository_name)
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertEqual(['123'], tuf.roledb.get_role_keyids(rolename, repository_name))

    # Verify that rolekeyids cannot be retrieved from a non-existent repository
    # name.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_role_keyids, rolename,
                      'non-existent')

    # Reset the roledb so that subsequent tests have access to the original,
    # default roledb
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where the arguments are improperly formatted, contain
    # invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_role_keyids)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_role_keyids, rolename, 123)



  def test_get_role_threshold(self):
    # Test conditions where the arguments are valid.
    rolename = 'targets'
    rolename2 = 'role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    roleinfo2 = {'keyids': ['456', '789'], 'threshold': 2}
    self.assertRaises(tuf.exceptions.UnknownRoleError, tuf.roledb.get_role_threshold, rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)

    self.assertEqual(1, tuf.roledb.get_role_threshold(rolename))
    self.assertEqual(2, tuf.roledb.get_role_threshold(rolename2))

    # Verify that the threshold can be retrieved for a role in a non-default
    # repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_role_threshold,
                                            rolename, repository_name)
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertEqual(roleinfo['threshold'], tuf.roledb.get_role_threshold(rolename, repository_name))

    # Verify that a role's threshold cannot be retrieved from a non-existent
    # repository name.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_role_threshold,
                      rolename, 'non-existent')

    # Reset the roledb so that subsequent tests have access to the original,
    # default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_role_threshold)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_role_threshold, rolename, 123)


  def test_get_role_paths(self):
    # Test conditions where the arguments are valid.
    rolename = 'targets'
    rolename2 = 'role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    paths = ['a/b', 'c/d']
    roleinfo2 = {'keyids': ['456', '789'], 'threshold': 2, 'paths': paths}
    self.assertRaises(tuf.exceptions.UnknownRoleError, tuf.roledb.get_role_paths, rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)

    self.assertEqual({}, tuf.roledb.get_role_paths(rolename))
    self.assertEqual(paths, tuf.roledb.get_role_paths(rolename2))

    # Verify that role paths can be queried for roles in non-default
    # repositories.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_role_paths,
                                            rolename, repository_name)

    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename2, roleinfo2, repository_name)
    self.assertEqual(roleinfo2['paths'], tuf.roledb.get_role_paths(rolename2,
                                         repository_name))

    # Reset the roledb so that subsequent roles have access to the original,
    # default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_role_paths)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_role_paths, rolename, 123)



  def test_get_delegated_rolenames(self):
    # Test conditions where the arguments are valid.
    rolename = 'unclaimed'
    rolename2 = 'django'
    rolename3 = 'release'
    rolename4 = 'tuf'

    # unclaimed's roleinfo.
    roleinfo = {'keyids': ['123'], 'threshold': 1, 'delegations':
      {'roles': [{'name': 'django', 'keyids': ['456'], 'threshold': 1},
                 {'name': 'tuf', 'keyids': ['888'], 'threshold': 1}],
      'keys': {'456': {'keytype': 'rsa', 'keyval': {'public': '456'}},
      }}}

    # django's roleinfo.
    roleinfo2 = {'keyids': ['456'], 'threshold': 1, 'delegations':
      {'roles': [{'name': 'release', 'keyids': ['789'], 'threshold': 1}],
      'keys': {'789': {'keytype': 'rsa', 'keyval': {'public': '789'}},
      }}}

    # release's roleinfo.
    roleinfo3 = {'keyids': ['789'], 'threshold': 1, 'delegations':
      {'roles': [],
      'keys': {}}}

    # tuf's roleinfo.
    roleinfo4 = {'keyids': ['888'], 'threshold': 1, 'delegations':
      {'roles': [],
      'keys': {}}}

    self.assertRaises(tuf.exceptions.UnknownRoleError, tuf.roledb.get_delegated_rolenames,
                      rolename)

    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)
    tuf.roledb.add_role(rolename3, roleinfo3)
    tuf.roledb.add_role(rolename4, roleinfo4)

    self.assertEqual(set(['django', 'tuf']),
                     set(tuf.roledb.get_delegated_rolenames(rolename)))

    self.assertEqual(set(['release']),
                     set(tuf.roledb.get_delegated_rolenames(rolename2)))

    self.assertEqual(set([]),
                     set(tuf.roledb.get_delegated_rolenames(rolename3)))

    self.assertEqual(set([]),
                     set(tuf.roledb.get_delegated_rolenames(rolename4)))

    # Verify that the delegated rolenames of a role in a non-default
    # repository can be accessed.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_delegated_rolenames,
                                           rolename, repository_name)
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    self.assertEqual(set(['django', 'tuf']),
                     set(tuf.roledb.get_delegated_rolenames(rolename, repository_name)))

    # Reset the roledb so that subsequent tests have access to the original,
    # default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_delegated_rolenames)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_delegated_rolenames, rolename, 123)



  def test_create_roledb_from_root_metadata(self):
    # Test condition using a valid 'root_metadata' argument.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    rsakey3 = KEYS[2]
    keyid3 = KEYS[2]['keyid']
    keydict = {keyid: rsakey, keyid2: rsakey2}
    roledict = {'root': {'keyids': [keyid], 'threshold': 1},
                'targets': {'keyids': [keyid2], 'threshold': 1}}
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

    self.assertEqual(None,
                     tuf.roledb.create_roledb_from_root_metadata(root_metadata))

    # Ensure 'Root' and 'Targets' were added to the role database.
    self.assertEqual([keyid], tuf.roledb.get_role_keyids('root'))
    self.assertEqual([keyid2], tuf.roledb.get_role_keyids('targets'))

    # Test that a roledb is created for a non-default repository.
    repository_name = 'example_repository'
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.clear_roledb,
                                            repository_name)
    tuf.roledb.create_roledb_from_root_metadata(root_metadata, repository_name)
    self.assertEqual([keyid], tuf.roledb.get_role_keyids('root', repository_name))
    self.assertEqual([keyid2], tuf.roledb.get_role_keyids('targets', repository_name))

    # Remove the example repository added to the roledb so that subsequent
    # tests have access to an original, default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test conditions for arguments with invalid formats.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, None)
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, '')
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, ['123'])
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, {'bad': '123'})
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, root_metadata, 123)

    # Verify that the expected roles of a Root file are properly loaded.
    tuf.roledb.clear_roledb()
    roledict = {'root': {'keyids': [keyid], 'threshold': 1},
                'release': {'keyids': [keyid3], 'threshold': 1}}
    version = 8

    # Add a third key for 'release'.
    keydict[keyid3] = rsakey3

    # Generate 'root_metadata' to verify that 'release' and 'root' are added
    # to the role database.

    root_metadata = tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.ROOT_SCHEMA,
        _type='root',
        spec_version='1.0.0',
        version=version,
        expires=expires,
        keys=keydict,
        roles=roledict,
        consistent_snapshot=consistent_snapshot)

    self.assertEqual(None,
        tuf.roledb.create_roledb_from_root_metadata(root_metadata))

    # Ensure only 'root' and 'release' were added to the role database.
    self.assertEqual(2, len(tuf.roledb._roledb_dict['default']))
    self.assertEqual(True, tuf.roledb.role_exists('root'))
    self.assertEqual(True, tuf.roledb.role_exists('release'))



  def test_update_roleinfo(self):
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo)

    # Test normal case.
    tuf.roledb.update_roleinfo(rolename, roleinfo)

    # Verify that a roleinfo can be updated for a role in a non-default
    # repository.
    repository_name = 'example_repository'
    mark_role_as_dirty = True
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.clear_roledb, repository_name)
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo, repository_name)
    tuf.roledb.update_roleinfo(rolename, roleinfo, mark_role_as_dirty, repository_name)
    self.assertEqual(roleinfo['keyids'], tuf.roledb.get_role_keyids(rolename, repository_name))

    # Reset the roledb so that subsequent tests can access the default roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test for an unknown role.
    self.assertRaises(tuf.exceptions.UnknownRoleError, tuf.roledb.update_roleinfo,
                      'unknown_rolename', roleinfo)

    # Verify that a roleinfo cannot be updated to a non-existent repository
    # name.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.update_roleinfo,
                      'new_rolename', roleinfo, False, 'non-existent')

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.update_roleinfo, 1, roleinfo)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.update_roleinfo, rolename, 1)

    repository_name = 'example_repository'
    mark_role_as_dirty = True
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.update_roleinfo, rolename,
                                       roleinfo, 1, repository_name)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.update_roleinfo,
                                       rolename, mark_role_as_dirty, 123)



  def test_get_dirty_roles(self):
    # Verify that the dirty roles of a role are returned.
    rolename = 'targets'
    roleinfo1 = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo1)
    roleinfo2 = {'keyids': ['123'], 'threshold': 2}
    mark_role_as_dirty = True
    tuf.roledb.update_roleinfo(rolename, roleinfo2, mark_role_as_dirty)
    # Note: The 'default' repository is searched if the repository name is
    # not given to get_dirty_roles().
    self.assertEqual([rolename], tuf.roledb.get_dirty_roles())

    # Verify that a list of dirty roles is returned for a non-default
    # repository.
    repository_name = 'example_repository'
    tuf.roledb.create_roledb(repository_name)
    tuf.roledb.add_role(rolename, roleinfo1, repository_name)
    tuf.roledb.update_roleinfo(rolename, roleinfo2, mark_role_as_dirty, repository_name)
    self.assertEqual([rolename], tuf.roledb.get_dirty_roles(repository_name))

    # Verify that dirty roles are not returned for a non-existent repository.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.get_dirty_roles, 'non-existent')

    # Reset the roledb so that subsequent tests have access to a default
    # roledb.
    tuf.roledb.remove_roledb(repository_name)

    # Test for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.roledb.get_dirty_roles, 123)



  def test_mark_dirty(self):
    # Add a dirty role to roledb.
    rolename = 'targets'
    roleinfo1 = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo1)
    rolename2 = 'dirty_role'
    roleinfo2 = {'keyids': ['123'], 'threshold': 2}
    mark_role_as_dirty = True
    tuf.roledb.update_roleinfo(rolename, roleinfo1, mark_role_as_dirty)
    # Note: The 'default' repository is searched if the repository name is
    # not given to get_dirty_roles().
    self.assertEqual([rolename], tuf.roledb.get_dirty_roles())

    tuf.roledb.mark_dirty(['dirty_role'])
    self.assertEqual([rolename2, rolename], tuf.roledb.get_dirty_roles())

    # Verify that a role cannot be marked as dirty for a non-existent
    # repository.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.mark_dirty,
                      ['dirty_role'], 'non-existent')



  def test_unmark_dirty(self):
    # Add a dirty role to roledb.
    rolename = 'targets'
    roleinfo1 = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo1)
    rolename2 = 'dirty_role'
    roleinfo2 = {'keyids': ['123'], 'threshold': 2}
    tuf.roledb.add_role(rolename2, roleinfo2)
    mark_role_as_dirty = True
    tuf.roledb.update_roleinfo(rolename, roleinfo1, mark_role_as_dirty)
    # Note: The 'default' repository is searched if the repository name is
    # not given to get_dirty_roles().
    self.assertEqual([rolename], tuf.roledb.get_dirty_roles())
    tuf.roledb.update_roleinfo(rolename2, roleinfo2, mark_role_as_dirty)

    tuf.roledb.unmark_dirty(['dirty_role'])
    self.assertEqual([rolename], tuf.roledb.get_dirty_roles())
    tuf.roledb.unmark_dirty(['targets'])
    self.assertEqual([], tuf.roledb.get_dirty_roles())

    # What happens for a role that isn't dirty?  unmark_dirty() should just
    # log a message.
    tuf.roledb.unmark_dirty(['unknown_role'])

    # Verify that a role cannot be unmarked as dirty for a non-existent
    # repository.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, tuf.roledb.unmark_dirty,
                      ['dirty_role'], 'non-existent')


  def _test_rolename(self, test_function):
    # Private function that tests the 'rolename' argument of 'test_function'
    # for format, invalid name, and unknown role exceptions.

    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(securesystemslib.exceptions.FormatError, test_function, None)
    self.assertRaises(securesystemslib.exceptions.FormatError, test_function, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, test_function, ['rolename'])
    self.assertRaises(securesystemslib.exceptions.FormatError, test_function, {'a': 'b'})
    self.assertRaises(securesystemslib.exceptions.FormatError, test_function, ('a', 'b'))
    self.assertRaises(securesystemslib.exceptions.FormatError, test_function, True)

    # Test condition where the 'rolename' has not been added to the role database.
    self.assertRaises(tuf.exceptions.UnknownRoleError, test_function, 'badrole')

    # Test conditions for invalid rolenames.
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, test_function, '')
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, test_function, ' badrole ')
    self.assertRaises(securesystemslib.exceptions.InvalidNameError, test_function, '/badrole/')



def setUpModule():
  # setUpModule() is called before any test cases run.
  # Ensure the roledb has not been modified by a previous test, which may
  # affect assumptions (i.e., empty roledb) made by the tests cases in this
  # unit test.
  tuf.roledb.clear_roledb()

def tearDownModule():
  # tearDownModule() is called after all the tests have run.
  # Ensure we clean up roledb.  Courtesy is contagious, and it begins with
  # test_roledb.py.
  tuf.roledb.clear_roledb()



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
