#!/usr/bin/env python

"""
<Program Name>
  test_roledb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE for licensing information.

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
import tuf.keys
import tuf.roledb
import tuf.log

logger = logging.getLogger('tuf.test_roledb')


# Generate the three keys to use in our test cases.
KEYS = []
for junk in range(3):
  KEYS.append(tuf.keys.generate_rsa_key(2048))



class TestRoledb(unittest.TestCase):
  def setUp(self):
    pass 



  def tearDown(self):
    tuf.roledb.clear_roledb()



  def test_clear_roledb(self):
    # Test for an empty roledb, a length of 1 after adding a key, and finally
    # an empty roledb after calling 'clear_roledb()'.
    self.assertEqual(0, len(tuf.roledb._roledb_dict))
    tuf.roledb._roledb_dict['Root'] = {'keyids': ['123'], 'threshold': 1}
    self.assertEqual(1, len(tuf.roledb._roledb_dict))
    tuf.roledb.clear_roledb()
    self.assertEqual(0, len(tuf.roledb._roledb_dict))

    # Test condition for unexpected argument.
    self.assertRaises(TypeError, tuf.roledb.clear_roledb, 'unexpected_argument')



  def test_add_role(self):
    # Test conditions where the arguments are valid.
    self.assertEqual(0, len(tuf.roledb._roledb_dict)) 
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    rolename2 = 'targets/role1'
    self.assertEqual(None, tuf.roledb.add_role(rolename, roleinfo))
    self.assertEqual(1, len(tuf.roledb._roledb_dict))
    tuf.roledb.clear_roledb()
    self.assertEqual(None, tuf.roledb.add_role(rolename, roleinfo, True))
    self.assertEqual(1, len(tuf.roledb._roledb_dict))

    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, None, roleinfo) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, 123, roleinfo) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, [''], roleinfo) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, rolename, None) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, rolename, 123)
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, rolename, [''])
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role,
                      rolename, roleinfo, 123)
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, rolename,
                      roleinfo, None)

    # Test condition where the role already exists in the role database.
    self.assertRaises(tuf.RoleAlreadyExistsError, tuf.roledb.add_role,
                      rolename, roleinfo)

    # Test condition where the parent role does not exist.
    tuf.roledb.clear_roledb()
    self.assertRaises(tuf.Error, tuf.roledb.add_role, rolename2, roleinfo)

    # Test conditions for invalid rolenames.
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.add_role, ' badrole ',
                      roleinfo)
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.add_role, '/badrole/',
                      roleinfo)



  def test_get_parent_rolename(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    rolename2 = 'targets/role1'
    rolename3 = 'targets/role1/role2'
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    tuf.roledb.add_role(rolename3, roleinfo)
    self.assertEqual(rolename, tuf.roledb.get_parent_rolename(rolename2))
    self.assertEqual(rolename2, tuf.roledb.get_parent_rolename(rolename3))
    self.assertEqual('', tuf.roledb.get_parent_rolename(rolename))

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_parent_rolename) 
  


  def test_role_exists(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    rolename2 = 'targets/role1'
    self.assertEqual(False, tuf.roledb.role_exists(rolename))
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    self.assertEqual(True, tuf.roledb.role_exists(rolename))
    self.assertEqual(True, tuf.roledb.role_exists(rolename2))

    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(tuf.FormatError, tuf.roledb.role_exists, None)
    self.assertRaises(tuf.FormatError, tuf.roledb.role_exists, 123)
    self.assertRaises(tuf.FormatError, tuf.roledb.role_exists, ['rolename'])

    # Test conditions for invalid rolenames.
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.role_exists, '')
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.role_exists, ' badrole ')
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.role_exists, '/badrole/')



  def test_get_all_parent_roles(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    rolename2 = 'targets/role1'
    rolename3 = 'targets/role1/role2'
    rolename4 = 'root'
    rolename5 = 'root/targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo)
    self.assertEqual(set(['targets']),
                     set(tuf.roledb.get_all_parent_roles(rolename)))
    tuf.roledb.add_role(rolename2, roleinfo)
    tuf.roledb.add_role(rolename3, roleinfo)
    tuf.roledb.add_role(rolename4, roleinfo)
    tuf.roledb.add_role(rolename5, roleinfo)
    
    self.assertEqual(set(['targets', 'targets/role1']),
                     set(tuf.roledb.get_all_parent_roles(rolename3)))
    self.assertEqual(set(['root']),
                     set(tuf.roledb.get_all_parent_roles(rolename5)))
  
    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_all_parent_roles) 



  def test_remove_role(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    rolename2 = 'release'
    rolename3 = 'release/role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    tuf.roledb.add_role(rolename3, roleinfo)

    self.assertEqual(None, tuf.roledb.remove_role(rolename))
    self.assertEqual(True, rolename not in tuf.roledb._roledb_dict)

    # Test conditions where removing a role causes the removal of its
    # delegated roles.
    self.assertEqual(None, tuf.roledb.remove_role(rolename2))
    self.assertEqual(0, len(tuf.roledb._roledb_dict))
 
    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.remove_role) 



  def test_remove_delegated_roles(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    rolename2 = 'targets/role1'
    rolename3 = 'targets/role1/role2'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    tuf.roledb.add_role(rolename3, roleinfo)
    self.assertEqual(None, tuf.roledb.remove_delegated_roles(rolename3))
    self.assertEqual(3, len(tuf.roledb._roledb_dict))
    self.assertEqual(None, tuf.roledb.remove_delegated_roles(rolename))
    self.assertEqual(1, len(tuf.roledb._roledb_dict))

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.remove_delegated_roles) 



  def test_get_rolenames(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    rolename2 = 'targets/role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    self.assertEqual([], tuf.roledb.get_rolenames())
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    self.assertEqual(set(['targets', 'targets/role1']),
                     set(tuf.roledb.get_rolenames()))

    

  def test_get_role_keyids(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    rolename2 = 'targets/role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    roleinfo2 = {'keyids': ['456', '789'], 'threshold': 2}
    self.assertRaises(tuf.UnknownRoleError, tuf.roledb.get_role_keyids, rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)
    
    self.assertEqual(['123'], tuf.roledb.get_role_keyids(rolename))
    self.assertEqual(set(['456', '789']),
                     set(tuf.roledb.get_role_keyids(rolename2)))

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_role_keyids) 
    


  def test_get_role_threshold(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    rolename2 = 'targets/role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    roleinfo2 = {'keyids': ['456', '789'], 'threshold': 2}
    self.assertRaises(tuf.UnknownRoleError, tuf.roledb.get_role_threshold, rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)
    
    self.assertEqual(1, tuf.roledb.get_role_threshold(rolename))
    self.assertEqual(2, tuf.roledb.get_role_threshold(rolename2))

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_role_threshold) 



  def test_get_role_paths(self):
    # Test conditions where the arguments are valid. 
    rolename = 'targets'
    rolename2 = 'targets/role1'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    paths = ['a/b', 'c/d']
    roleinfo2 = {'keyids': ['456', '789'], 'threshold': 2, 'paths': paths}
    self.assertRaises(tuf.UnknownRoleError, tuf.roledb.get_role_paths, rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo2)

    self.assertEqual({}, tuf.roledb.get_role_paths(rolename))
    self.assertEqual(paths, tuf.roledb.get_role_paths(rolename2))

    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_role_paths)



  def test_get_delegated_rolenames(self):
    # Test conditions where the arguments are valid. 
    rolename = 'a'
    rolename2 = 'a/b'
    rolename3 = 'a/b/c'
    rolename4 = 'a/b/c/d'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    self.assertRaises(tuf.UnknownRoleError, tuf.roledb.get_delegated_rolenames,
                      rolename)
    tuf.roledb.add_role(rolename, roleinfo)
    tuf.roledb.add_role(rolename2, roleinfo)
    tuf.roledb.add_role(rolename3, roleinfo)
    tuf.roledb.add_role(rolename4, roleinfo)
    self.assertEqual(set(['a/b/c', 'a/b/c/d']),
                     set(tuf.roledb.get_delegated_rolenames(rolename2)))
  
    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.get_delegated_rolenames)
 


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
    compression_algorithms = ['gz'] 

    root_metadata = tuf.formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot,
                                                       compression_algorithms)
    self.assertEqual(None,
                     tuf.roledb.create_roledb_from_root_metadata(root_metadata))
    # Ensure 'Root' and 'Targets' were added to the role database.
    self.assertEqual([keyid], tuf.roledb.get_role_keyids('root'))
    self.assertEqual([keyid2], tuf.roledb.get_role_keyids('targets'))

    # Test conditions for arguments with invalid formats.
    self.assertRaises(tuf.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, None)
    self.assertRaises(tuf.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, '')
    self.assertRaises(tuf.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, 123)
    self.assertRaises(tuf.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, ['123'])
    self.assertRaises(tuf.FormatError,
                      tuf.roledb.create_roledb_from_root_metadata, {'bad': '123'})

    # Test conditions for correctly formatted 'root_metadata' arguments but
    # containing incorrect role delegations (i.e., a missing parent role).
    # In these conditions, the roles should not be added to the role database
    # and a message logged by the logger.
    tuf.roledb.clear_roledb()
    
    # 'roledict' is missing a parent role and also contains duplicate roles.
    # These invalid roles should not be added to the role database.
    roledict = {'root': {'keyids': [keyid], 'threshold': 1},
                'targets/role1': {'keyids': [keyid2], 'threshold': 1},
                'release': {'keyids': [keyid3], 'threshold': 1}}
    version = 8
    
    # Add a third key for 'release'.
    keydict[keyid3] = rsakey3
    
    root_metadata = tuf.formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot,
                                                       compression_algorithms)
    self.assertRaises(tuf.Error,
                      tuf.roledb.create_roledb_from_root_metadata, root_metadata)
    # Remove the invalid role and re-generate 'root_metadata' to test for the
    # other two roles.
    del roledict['targets/role1']
    root_metadata = tuf.formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot,
                                                       compression_algorithms)
    self.assertEqual(None,
                     tuf.roledb.create_roledb_from_root_metadata(root_metadata))

    # Ensure only 'root' and 'release' were added to the role database.
    self.assertEqual(2, len(tuf.roledb._roledb_dict))
    self.assertEqual(True, tuf.roledb.role_exists('root'))
    self.assertEqual(True, tuf.roledb.role_exists('release'))



  def test_update_roleinfo(self):
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    tuf.roledb.add_role(rolename, roleinfo)
    
    # Test normal case.
    tuf.roledb.update_roleinfo(rolename, roleinfo)

    # Test for an unknown role.
    self.assertRaises(tuf.UnknownRoleError, tuf.roledb.update_roleinfo,
                      'unknown_rolename', roleinfo)

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, tuf.roledb.update_roleinfo, 1, roleinfo)
    self.assertRaises(tuf.FormatError, tuf.roledb.update_roleinfo, rolename, 1)

    


  def _test_rolename(self, test_function):
    # Private function that tests the 'rolename' argument of 'test_function'
    # for format, invalid name, and unknown role exceptions.
    
    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(tuf.FormatError, test_function, None)
    self.assertRaises(tuf.FormatError, test_function, 123)
    self.assertRaises(tuf.FormatError, test_function, ['rolename'])
    self.assertRaises(tuf.FormatError, test_function, {'a': 'b'})
    self.assertRaises(tuf.FormatError, test_function, ('a', 'b'))
    self.assertRaises(tuf.FormatError, test_function, True)
    
    # Test condition where the 'rolename' has not been added to the role database.
    self.assertRaises(tuf.UnknownRoleError, test_function, 'badrole')

    # Test conditions for invalid rolenames.
    self.assertRaises(tuf.InvalidNameError, test_function, '')
    self.assertRaises(tuf.InvalidNameError, test_function, ' badrole ')
    self.assertRaises(tuf.InvalidNameError, test_function, '/badrole/')



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
