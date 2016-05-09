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



  def test_create_roledb(self):
    # Verify that a roledb is created for a named repository.
    self.assertEqual(1, len(tuf.roledb._roledb_dict))
    self.assertTrue('default' in tuf.roledb._roledb_dict)

    repository_name = 'example_repository'
    tuf.roledb.create_roledb(repository_name)
    self.assertEqual(2, len(tuf.roledb._roledb_dict))
    self.assertTrue(repository_name in tuf.roledb._roledb_dict)
   
    # Test for invalid and improperly formatted arguments.
    self.assertRaises(tuf.FormatError, tuf.roledb.create_roledb, 123)
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.create_roledb, 'default')

    # Reset the roledb so that subsequent test functions have access to the
    # original, default roledb.
    tuf.roledb.remove_roledb(repository_name)


  def test_remove_roledb(self):
    # Verify that the named repository is removed from the roledb.
    repository_name = 'example_repository'
    
    rolename = 'targets'
    roleinfo = {'keyids': ['123'], 'threshold': 1}
    
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.remove_roledb, 'default') 
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

    # Test condition for unexpected argument.
    self.assertRaises(TypeError, tuf.roledb.clear_roledb, 'default', 'unexpected_argument')



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

    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, None, roleinfo) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, 123, roleinfo) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, [''], roleinfo) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, rolename, None) 
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, rolename, 123)
    self.assertRaises(tuf.FormatError, tuf.roledb.add_role, rolename, [''])

    # Test condition where the role already exists in the role database.
    self.assertRaises(tuf.RoleAlreadyExistsError, tuf.roledb.add_role,
                      rolename, roleinfo)

    """
    # Test condition where the parent role does not exist.
    tuf.roledb.clear_roledb()
    self.assertRaises(tuf.Error, tuf.roledb.add_role, rolename2, roleinfo)
    """
    
    # Test conditions for invalid rolenames.
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.add_role, ' badrole ',
                      roleinfo)
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.add_role, '/badrole/',
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

    # Test conditions where the arguments are improperly formatted.
    self.assertRaises(tuf.FormatError, tuf.roledb.role_exists, None)
    self.assertRaises(tuf.FormatError, tuf.roledb.role_exists, 123)
    self.assertRaises(tuf.FormatError, tuf.roledb.role_exists, ['rolename'])

    # Test conditions for invalid rolenames.
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.role_exists, '')
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.role_exists, ' badrole ')
    self.assertRaises(tuf.InvalidNameError, tuf.roledb.role_exists, '/badrole/')





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

    # Test conditions where removing a role does not cause the removal of its
    # delegated roles.  The 'django' role should now only exist (after the
    # removal of 'targets' in the previous test condition, and the removal
    # of 'release' in the remove_role() call next.
    self.assertEqual(None, tuf.roledb.remove_role(rolename2))
    self.assertEqual(1, len(tuf.roledb._roledb_dict))
 
    # Test conditions where the arguments are improperly formatted,
    # contain invalid names, or haven't been added to the role database.
    self._test_rolename(tuf.roledb.remove_role) 





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
    rolename2 = 'role1'
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
    rolename2 = 'role1'
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

    self.assertRaises(tuf.UnknownRoleError, tuf.roledb.get_delegated_rolenames,
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

    # Verify that the expected roles of a Root file are properly loaded.
    tuf.roledb.clear_roledb()
    roledict = {'root': {'keyids': [keyid], 'threshold': 1},
                'release': {'keyids': [keyid3], 'threshold': 1}}
    version = 8
    
    # Add a third key for 'release'.
    keydict[keyid3] = rsakey3
    
    # Generate 'root_metadata' to verify that 'release' and 'root' are added
    # to the role database.
    root_metadata = tuf.formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot,
                                                       compression_algorithms)
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
