"""
<Program Name>
  roledb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  March 21, 2012.  Based on a previous version of this module by Geremy Condra.
  
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Represent a collection of roles and their organization.  The caller may
  create a collection of roles from those found in the 'root.json' metadata
  file by calling 'create_roledb_from_root_metadata()', or individually by
  adding roles with 'add_role()'.  There are many supplemental functions
  included here that yield useful information about the roles contained in the
  database, such as extracting all the parent rolenames for a specified
  rolename, deleting all the delegated roles, retrieving role paths, etc.  The
  Update Framework process maintains a single roledb.

  The role database is a dictionary conformant to 'tuf.formats.ROLEDICT_SCHEMA'
  and has the form:
  
  {'rolename': {'keyids': ['34345df32093bd12...'],
                'threshold': 1
                'signatures': ['abcd3452...'],
                'paths': ['role.json'],
                'path_hash_prefixes': ['ab34df13'],
                'delegations': {'keys': {}, 'roles': {}}}
  
  The 'name', 'paths', 'path_hash_prefixes', and 'delegations' dict keys are
  optional.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import logging
import copy

import tuf
import tuf.formats
import tuf.log
import six

# See 'tuf.log' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.roledb')

# The role database.
_roledb_dict = {}

# A set of roles that have been modified (e.g., via update_roleinfo()) and
# should be written to disk.
_dirty_roles = set() 


def create_roledb_from_root_metadata(root_metadata):
  """
  <Purpose>
    Create a role database containing all of the unique roles found in
    'root_metadata'.

  <Arguments>
    root_metadata:
      A dictionary conformant to 'tuf.formats.ROOT_SCHEMA'.  The roles found
      in the 'roles' field of 'root_metadata' is needed by this function.  

  <Exceptions>
    tuf.FormatError, if 'root_metadata' does not have the correct object format.

    tuf.Error, if one of the roles found in 'root_metadata' contains an invalid
    delegation (i.e., a nonexistent parent role).

  <Side Effects>
    Calls add_role().
    
    The old role database is replaced.

  <Returns>
    None.
  """

  # Does 'root_metadata' have the correct object format?
  # This check will ensure 'root_metadata' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  # Raises tuf.FormatError.
  tuf.formats.ROOT_SCHEMA.check_match(root_metadata)

  # Clear the role database.
  _roledb_dict.clear()

  # Do not modify the contents of the 'root_metadata' argument.
  root_metadata = copy.deepcopy(root_metadata)
  
  # Iterate through the roles found in 'root_metadata'
  # and add them to '_roledb_dict'.  Duplicates are avoided.
  for rolename, roleinfo in six.iteritems(root_metadata['roles']):
    if rolename == 'root':
      roleinfo['version'] = root_metadata['version']
      roleinfo['expires'] = root_metadata['expires']
    
    roleinfo['signatures'] = []
    roleinfo['signing_keyids'] = []
    roleinfo['compressions'] = ['']
    roleinfo['partial_loaded'] = False
    if rolename.startswith('targets'):
      roleinfo['paths'] = {}
      roleinfo['delegations'] = {'keys': {}, 'roles': []}
  
    add_role(rolename, roleinfo)





def add_role(rolename, roleinfo):
  """
  <Purpose>
    Add to the role database the 'roleinfo' associated with 'rolename'.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

    roleinfo:
      An object representing the role associated with 'rolename', conformant to
      ROLEDB_SCHEMA.  'roleinfo' has the form: 
      {'keyids': ['34345df32093bd12...'],
       'threshold': 1,
       'signatures': ['ab23dfc32']
       'paths': ['path/to/target1', 'path/to/target2', ...],
       'path_hash_prefixes': ['a324fcd...', ...],
       'delegations': {'keys': }

      The 'paths', 'path_hash_prefixes', and 'delegations' dict keys are
      optional.
      
      The 'target' role has an additional 'paths' key.  Its value is a list of
      strings representing the path of the target file(s).
  
  <Exceptions>
    tuf.FormatError, if 'rolename' or 'roleinfo' does not have the correct
    object format.

    tuf.RoleAlreadyExistsError, if 'rolename' has already been added.

    tuf.InvalidNameError, if 'rolename' is improperly formatted.

  <Side Effects>
    The role database is modified.

  <Returns>
    None.
  """

  # Does 'rolename' have the correct object format?
  # This check will ensure 'rolename' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  # Does 'roleinfo' have the correct object format?
  tuf.formats.ROLEDB_SCHEMA.check_match(roleinfo)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)

  if rolename in _roledb_dict:
    raise tuf.RoleAlreadyExistsError('Role already exists: ' + rolename)

  _roledb_dict[rolename] = copy.deepcopy(roleinfo)





def update_roleinfo(rolename, roleinfo, mark_role_as_dirty=True):
  """
  <Purpose>
    Modify 'rolename's _roledb_dict entry to include the new 'roleinfo'.
    'rolename' is also added to the _dirty_roles set.  Roles added to
    '_dirty_roles' are marked as modified and can be used by the repository
    tools to determine which roles need to be written to disk.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

    roleinfo:
      An object representing the role associated with 'rolename', conformant to
      ROLEDB_SCHEMA.  'roleinfo' has the form: 
      {'name': 'role_name',
       'keyids': ['34345df32093bd12...'],
       'threshold': 1,
       'paths': ['path/to/target1', 'path/to/target2', ...],
       'path_hash_prefixes': ['a324fcd...', ...]}

      The 'name', 'paths', and 'path_hash_prefixes' dict keys are optional.

      The 'target' role has an additional 'paths' key.  Its value is a list of
      strings representing the path of the target file(s).
    
    mark_role_as_dirty:
      A boolean indicating whether the updated 'roleinfo' for 'rolename' should
      be marked as dirty.  The caller might not want to mark 'rolename' as
      dirty if it is loading metadata from disk and only wants to populate
      roledb.py.  Likewise, add_role() would support a similar boolean to allow
      the repository tools to successfully load roles via load_repository()
      without needing to mark these roles as dirty (default behavior).

  <Exceptions>
    tuf.FormatError, if 'rolename' or 'roleinfo' does not have the correct
    object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.
    
    tuf.InvalidNameError, if 'rolename' is improperly formatted.

  <Side Effects>
    The role database is modified.

  <Returns>
    None.
  """

  # Does the arguments have the correct object format?
  # This check will ensure arguments have the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
  tuf.formats.BOOLEAN_SCHEMA.check_match(mark_role_as_dirty)

  # Does 'roleinfo' have the correct object format?
  tuf.formats.ROLEDB_SCHEMA.check_match(roleinfo)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)

  if rolename not in _roledb_dict:
    raise tuf.UnknownRoleError('Role does not exist: ' + rolename)

  # Update the global _roledb_dict and _dirty_roles structures so that
  # the latest 'roleinfo' is available to other modules, and the repository
  # tools know which roles should be saved to disk.
  _roledb_dict[rolename] = copy.deepcopy(roleinfo)
  
  if mark_role_as_dirty: 
    _dirty_roles.add(rolename)





def get_dirty_roles():
  """
  <Purpose>
    A function that returns a list of the roles that have been modified.  Tools
    that write metadata to disk can use the list returned to determine which
    roles should be written.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    A list of the roles that have been modified.
  """

  return list(_dirty_roles)





def role_exists(rolename):
  """
  <Purpose>
    Verify whether 'rolename' is stored in the role database.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    Boolean.  True if 'rolename' is found in the role database, False otherwise.
  """

  # Raise tuf.FormatError, tuf.InvalidNameError.
  try: 
    _check_rolename(rolename)
  except (tuf.FormatError, tuf.InvalidNameError):
    raise
  except tuf.UnknownRoleError:
    return False
  
  return True





def remove_role(rolename):
  """
  <Purpose>
    Remove 'rolename'.  Delegated roles were previously removed as well,
    but this step is longer supported since the repository can resemble
    a graph of delegations.  That is, we shouldn't delete rolename's
    delegations because another role may have a valid delegation
    to it, whereas before the only valid delegation to it must be from
    'rolename' (repository resembles a tree of delegations).

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    A role may be removed from the role database.

  <Returns>
    None.
  """
 
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)
  
  # 'rolename' was verified to exist by _check_rolename().
  # Remove 'rolename'.
  del _roledb_dict[rolename]






def get_rolenames():
  """
  <Purpose>
    Return a list of the rolenames found in the role database.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    None.
  
  <Returns>
    A list of rolenames.
  """
  
  return list(_roledb_dict.keys())





def get_roleinfo(rolename):
  """
  <Purpose>
    Return the roleinfo of 'rolename'.

    {'keyids': ['34345df32093bd12...'],
     'threshold': 1,
     'signatures': ['ab453bdf...', ...],
     'paths': ['path/to/target1', 'path/to/target2', ...],
     'path_hash_prefixes': ['a324fcd...', ...],
     'delegations': {'keys': {}, 'roles': []}}

    The 'signatures', 'paths', 'path_hash_prefixes', and 'delegations' dict keys
    are optional.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' is improperly formatted.
    
    tuf.UnknownRoleError, if 'rolename' does not exist.

  <Side Effects>
    None.
  
  <Returns>
    The roleinfo of 'rolename'.
  """
  
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)
  
  return copy.deepcopy(_roledb_dict[rolename])





def get_role_keyids(rolename):
  """
  <Purpose>
    Return a list of the keyids associated with 'rolename'.
    Keyids are used as identifiers for keys (e.g., rsa key).
    A list of keyids are associated with each rolename.
    Signing a metadata file, such as 'root.json' (Root role),
    involves signing or verifying the file with a list of
    keys identified by keyid.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A list of keyids.
  """
  
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  roleinfo = _roledb_dict[rolename]
  
  return roleinfo['keyids']





def get_role_threshold(rolename):
  """
  <Purpose>
    Return the threshold value of the role associated with 'rolename'.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 

    tuf.UnknownRoleError, if 'rolename' cannot be found in in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A threshold integer value.
  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  roleinfo = _roledb_dict[rolename]
  
  return roleinfo['threshold']





def get_role_paths(rolename):
  """
  <Purpose>
    Return the paths of the role associated with 'rolename'.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A list of paths. 
  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  roleinfo = _roledb_dict[rolename]
  
  # Paths won't exist for non-target roles.
  try:
    return roleinfo['paths']
  except KeyError:
    return dict()





def get_delegated_rolenames(rolename):
  """
  <Purpose>
    Return the delegations of a role.  If 'rolename' is 'tuf'
    and the role database contains ['django', 'requests', 'cryptography'], 
    in 'tuf's delegations field, return ['django', 'requests', 'cryptography']

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A list of rolenames. Note that the rolenames are *NOT* sorted by order of
    delegation.
  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  roleinfo = get_roleinfo(rolename)
  delegated_roles = []
 
  for delegated_role in roleinfo['delegations']['roles']:
    delegated_roles.append(delegated_role['name'])

  return delegated_roles





def clear_roledb():
  """
  <Purpose>
    Reset the roledb database.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    None.
  """

  _roledb_dict.clear()
  _dirty_roles.clear()





def _check_rolename(rolename):
  """
  Raise tuf.FormatError if 'rolename' does not match
  'tuf.formats.ROLENAME_SCHEMA', tuf.UnknownRoleError if 'rolename' is not
  found in the role database, or tuf.InvalidNameError if 'rolename' is not
  formatted correctly.
  """
  
  # Does 'rolename' have the correct object format?
  # This check will ensure 'rolename' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)
  
  if rolename not in _roledb_dict:
    raise tuf.UnknownRoleError('Role name does not exist: ' + rolename)





def _validate_rolename(rolename):
  """
  Raise tuf.InvalidNameError if 'rolename' is not formatted correctly.
  It is assumed 'rolename' has been checked against 'ROLENAME_SCHEMA'
  prior to calling this function.
  """

  if rolename == '':
    raise tuf.InvalidNameError('Rolename must not be an empty string')

  if rolename != rolename.strip():
    raise tuf.InvalidNameError(
             'Invalid rolename. Cannot start or end with whitespace: '+rolename)

  if rolename.startswith('/') or rolename.endswith('/'):
    raise tuf.InvalidNameError(
             'Invalid rolename. Cannot start or end with "/": '+rolename)
