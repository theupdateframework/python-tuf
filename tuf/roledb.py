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
  Represent a collection of roles and their organization.  The caller may create
  a collection of roles from those found in the 'root.txt' metadata file by
  calling 'create_roledb_from_rootmeta()', or individually by adding roles with
  'add_role()'.  There are many supplemental functions included here that yield
  useful information about the roles contained in the database, such as
  extracting all the parent rolenames for a specified rolename, deleting all the
  delegated roles, retrieving role paths, etc.  The Update Framework process
  maintains a single roledb.

  The role database is a dictionary conformant to 'tuf.formats.ROLEDICT_SCHEMA'
  and has the form:
  {'rolename': {'keyids': ['34345df32093bd12...'],
                'threshold': 1
                'paths': ['path/to/role.txt']}}

"""

import logging

import tuf
import tuf.formats
import tuf.log

# See 'tuf.log' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.roledb')

# The role database.
_roledb_dict = {}


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

  # Iterate through the roles found in 'root_metadata'
  # and add them to '_roledb_dict'.  Duplicates are avoided.
  for rolename, roleinfo in root_metadata['roles'].items():
    try:
      add_role(rolename, roleinfo)
    # tuf.Error raised if the parent role of 'rolename' does not exist.  
    except tuf.Error, e:
      logger.error(e)
      raise





def add_role(rolename, roleinfo, require_parent=True):
  """
  <Purpose>
    Add to the role database the 'roleinfo' associated with 'rolename'.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

    roleinfo:
      An object representing the role associated with 'rolename', conformant to
      ROLE_SCHEMA.  'roleinfo' has the form: 
      {'keyids': ['34345df32093bd12...'],
       'threshold': 1}

      The 'target' role has an additional 'paths' key.  Its value is a list of
      strings representing the path of the target file(s).

    require_parent:
      A boolean indicating whether to check for a delegating role.  add_role()
      will raise an exception if this parent role does not exist.

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
  tuf.formats.ROLE_SCHEMA.check_match(roleinfo)

  # Does 'require_parent' have the correct format?
  tuf.formats.TOGGLE_SCHEMA.check_match(require_parent)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)

  if rolename in _roledb_dict:
    raise tuf.RoleAlreadyExistsError('Role already exists: '+rolename)

  # Make sure that the delegating role exists. This should be just a
  # sanity check and not a security measure.
  if require_parent and '/' in rolename:
    # Get parent role.  'a/b/c/d' --> 'a/b/c'. 
    parent_role = '/'.join(rolename.split('/')[:-1])

    if parent_role not in _roledb_dict:
      raise tuf.Error('Parent role does not exist: '+parent_role)

  _roledb_dict[rolename] = roleinfo





def get_parent_rolename(rolename):
  """
  <Purpose>
    Return the name of the parent role for 'rolename'.
    Given the rolename 'a/b/c/d', return 'a/b/c'.
    Given 'a', return ''.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A string representing the name of the parent role.

  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  parts = rolename.split('/')
  parent_rolename = '/'.join(parts[:-1])

  return parent_rolename





def get_all_parent_roles(rolename):
  """
  <Purpose>
    Return a list of roles that are parents of 'rolename'.
    Given the rolename 'a/b/c/d', return the list:
    ['a', 'a/b', 'a/b/c'].

    Given 'a', return ['a'].
  
  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A list containing all the parent roles.

  """
    
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  # List of parent roles returned.
  parent_roles = []

  parts = rolename.split('/')

  # Append the first role to the list.
  parent_roles.append(parts[0])

  # The 'roles_added' string contains the roles already added.  If 'a' and 'a/b'
  # have been added to 'parent_roles', 'roles_added' would contain 'a/b'
  roles_added = parts[0]

  # Add each subsequent role to the previous string (with a '/' separator).
  # This only goes to -1 because we only want to return the parents (so we
  # ignore the last element).
  for next_role in parts[1:-1]:
    parent_roles.append(roles_added+'/'+next_role)
    roles_added = roles_added+'/'+next_role

  return parent_roles





def role_exists(rolename):
  """
  <Purpose>
    Verify whether 'rolename' is stored in the role database.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

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
    Remove 'rolename', including its delegations.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    A role, or roles, may be removed from the role database.

  <Returns>
    None.
  
  """
 
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)
  
  remove_delegated_roles(rolename)
  if rolename in _roledb_dict:
    del _roledb_dict[rolename]





def remove_delegated_roles(rolename):
  """
  <Purpose>
    Remove a role's delegations (leaving the rest of the role alone).
    All levels of delegation are removed, not just the directly delegated roles.
    If 'rolename' is 'a/b/c' and the role database contains
    ['a/b/c/d/e', 'a/b/c/d', 'a/b/c', 'a/b', 'a'], return
    ['a/b/c', 'a/b', 'a'].

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 
   
    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    Role(s) from the role database may be deleted.

  <Returns>
    None.

  """
  
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  # Ensure that we only care about delegated roles!
  rolename_with_slash = rolename + '/'
  for name in get_rolenames():
    if name.startswith(rolename_with_slash):
      del _roledb_dict[name]





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
  
  return _roledb_dict.keys()





def get_role_keyids(rolename):
  """
  <Purpose>
    Return a list of the keyids associated with 'rolename'.
    Keyids are used as identifiers for keys (e.g., rsa key).
    A list of keyids are associated with each rolename.
    Signing a metadata file, such as 'root.txt' (Root role),
    involves signing or verifying the file with a list of
    keys identified by keyid.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

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
      (e.g., 'root', 'release', 'timestamp').

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
      (e.g., 'root', 'release', 'timestamp').

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
    return list()





def get_delegated_rolenames(rolename):
  """
  <Purpose>
    Return the delegations of a role.  If 'rolename' is 'a/b/c'
    and the role database contains ['a/b/c/d', 'a/b/c/d/e', 'a/b/c'], 
    return ['a/b/c/d', 'a/b/c/d/e']

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'release', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A list of rolenames. Note that the rolenames are *NOT* sorted by order of
    delegation!

  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  # The list of delegated roles to be returned. 
  delegated_roles = []

  # Ensure that we only care about delegated roles!
  rolename_with_slash = rolename + '/'
  for name in get_rolenames():
    if name.startswith(rolename_with_slash):
      delegated_roles.append(name)
  
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





def _check_rolename(rolename):
  """
  Raise tuf.FormatError if 'rolename' does not match
  'tuf.formats.ROLENAME_SCHEMA', tuf.UnknownRoleError if 'rolename' is not
  found in the role database, or tuf.InvalidNameError if 'rolename' is
  not formatted correctly.

  """
  
  # Does 'rolename' have the correct object format?
  # This check will ensure 'rolename' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)
  
  if rolename not in _roledb_dict:
    raise tuf.UnknownRoleError('Role name does not exist: '+rolename)





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
