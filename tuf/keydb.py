"""
<Program Name>
  keydb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  March 21, 2012.  Based on a previous version of this module by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Represent a collection of keys and their organization.  This module ensures
  the layout of the collection remain consistent and easily verifiable.
  Provided are functions to add and delete keys from the database, retrieve a
  single key, and assemble a collection from keys stored in TUF 'Root' Metadata
  files. The Update Framework process maintains a single keydb. 
  
  RSA keys are currently supported and a collection of keys is organized as a 
  dictionary indexed by key ID.  Key IDs are used as identifiers for keys (e.g.,
  RSA key).  They are the hexadecimal representations of the hash of key objects
  (specifically, the key object containing only the public key).  See 'rsa_key.py'
  and the '_get_keyid()' function to learn precisely how keyids are generated.
  One may get the keyid of a key object by simply accessing the dictionary's
  'keyid' key (i.e., rsakey['keyid']).
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
import tuf.keys
import tuf._vendor.six as six

# List of strings representing the key types supported by TUF.
_SUPPORTED_KEY_TYPES = ['rsa', 'ed25519']

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.keydb')

# The key database.
_keydb_dict = {}


def create_keydb_from_root_metadata(root_metadata):
  """
  <Purpose>
    Populate the key database with the unique keys found in 'root_metadata'.
    The database dictionary will conform to 'tuf.formats.KEYDB_SCHEMA' and
    have the form: {keyid: key, ...}.  
    The 'keyid' conforms to 'tuf.formats.KEYID_SCHEMA' and 'key' to its
    respective type.  In the case of RSA keys, this object would match
    'RSAKEY_SCHEMA'.

  <Arguments>
    root_metadata:
      A dictionary conformant to 'tuf.formats.ROOT_SCHEMA'.  The keys found
      in the 'keys' field of 'root_metadata' are needed by this function.

  <Exceptions>
    tuf.FormatError, if 'root_metadata' does not have the correct format.

  <Side Effects>
    A function to add the key to the database is called.  In the case of RSA
    keys, this function is add_key().
    
    The old keydb key database is replaced.

  <Returns>
    None.
  """

  # Does 'root_metadata' have the correct format?
  # This check will ensure 'root_metadata' has the appropriate number of objects
  # and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ROOT_SCHEMA.check_match(root_metadata)

  # Clear the key database.
  _keydb_dict.clear()

  # Iterate through the keys found in 'root_metadata' by converting
  # them to 'RSAKEY_SCHEMA' if their type is 'rsa', and then
  # adding them the database.  Duplicates are avoided.
  for keyid, key_metadata in six.iteritems(root_metadata['keys']):
    if key_metadata['keytype'] in _SUPPORTED_KEY_TYPES:
      # 'key_metadata' is stored in 'KEY_SCHEMA' format.  Call
      # create_from_metadata_format() to get the key in 'RSAKEY_SCHEMA'
      # format, which is the format expected by 'add_key()'.
      key_dict = tuf.keys.format_metadata_to_key(key_metadata)
      try:
        add_key(key_dict, keyid)
      
      except tuf.KeyAlreadyExistsError as e:
        logger.warning(e)
        continue
      
      # 'tuf.Error' raised if keyid does not match the keyid for 'rsakey_dict'.
      except tuf.Error as e:
        logger.error(e)
        continue
    
    else:
      logger.warning('Root Metadata file contains a key with an invalid keytype.')





def add_key(key_dict, keyid=None):
  """
  <Purpose>
    Add 'rsakey_dict' to the key database while avoiding duplicates.
    If keyid is provided, verify it is the correct keyid for 'rsakey_dict'
    and raise an exception if it is not.
  
  <Arguments>
    key_dict:
      A dictionary conformant to 'tuf.formats.ANYKEY_SCHEMA'.
      It has the form:
      {'keytype': 'rsa',
       'keyid': keyid,
       'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                  'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}
    
    keyid:
      An object conformant to 'KEYID_SCHEMA'.  It is used as an identifier
      for RSA keys.

  <Exceptions>
    tuf.FormatError, if 'rsakey_dict' or 'keyid' does not have the 
    correct format.

    tuf.Error, if 'keyid' does not match the keyid for 'rsakey_dict'.

    tuf.KeyAlreadyExistsError, if 'rsakey_dict' is found in the key database.

  <Side Effects>
    The keydb key database is modified.

  <Returns>
    None.
  """

  # Does 'rsakey_dict' have the correct format?
  # This check will ensure 'rsakey_dict' has the appropriate number of objects
  # and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError if the check fails.
  tuf.formats.ANYKEY_SCHEMA.check_match(key_dict)

  # Does 'keyid' have the correct format?
  if keyid is not None:
    # Raise 'tuf.FormatError' if the check fails. 
    tuf.formats.KEYID_SCHEMA.check_match(keyid)

    # Check if the keyid found in 'rsakey_dict' matches 'keyid'.
    if keyid != key_dict['keyid']:
      raise tuf.Error('Incorrect keyid '+key_dict['keyid']+' expected '+keyid)
 
  # Check if the keyid belonging to 'rsakey_dict' is not already
  # available in the key database before returning.
  keyid = key_dict['keyid']
  if keyid in _keydb_dict:
    raise tuf.KeyAlreadyExistsError('Key: '+keyid)
 
  _keydb_dict[keyid] = copy.deepcopy(key_dict)





def get_key(keyid):
  """ 
  <Purpose>
    Return the key belonging to 'keyid'.

  <Arguments>
    keyid:
      An object conformant to 'tuf.formats.KEYID_SCHEMA'.  It is used as an
      identifier for keys.

  <Exceptions>
    tuf.FormatError, if 'keyid' does not have the correct format.

    tuf.UnknownKeyError, if 'keyid' is not found in the keydb database.

  <Side Effects>
    None.

  <Returns>
    The key matching 'keyid'.  In the case of RSA keys, a dictionary conformant
    to 'tuf.formats.RSAKEY_SCHEMA' is returned.
  """

  # Does 'keyid' have the correct format?
  # This check will ensure 'keyid' has the appropriate number of objects
  # and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' is the match fails.
  tuf.formats.KEYID_SCHEMA.check_match(keyid)

  # Return the key belonging to 'keyid', if found in the key database.
  try:
    return copy.deepcopy(_keydb_dict[keyid])
  except KeyError:
    raise tuf.UnknownKeyError('Key: '+keyid)





def remove_key(keyid):
  """ 
  <Purpose>
    Remove the key belonging to 'keyid'.

  <Arguments>
    keyid:
      An object conformant to 'tuf.formats.KEYID_SCHEMA'.  It is used as an
      identifier for keys.

  <Exceptions>
    tuf.FormatError, if 'keyid' does not have the correct format.

    tuf.UnknownKeyError, if 'keyid' is not found in key database.

  <Side Effects>
    The key, identified by 'keyid', is deleted from the key database.

  <Returns>
    None.
  """

  # Does 'keyid' have the correct format?
  # This check will ensure 'keyid' has the appropriate number of objects
  # and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' is the match fails.
  tuf.formats.KEYID_SCHEMA.check_match(keyid)

  # Remove the key belonging to 'keyid' if found in the key database.
  if keyid in _keydb_dict: 
    del _keydb_dict[keyid]
  else:
    raise tuf.UnknownKeyError('Key: '+keyid)





def clear_keydb():
  """
  <Purpose>
    Clear the keydb key database.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    The keydb key database is reset.

  <Returns>
    None.
  """
  
  _keydb_dict.clear()
