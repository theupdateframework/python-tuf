"""
<Program Name>
  keystore.py
  
<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>
  
<Started>
  March 28, 2012.  Based on a previous version of this module by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Help store private keys in encrypted files and provide functions to load and
  save a keystore database. The database contains all of the keys needed to
  sign a repository's Metadata files, such as 'root.txt' and 'release.txt'.

  Originally, this stored the keys in one file- we've changed that so that it
  instead encrypts them separately, naming them according to their keyid value.

  This changes the semantics of the system considerably- first, the 'fname'
  passed in was originally treated as a filename. We now treat it as the name
  of a directory.

  Secondly, it no longer makes sense to provide access to keys which do not
  match the given decryption key.

  Thirdly, the semantics of adding keys has changed. It does not make sense to 
  have only one key for the entire keystore, and as a result, we're requiring 
  that the password be set at the point where the key is added.

"""

import os
import binascii
import logging

import evpy.cipher

import tuf.rsa_key
import tuf.util

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.keystore')

json = tuf.util.import_json()

# The delimeter symbol used to separate the different sections
# of encrypted files (i.e., salt, IV, ciphertext, passphrase).
# This delimeter is arbitrarily chosen and should not occur in
# the hexadecimal representations of the fields it is separating.
_ENCRYPTION_DELIMETER = '@@@@'

# A password is set for each key added to the keystore.
# The passwords dict has the form: {keyid: 'password', ...}
_key_passwords = {}

# The keystore database, which has the form:
# {keyid: key, ...}.
_keystore = {}


def add_rsakey(rsakey_dict, password, keyid=None):
  """
  <Purpose>
    Add 'rsakey_dict' to the keystore database while ensuring only
    unique keys are added.  If 'keyid' is provided, verify it is the
    correct keyid for 'rsakey_dict' and raise an exception otherwise.
  
  <Arguments>
    rsakey_dict:
      A dictionary conformant to 'tuf.formats.RSAKEY_SCHEMA', which
      has the form:
      {'keytype': 'rsa',
       'keyid': keyid,
       'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                  'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

    password:
      The object containing the password needed to encrypt and decrypt
      the key file (i.e., '<keyid>.key').  It must conform to
      'PASSWORD_SCHEMA'.

    keyid:
      An object conformant to 'KEYID_SCHEMA'.  It is used as an identifier
      for RSA keys.  This particular keyid should be extracted by the caller
      from the file name used by the key file ('<keyid>.key') to ensure it
      was correctly named.

  <Exceptions>
    tuf.FormatError, if 'rsakey_dict' or 'keyid' has an incorrect format.

    tuf.Error, if 'keyid' argument does not match the keyid for 'rsakey_dict'.

    tuf.KeyAlreadyExistsError, if 'rsakey_dict' is found in the keystore.

  <Side Effects>
    The '_keystore' and '_key_passwords' dictionaries are modified.

  <Returns>
    None.

  """
  
  # Does 'rsakey_dict' have the correct format?
  # This check will ensure 'rsakey_dict' has the appropriate number of objects
  # and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.RSAKEY_SCHEMA.check_match(rsakey_dict)

  # Does 'password' have the correct format?
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  # If 'keyid' was passed as an argument, does it
  # have the correct format?
  if keyid:
    # Raise 'tuf.FormatError' if the check fails.
    tuf.formats.KEYID_SCHEMA.check_match(keyid)

    # Check if the keyid found in 'rsakey_dict' matches
    # the 'keyid' supplied as an argument. 
    if keyid != rsakey_dict['keyid']:
      raise tuf.Error('Incorrect keyid '+rsakey_dict['keyid']+' expected '+keyid)
 
  # Check if the keyid belonging to 'rsakey_dict' is not already
  # available in the key database.
  keyid = rsakey_dict['keyid']
  if keyid in _keystore:
    raise tuf.KeyAlreadyExistsError('keyid: '+keyid)
  
  _key_passwords[keyid] = password
  _keystore[keyid] = rsakey_dict





def load_keystore_from_keyfiles(directory_name, keyids, passwords):
  """
  <Purpose>
    Populate the keystore database with the key files found in
    'directory_name'.  Use the user-supplied passwords in 'passwords' to
    decrypt the key files.  Each key file has a corresponding password.

  <Arguments>
    directory_name:
      The name of the directory containing the key files ('<keyid>.key'),
      conformant to tuf.formats.RELPATH_SCHEMA.

    keyids:
      A list containing the keyids of the signing keys to load.

    passwords:
      A list containing the password objects to encrypt and decrypt
      the key files ('<keyid>.key').

  <Exceptions>
    tuf.FormatError, if 'directory_name' or 'passwords' has an incorrect
    format.

  <Side Effects>
    The '_keystore' and '_key_passwords' dictionaries are modified.
    The key files found in 'directory_name' are read.

  <Returns>
    A list containing the keyids of the loaded keys.

  """

  # Does 'directory_name' have the correct format?
  # This check will ensure 'directory_name' has the appropriate number of
  # objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.RELPATH_SCHEMA.check_match(directory_name)

  # Does 'keyids' have the correct format?
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.KEYIDS_SCHEMA.check_match(keyids)
  
  # Does 'passwords' have the correct format?
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PASSWORDS_SCHEMA.check_match(passwords)

  # Keep a list of the keys loaded.
  loaded_keys = [] 
  
  logger.info('Loading private key(s) from '+repr(directory_name))

  # Make sure the directory exists.
  if not os.path.exists(directory_name):
    logger.info('...no such directory.  Keystore cannot be loaded.')
    return 

  # Get the list of filenames with a '.key' extension from 'directory_name'.
  keypaths = []
  for filename in os.listdir(directory_name):
    if filename.endswith('.key'):
      keypaths.append(filename) 

  # Decrypt the keys we can from those stored in 'keypaths'.
  for keypath in keypaths:
    full_filepath = os.path.join(directory_name, keypath)
    raw_contents = open(full_filepath, 'rb').read()

    # Try to decrypt the file using one of the passwords in 'passwords'.
    for password in passwords:
      try:
        json_data = _decrypt(raw_contents, password)
      except tuf.CryptoError:
        continue
     
      try: 
        keydata = tuf.util.load_json_string(json_data)
      except ValueError:
        # 'keydata' could not be decoded.  This will be the case
        # if the encrypted file could not be decrypted (e.g.,
        # invalid password).
        continue

      # Create the key based on its key type.  RSA keys currently
      # supported.
      if keydata['keytype'] == 'rsa':
        # 'keydata' is stored in KEY_SCHEMA format.  Call
        # create_from_metadata_format() to get the key in RSAKEY_SCHEMA
        # format, which is the format expected by 'add_rsakey()'.
        rsa_key = tuf.rsa_key.create_from_metadata_format(keydata)

        # Ensure the keyid for 'rsa_key' is one of the keys specified in
        # 'keyids'.  If not, do not load the key.
        if rsa_key['keyid'] not in keyids:
          continue
        
        # Ensure the '.key' extension is removed (keypath[:-4]), as we only
        # need the basefilename containing the full keyid.
        add_rsakey(rsa_key, password, keyid=keypath[:-4])
        logger.info('Loaded key: '+rsa_key['keyid'])
        loaded_keys.append(rsa_key['keyid'])
        continue
      else:
        logger.warn(repr(full_filepath)+' contains an invalid key type.')
        continue

  logger.info('Done.')
  return loaded_keys





def save_keystore_to_keyfiles(directory_name):
  """
  <Purpose>
    Save all the keys found in the keystore to separate files.  The password
    for each key is stored when it is added to the keystore.  Use these 
    passwords to encrypt the key files and save them in encrypted form to
    'directory_name'.

  <Arguments>
    directory_name:
      The name of the directory containing the key files ('<keyid>.key'),
      conformant to tuf.formats.RELPATH_SCHEMA.

  <Exceptions>
    tuf.FormatError if 'directory_name is incorrectly formatted.

  <Side Effects>
    'directory_name' created if it does not exist.

  <Returns>
    None.

  """

  # Does 'directory_name' have the correct format?
  # This check will ensure 'directory_name' has the appropriate number of
  # objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.RELPATH_SCHEMA.check_match(directory_name)

  logger.info('Saving private key(s) to '+repr(directory_name))

  # Make sure the directory exists, otherwise create it.
  if not os.path.exists(directory_name):
    logger.info('...no such directory.  The directory will be created.')
    os.mkdir(directory_name)

  # Iterate through the keystore keys and save them individually to a file.
  for keyid, key in _keystore.items():
    basefilename = os.path.join(directory_name, str(keyid)+'.key')
    file_object = open(basefilename, 'w')
    
    # Determine the appropriate format to save the key based on its key type.
    if key['keytype'] == 'rsa':
      key_metadata_format = \
            tuf.rsa_key.create_in_metadata_format(key['keyval'], private=True)
    else:
      logger.warn('The keystore has a key with an unrecognized key type.')
      continue
    
    # Encrypt 'key_metadata_format' and save it.
    encrypted_key = _encrypt(json.dumps(key_metadata_format), _key_passwords[keyid])
    file_object.write(encrypted_key)
    file_object.close()
    logger.info(repr(basefilename)+' saved.')

  logger.info('Done.')





def clear_keystore():
  """
  <Purpose>
    Clear the keystore and key passwords.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effect>
    The keystore and password dicts are reset.

  <Returns>
    None.

  """

  _keystore.clear()
  _key_passwords.clear()





def change_password(keyid, old_password, new_password):
  """
  <Purpose>
    Change the password for 'keyid'.

  <Arguments>
    keyid:
      The keyid for the signing key.

    old_password:
      The old password for the signing key to modify.

    new_password:
      The new password to set for the signing key.

  <Exceptions>
    tuf.UnknownKeyError, if 'keyid' is not found in the
    keystore.
    
    tuf.BadPasswordError, if 'old_password' is invalid or
    'new_password' does not have to correct format.

  <Side Effects>
    The old password for 'keyid' is changed to 'new_password'.

  <Returns>
    None.

  """
  
  # Check if 'keyid' is the keystore.
  if keyid not in _keystore or keyid not in _key_passwords:
    raise tuf.UnknownKeyError(keyid+' not recognized.')

  # Check if the old password matches.
  if _key_passwords[keyid] != old_password:
    raise tuf.BadPasswordError('Old password invalid')

  # If 'new_password' has the correct format, update '_key_passwords'.
  if tuf.formats.PASSWORD_SCHEMA.matches(new_password):
    _key_passwords[keyid] = new_password





def get_key(keyid):
  """
  <Purpose>
    Return the key for 'keyid'.  If 'keyid' corresponds to an
    RSA key, the object returned would conform to
    'tuf.formats.RSAKEY_SCHEMA'.  A different key type would return
    its corresponding key schema.

  <Arguments>
    keyid:
      The key identifier.

  <Exceptions>
    tuf.FormatError, if 'keyid' does not have the correct format.

    tuf.UnknownKeyError, if 'keyid' is not found in the keystore.

  <Side Effects>
    None.

  <Returns>
    The key belonging to 'keyid' (e.g., RSA key).

  """

  # Does 'keyid' have the correct format?
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.KEYID_SCHEMA.check_match(keyid)

  try:
    key = _keystore[keyid]
  except KeyError:
    raise tuf.UnknownKeyError('The keyid was not found in the keystore')

  return key





def _encrypt(key_data, password):
  """
  Encrypt 'key_data' using the Advanced Encryption Standard algorithm.
  'password' is treated as the symmetric key, strengthened using SHA512.
  The key size is 192 bits and AES's mode of operation is set to CBC
  (Cipher-Block Chaining).

  'key_data' is the JSON string representation of the key.  In the case
  of RSA keys, this format would be 'tuf.formats.RSAKEY_SCHEMA':
  {'keytype': 'rsa',
   'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
              'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

  tuf.CryptoError raised if the encryption fails.
  
  """
  
  # Use AES192 to encrypt 'key_data'.
  try:
    salt, iv, ciphertext = evpy.cipher.encrypt(key_data, password)
  except evpy.cipher.CipherError:
    raise tuf.CryptoError

  # Return the salt, initialization vector, and ciphertext as a single string.
  # These three values are delimited by '_ENCRYPTION_DELIMETER' to make
  # extraction easier.  This delimeter is arbitrarily chosen and should not
  # occur in the hexadecimal representations of the fields it is separating.
  return binascii.hexlify(salt) + _ENCRYPTION_DELIMETER + \
         binascii.hexlify(iv) + _ENCRYPTION_DELIMETER + \
         binascii.hexlify(ciphertext)





def _decrypt(key_data, password):
  """
  The corresponding decryption routine for _encrypt().

  tuf.CryptoError raised if the decryption fails.
  
  """
 
  # Extract the salt, initialization vector, and ciphertext from 'key_data'. 
  # These three values are delimited by '_ENCRYPTION_DELIMETER'.
  # This delimeter is arbitrarily chosen and should not occur in the
  # hexadecimal representations of the fields it is separating.
  salt, iv, ciphertext = key_data.split(_ENCRYPTION_DELIMETER)

  # The following decryption routine assumes 'key_data' was encrypted
  # using AES192.
  try:
    key_plaintext = evpy.cipher.decrypt(binascii.unhexlify(salt),
                                        binascii.unhexlify(iv),
                                        binascii.unhexlify(ciphertext),
                                        password)
  except evpy.cipher.CipherError:
    raise tuf.CryptoError

  return key_plaintext
