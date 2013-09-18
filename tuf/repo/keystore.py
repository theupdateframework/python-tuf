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

  The <keyid>.key files are encrypted with the AES-256-CTR-Mode symmetric key
  algorithm.  User passwords are strengthened with PBKDF2, currently set to
  100,000 passphrase iterations.  The previous evpy implementation used 1,000
  iterations.

"""

import os
import binascii
import logging

# Import PyCrypto's Key Derivation Function (KDF) module.  'keystore.py'
# needs this module to derive a secret key according to the Password-Based
# Key Derivation Function 2 specification.  The derived key is used as the
# symmetric key to encrypt TUF key information.  PyCrypto's implementation:
# Crypto.Protocol.KDF.PBKDF2().  PKCS#5 v2.0 PBKDF2 specification:
# http://tools.ietf.org/html/rfc2898#section-5.2 
import Crypto.Protocol.KDF

# PyCrypto's AES implementation.  AES is a symmetric key algorithm that
# operates on fixed block sizes of 128-bits.
# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
import Crypto.Cipher.AES

# 'Crypto.Random' is a cryptographically strong version of Python's standard
# "random" module.  Random bits of data is needed for salts and 
# initialization vectors suitable for the encryption algorithms used in 
# 'keystore.py'.
import Crypto.Random

# The mode of operation is presently set to CTR (CounTeR Mode) for symmetric
# block encryption (AES-256).  PyCrypto provides a callable stateful block
# counter that can update successive blocks when needed.  The initial random
# block (IV) can be set to begin the process of incrementing the 128-bit blocks
# and allowing the AES algorithm to perform cipher block operations on them. 
import Crypto.Util.Counter

import tuf.rsa_key
import tuf.util


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.keystore')

json = tuf.util.import_json()

# The delimiter symbol used to separate the different sections
# of encrypted files (i.e., salt, IV, ciphertext, passphrase).
# This delimiter is arbitrarily chosen and should not occur in
# the hexadecimal representations of the fields it is separating.
_ENCRYPTION_DELIMITER = '@@@@'

# AES key size.  Default key size = 32 bytes = AES-256.
_AES_KEY_SIZE = 32

# Default salt size, in bytes.  A 128-bit salt (i.e., a random sequence of data
# to protect against dictionary attacks) is generated for PBKDF2.  
_SALT_SIZE = 16 

# Default PBKDF2 passphrase iterations.  The current (2013) "good enough" number
# of passphrase iterations.  We recommend that important keys, such as root,
# be kept offline.  Are we going overboard with respect to our use case?
# http://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256
_PBKDF2_ITERATIONS = 100000

# A user password is read and a derived key generated.  The derived key and
# salt returned by the key derivation function (PBKDF2) is saved in
# '_derived_keys', which has the form:
# {keyid: {'salt': ..., 'derived_key': ...}}
_derived_keys = {}

# The keystore database, which has the form:
# {keyid: key, keyid2: key2, ...}
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
    The '_keystore' and '_derived_keys' dictionaries are modified.

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
  if keyid is not None:
    # Raise 'tuf.FormatError' if the check fails.
    tuf.formats.KEYID_SCHEMA.check_match(keyid)

    # Check if the keyid found in 'rsakey_dict' matches
    # the 'keyid' supplied as an argument. 
    if keyid != rsakey_dict['keyid']:
      message = 'Incorrect keyid: '+repr(rsakey_dict['keyid'])+'.'+\
        'Expected: '+repr(keyid)
      raise tuf.Error(message)
 
  # Check if the keyid belonging to 'rsakey_dict' is not already
  # available in the key database.
  keyid = rsakey_dict['keyid']
  if keyid in _keystore:
    message = 'Keyid: '+repr(keyid)+' already exists.'
    raise tuf.KeyAlreadyExistsError(message)
 
  # The '_derived_keys' dictionary does not store the user's password.  A key
  # derivation function is applied to 'password' prior to storing it in
  # _derived_key and may then be used as a symmetric key.
  salt, derived_key = _generate_derived_key(password)
  _derived_keys[keyid] = {'salt': salt, 'derived_key': derived_key}
  _keystore[keyid] = rsakey_dict





def load_keystore_from_keyfiles(directory_name, keyids, passwords):
  """
  <Purpose>
    Populate the keystore database with the key files found in
    'directory_name'.  Use the user-supplied passwords in 'passwords' to
    decrypt the key files.  Each '<keyid>.key' file has a corresponding
    password.

  <Arguments>
    directory_name:
      The name of the directory containing the key files ('<keyid>.key'),
      conformant to 'tuf.formats.RELPATH_SCHEMA'.

    keyids:
      A list containing the keyids of the signing keys to load.

    passwords:
      A list containing the password objects to encrypt and decrypt
      the key files ('<keyid>.key').

  <Exceptions>
    tuf.FormatError, if 'directory_name' or 'passwords' has an incorrect
    format.

  <Side Effects>
    The '_keystore' and '_derived_keys' dictionaries are modified.
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

  # Keep a list of the keyids loaded, which is returned to the caller.
  loaded_keyids = [] 
  
  logger.info('Loading private key(s) from '+repr(directory_name))

  # Load the private key(s) if 'directory_name' exists, otherwise log a warning.
  if os.path.exists(directory_name):
    # Decrypt the keys we can from those stored in 'keyids'.
    for keyid in keyids:
      try:
        keyfilename = keyid+'.key'
        full_filepath = os.path.join(directory_name, keyfilename)
        raw_contents = open(full_filepath, 'rb').read()
      except:
        logger.warn('Could not find key '+repr(full_filepath)+'.')
      else:
        # Try to decrypt the file using one of the passwords in 'passwords'.
        for password in passwords:
          try:
            json_data = _decrypt(raw_contents, password)
          except:
            logger.warn(repr(full_filepath)+' contains an invalid key.')
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

            # Ensure the '.key' extension is removed, as we only
            # need the basefilename containing the full keyid.
            try:
              add_rsakey(rsa_key, password, keyid=keyid)
              logger.info('Loaded key: '+rsa_key['keyid'])
            except tuf.KeyAlreadyExistsError, e:
              logger.info('Key already loaded: '+rsa_key['keyid'])
            loaded_keyids.append(rsa_key['keyid'])
            continue
          else:
            logger.warn(repr(full_filepath)+' contains an invalid key type.')
            continue

  else:
    logger.warn('...no such directory.  Keystore cannot be loaded.')

  logger.info('Done.')

  return loaded_keyids





def save_keystore_to_keyfiles(directory_name):
  """
  <Purpose>
    Save all the keys found in the keystore to individual files.  The derived
    symmetric key and salt for each key is stored when it is added to the
    keystore.  Use the symmetric key to encrypt the key files and save the
    the ciphertext to 'directory_name' (Note: salt, IV, etc. is also appended
    to the generated '<keyid>.key').

  <Arguments>
    directory_name:
      The name of the directory containing the key files ('<keyid>.key'),
      conformant to 'tuf.formats.RELPATH_SCHEMA'.

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

  # Iterate the keystore keys and save them individually to a file.
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
    encrypted_key = _encrypt(json.dumps(key_metadata_format),
                             _derived_keys[keyid])
    file_object.write(encrypted_key)
    file_object.close()
    logger.info(repr(basefilename)+' saved.')

  logger.info('Done.')





def clear_keystore():
  """
  <Purpose>
    Clear '_keystore', containing the all key data, and '_derived_keys',
    containing the salt and symmetric keys.

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
  _derived_keys.clear()





def change_password(keyid, old_password, new_password):
  """
  <Purpose>
    Change the password for 'keyid'.  'old_password' is verified prior to
    any changes.  Since user passwords are not stored, the derived key
    information generated from these passwords is what's verified and updated. 

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
    'new_password' does not have the correct format.

  <Side Effects>
    The old key information generated from the user password for 'keyid'
    is changed for the new key information from 'new_password'.

  <Returns>
    None.

  """
  
  # Does 'keyid' have the correct format?
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.KEYID_SCHEMA.check_match(keyid)
  
  # Does 'old_password' and 'new_password' have the correct format?
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PASSWORD_SCHEMA.check_match(old_password)
  tuf.formats.PASSWORD_SCHEMA.check_match(new_password)
  
  # Check if 'keyid' is in the keystore.
  if keyid not in _keystore or keyid not in _derived_keys:
    message = repr(keyid)+' not recognized.'
    raise tuf.UnknownKeyError(message)

  # Check if the old password is valid.  The _derived_keys dictionary
  # stores derived keys instead of user passwords, according to the
  # key derivation function used by _generate_derived_key().
  salt = _derived_keys[keyid]['salt']
  junk, old_derived_key = _generate_derived_key(old_password, salt)
  if _derived_keys[keyid]['derived_key'] != old_derived_key:
    message = 'Old password invalid.'
    raise tuf.BadPasswordError(message)

  # Update '_derived_keys[keyid]' with the new derived key and salt.
  salt, new_derived_key = _generate_derived_key(new_password) 
  _derived_keys[keyid] = {}
  _derived_keys[keyid]['salt'] = salt
  _derived_keys[keyid]['derived_key'] = new_derived_key





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





def _generate_derived_key(password, salt=None):
  """
  Generate a derived key by feeding 'password' to the Password-Based Key
  Derivation Function (PBKDF2).  PyCrypto's PBKDF2 implementation is
  currently used.  'salt' may be specified so that a previous derived key
  may be regenerated.
  
  """
  
  if salt is None:
    salt = Crypto.Random.new().read(_SALT_SIZE) 


  def pseudorandom_function(password, salt):
    """
    PyCrypto's PBKDF2() expects a callable function for its optional
    'prf' argument.  'prf' is set to HMAC-SHA1 (in PyCrypto's PBKDF2 function)
    by default.  'pseudorandom_function' instead sets 'prf' to HMAC-SHA256. 
    """
    
    return Crypto.Hash.HMAC.new(password, salt, Crypto.Hash.SHA256).digest()  


  # 'dkLen' is the desired key length.  'count' is the number of password
  # iterations performed by PBKDF2.  'prf' is a pseudorandom function, which
  # must be callable. 
  derived_key = Crypto.Protocol.KDF.PBKDF2(password, salt,
                                           dkLen=_AES_KEY_SIZE,
                                           count=_PBKDF2_ITERATIONS,
                                           prf=pseudorandom_function)

  return salt, derived_key





def _encrypt(key_data, derived_key_information):
  """
  Encrypt 'key_data' using the Advanced Encryption Standard (AES-256) algorithm.
  'derived_key_information' should contain a key strengthened by PBKDF2.  The
  key size is 256 bits and AES's mode of operation is set to CTR (CounTeR Mode).
  The HMAC of the ciphertext is generated to ensure the ciphertext has not been
  modified.

  'key_data' is the JSON string representation of the key.  In the case
  of RSA keys, this format would be 'tuf.formats.RSAKEY_SCHEMA':
  {'keytype': 'rsa',
   'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
              'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

  'derived_key_information' is a dictionary of the form:
    {'salt': '...'
     'derived_key': '...'}

  'tuf.CryptoError' raised if the encryption fails.
  
  """
  
  # Generate a random initialization vector (IV).  The 'iv' is treated as the
  # initial counter block to a stateful counter block function (i.e.,
  # PyCrypto's 'Crypto.Util.Counter'.  The AES block cipher operates on 128-bit
  # blocks, so generate a random 16-byte initialization block.  PyCrypto expects
  # the initial value of the stateful counter to be an integer.
  # Follow the provably secure encrypt-then-MAC approach, which affords the
  # ability to verify ciphertext without needing to decrypt it and preventing
  # an attacker from feeding the block cipher malicious data.  Modes like GCM
  # provide both encryption and authentication, whereas CTR only provides
  # encryption.  
  iv = Crypto.Random.new().read(16)
  stateful_counter_128bit_blocks = Crypto.Util.Counter.new(128,
                                      initial_value=long(iv.encode('hex'), 16)) 
  symmetric_key = derived_key_information['derived_key'] 
  aes_cipher = Crypto.Cipher.AES.new(symmetric_key,
                                     Crypto.Cipher.AES.MODE_CTR,
                                     counter=stateful_counter_128bit_blocks)
 
  # Use AES-256 to encrypt 'key_data'.  The key size determines how many cycle
  # repetitions are performed by AES, 14 cycles for 256-bit keys.
  try:
    ciphertext = aes_cipher.encrypt(key_data)
  except:
    message = 'The key data could not be encrypted.' 
    raise tuf.CryptoError(message)

  # Generate the hmac of the ciphertext to ensure it has not been modified.
  # The decryption routine may verify a ciphertext without having to perform
  # a decryption operation.
  salt = derived_key_information['salt'] 
  derived_key = derived_key_information['derived_key']
  hmac_object = Crypto.Hash.HMAC.new(derived_key, ciphertext, Crypto.Hash.SHA256)
  hmac = hmac_object.hexdigest()

  # Return the hmac, initialization vector, and ciphertext as a single string.
  # These three values are delimited by '_ENCRYPTION_DELIMITER' to make
  # extraction easier.  This delimiter is arbitrarily chosen and should not
  # occur in the hexadecimal representations of the fields it is separating.
  return binascii.hexlify(salt) + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(hmac) + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(iv) + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(ciphertext)





def _decrypt(file_contents, password):
  """
  The corresponding decryption routine for _encrypt().

  'tuf.CryptoError' raised if the decryption fails.
  
  """
 
  # Extract the salt, hmac, initialization vector, and ciphertext from
  # 'file_contents'.  These three values are delimited by '_ENCRYPTION_DELIMITER'.
  # This delimiter is arbitrarily chosen and should not occur in the
  # hexadecimal representations of the fields it is separating.
  salt, hmac, iv, ciphertext = file_contents.split(_ENCRYPTION_DELIMITER)
  
  # Ensure we have the expected raw data for the delimited cryptographic data. 
  salt =  binascii.unhexlify(salt)
  hmac = binascii.unhexlify(hmac)
  iv = binascii.unhexlify(iv)
  ciphertext = binascii.unhexlify(ciphertext)

  # Generate derived key from 'password'.  The salt is specified so that
  # the expected derived key is regenerated correctly.
  junk, derived_key = _generate_derived_key(password, salt)

  # Verify the hmac to ensure the ciphertext is valid and has not been altered.
  # See the encryption routine for why we use the encrypt-then-MAC approach.
  generated_hmac_object = Crypto.Hash.HMAC.new(derived_key, ciphertext,
                                               Crypto.Hash.SHA256)
  generated_hmac = generated_hmac_object.hexdigest()

  if generated_hmac != hmac:
    raise tuf.CryptoError('Decryption failed.')

  # The following decryption routine assumes 'ciphertext' was encrypted with
  # AES-256.
  stateful_counter_128bit_blocks = Crypto.Util.Counter.new(128,
                                      initial_value=long(iv.encode('hex'), 16)) 
  aes_cipher = Crypto.Cipher.AES.new(derived_key,
                                     Crypto.Cipher.AES.MODE_CTR,
                                     counter=stateful_counter_128bit_blocks)
  try:
    key_plaintext = aes_cipher.decrypt(ciphertext)
  except: 
    raise tuf.CryptoError('Decryption failed.')

  return key_plaintext
