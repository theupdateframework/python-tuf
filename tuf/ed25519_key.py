"""
<Program Name>
  ed25519_key.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  September 24, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to support ed25519 signatures.  ed25519 is an
  elliptic-curve public key signature scheme, its main strength being small
  signatures (64 bytes) and small public keys (32 bytes).
  http://ed25519.cr.yp.to/
  
  'tuf/ed25519_key.py' calls 'ed25519/ed25519.py', which is the pure Python
  implementation of ed25519 provided by the author:
  http://ed25519.cr.yp.to/software.html
  Optionally, ed25519 cryptographic operations may be executed by PyNaCl, which
  provides Python bindings to the NaCl library and is much faster than the pure
  python implementation.  PyNaCl relies on the C library, libsodium.
  
  https://github.com/dstufft/pynacl
  https://github.com/jedisct1/libsodium
  http://nacl.cr.yp.to/
  
  The ed25519-related functions included here are generate(), create_signature()
  and verify_signature().  The 'ed25519' and PyNaCl (i.e., 'nacl') modules used 
  by ed25519_key.py generate the actual ed25519 keys and the functions listed
  above can be viewed as an easy-to-use public interface.  Additional functions
  contained here include format_keyval_to_metadata() and
  format_metadata_to_key().  These last two functions produce or use
  ed25519 keys compatible with the key structures listed in TUF Metadata files.
  The generate() function returns a dictionary containing all the information
  needed of ed25519 keys, such as public/private keys and a keyID identifier.
  create_signature() and verify_signature() are supplemental functions used for
  generating ed25519 signatures and verifying them.
  
  Key IDs are used as identifiers for keys (e.g., RSA key).  They are the
  hexadecimal representation of the hash of key object (specifically, the key
  object containing only the public key).  Review 'ed25519_key.py' and the
  '_get_keyid()' function to see precisely how keyids are generated.  One may
  get the keyid of a key object by simply accessing the dictionary's 'keyid'
  key (i.e., ed25519_key_dict['keyid']).
 """

# Help with Python 3 compatability, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

# Required for hexadecimal conversions.  Signatures and public/private keys are
# hexlified.
import binascii

# Generate OS-specific randomness (os.urandom) suitable for cryptographic use.
# http://docs.python.org/2/library/os.html#miscellaneous-functions
import os

import tuf

# Import the python implementation of the ed25519 algorithm that is provided by
# the author.  Note: This implementation is very slow and does not include
# protection against side-channel attacks according to the author.  Verifying
# signatures can take approximately 9 seconds on an intel core 2 duo @
# 2.2 ghz x 2).  Optionally, the PyNaCl module may be used to speed up ed25519
# cryptographic operations.
# http://ed25519.cr.yp.to/software.html
# Try to import PyNaCl.  The functions found in this module provide the option
# of using PyNaCl over the slower implementation of ed25519.
try:
  import nacl.signing
  import nacl.encoding
except (ImportError, IOError):
  message = 'The PyNacl library and/or its dependencies cannot be imported.'
  raise tuf.UnsupportedLibraryError(message)

# The pure Python implementation of ed25519.
import ed25519.ed25519

# Digest objects needed to generate hashes.
import tuf.hash

# Perform object format-checking.
import tuf.formats

# The default hash algorithm to use when generating KeyIDs.
_KEY_ID_HASH_ALGORITHM = 'sha256'

# Supported ed25519 signing methods.  'ed25519-python' is the pure Python
# implementation signing method.  'ed25519-pynacl' (i.e., 'nacl' module) is the
# (libsodium+Python bindings) implementation signing method. 
_SUPPORTED_ED25519_SIGNING_METHODS = ['ed25519-python', 'ed25519-pynacl']


def generate(use_pynacl=False):
  """
  <Purpose> 
    Generate an ed25519 seed key ('sk') and public key ('pk').
    In addition, a keyid used as an identifier for ed25519 keys is generated.
    The object returned conforms to 'tuf.formats.ED25519KEY_SCHEMA' and has the
    form:
    {'keytype': 'ed25519',
     'keyid': keyid,
     'keyval': {'public': '876f5584a9db99b8546c0d8608d6...',
                'private': 'bf7336055c7638276efe9afe039...'}}
    
    The public and private keys are strings.  An ed25519 seed key is a random
    32-byte value and public key 32 bytes, although both are hexlified to 64
    bytes.

    >>> ed25519_key = generate()
    >>> tuf.formats.ED25519KEY_SCHEMA.matches(ed25519_key)
    True
    >>> len(ed25519_key['keyval']['public'])
    64
    >>> len(ed25519_key['keyval']['private'])
    64
    >>> ed25519_key_pynacl = generate(use_pynacl=True)
    >>> tuf.formats.ED25519KEY_SCHEMA.matches(ed25519_key_pynacl)
    True
    >>> len(ed25519_key_pynacl['keyval']['public'])
    64
    >>> len(ed25519_key_pynacl['keyval']['private'])
    64

  <Arguments>
    use_pynacl:
      True, if the ed25519 keys should be generated with PyNaCl.  False, if the
      keys should be generated with the pure Python implementation of ed25519
      (much slower).

  <Exceptions>
    NotImplementedError, if a randomness source is not found.

  <Side Effects>
    The ed25519 keys are generated by first creating a random 32-byte value
    'sk' with os.urandom() and then calling ed25519's ed25519.25519.publickey(sk)
    or PyNaCl's nacl.signing.SigningKey().

  <Returns>
    A dictionary containing the ed25519 keys and other identifying information.
    Conforms to 'tuf.formats.ED25519KEY_SCHEMA'.
  """

  # Begin building the ed25519 key dictionary. 
  ed25519_key_dict = {}
  keytype = 'ed25519'
 
  # Generate ed25519's seed key by calling os.urandom().  The random bytes
  # returned should be suitable for cryptographic use and is OS-specific.
  # Raise 'NotImplementedError' if a randomness source is not found.
  # ed25519 seed keys are fixed at 32 bytes (256-bit keys).
  # http://blog.mozilla.org/warner/2011/11/29/ed25519-keys/ 
  seed = os.urandom(32)
  public = None

  if use_pynacl:
    # Generate the public key.  PyNaCl (i.e., 'nacl' module) performs
    # the actual key generation.
    nacl_key = nacl.signing.SigningKey(seed)
    public = str(nacl_key.verify_key)
  
  # Use the pure Python implementation of ed25519. 
  else: 
    public = ed25519.ed25519.publickey(seed)
  
  # Generate the keyid for the ed25519 key dict.  'key_value' corresponds to the
  # 'keyval' entry of the 'ED25519KEY_SCHEMA' dictionary.  The seed (private)
  # key information is not included in the generation of the 'keyid' identifier.
  key_value = {'public': binascii.hexlify(public),
               'private': ''}
  keyid = _get_keyid(key_value)

  # Build the 'ed25519_key_dict' dictionary.  Update 'key_value' with the
  # ed25519 seed key prior to adding 'key_value' to 'ed25519_key_dict'.
  key_value['private'] = binascii.hexlify(seed)

  ed25519_key_dict['keytype'] = keytype
  ed25519_key_dict['keyid'] = keyid
  ed25519_key_dict['keyval'] = key_value

  return ed25519_key_dict





def format_keyval_to_metadata(key_value, private=False):
  """
  <Purpose>
    Return a dictionary conformant to 'tuf.formats.KEY_SCHEMA'.
    If 'private' is True, include the private key.  The dictionary
    returned has the form:
    {'keytype': 'ed25519',
     'keyval': {'public': '876f5584a9db99b8546c0d8608d6...',
                'private': 'bf7336055c7638276efe9afe039...'}}
    
    or if 'private' is False:

    {'keytype': 'ed25519',
     'keyval': {'public': '876f5584a9db99b8546c0d8608d6...',
                'private': ''}}
    
    The private and public keys are 32 bytes, although hexlified to 64 bytes.
    
    ed25519 keys are stored in Metadata files (e.g., root.txt) in the format
    returned by this function.

    >>> ed25519_key = generate()
    >>> key_val = ed25519_key['keyval']
    >>> ed25519_metadata = format_keyval_to_metadata(key_val, private=True)
    >>> tuf.formats.KEY_SCHEMA.matches(ed25519_metadata)
    True
  
  <Arguments>
    key_value:
      A dictionary containing a seed and public ed25519 key.
      'key_value' is of the form:

      {'public': '876f5584a9db99b8546c0d8608d6...',
       'private': 'bf7336055c7638276efe9afe039...'}
      
      conformat to 'tuf.formats.KEYVAL_SCHEMA'.

    private:
      Indicates if the private key should be included in the
      returned dictionary.

  <Exceptions>
    tuf.FormatError, if 'key_value' does not conform to 
    'tuf.formats.KEYVAL_SCHEMA'.

  <Side Effects>
    None.

  <Returns>
    A 'KEY_SCHEMA' dictionary.
  """

  # Does 'key_value' have the correct format?
  # This check will ensure 'key_value' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.KEYVAL_SCHEMA.check_match(key_value)

  if private is True and len(key_value['private']):
    return {'keytype': 'ed25519', 'keyval': key_value}
  else:
    public_key_value = {'public': key_value['public'], 'private': ''}
    return {'keytype': 'ed25519', 'keyval': public_key_value}





def format_metadata_to_key(key_metadata):
  """
  <Purpose>
    Construct an ed25519 key dictionary (i.e., tuf.formats.ED25519KEY_SCHEMA)
    from 'key_metadata'.  The dict returned by this function has the exact
    format as the dict returned by generate().  It is of the form:
   
    {'keytype': 'ed25519',
     'keyid': keyid,
     'keyval': {'public': '876f5584a9db99b8546c0d8608d6...',
                'private': 'bf7336055c7638276efe9afe039...'}}

    The public and private keys are 32-byte strings, although hexlified to 64
    bytes.

    ed25519 key dictionaries in 'ED25519KEY_SCHEMA' format should be used by
    modules storing a collection of keys, such as a keydb keystore.
    ed25519 keys as stored in metadata files use a different format, so this 
    function should be called if an ed25519 key is extracted from one of these 
    metadata files and needs converting.  Generate() creates an entirely
    new key and returns it in the format appropriate for 'keydb.py' and
    'keystore.py'.

    >>> ed25519_key = generate()
    >>> key_val = ed25519_key['keyval']
    >>> ed25519_metadata = format_keyval_to_metadata(key_val, private=True)
    >>> ed25519_key_2 = format_metadata_to_key(ed25519_metadata)
    >>> tuf.formats.ED25519KEY_SCHEMA.matches(ed25519_key_2)
    True
    >>> ed25519_key == ed25519_key_2
    True

  <Arguments>
    key_metadata:
      The ed25519 key dictionary as stored in Metadata files, conforming to
      'tuf.formats.KEY_SCHEMA'.  It has the form:
      
      {'keytype': 'ed25519',
       'keyval': {'public': '876f5584a9db99b8546c0d8608d6...',
                  'private': 'bf7336055c7638276efe9afe039...'}}

  <Exceptions>
    tuf.FormatError, if 'key_metadata' does not conform to
    'tuf.formats.KEY_SCHEMA'.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the ed25519 keys and other identifying information.
  """
  
  # Does 'key_metadata' have the correct format?
  # This check will ensure 'key_metadata' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.KEY_SCHEMA.check_match(key_metadata)

  # Construct the dictionary to be returned.
  ed25519_key_dict = {}
  keytype = 'ed25519'
  key_value = key_metadata['keyval']

  # Convert 'key_value' to 'tuf.formats.KEY_SCHEMA' and generate its hash
  # The hash is in hexdigest form.  _get_keyid() ensures the private key
  # information is not included.
  keyid = _get_keyid(key_value)

  # We now have all the required key values.  Build 'ed25519_key_dict'.
  ed25519_key_dict['keytype'] = keytype
  ed25519_key_dict['keyid'] = keyid
  ed25519_key_dict['keyval'] = key_value

  return ed25519_key_dict





def _get_keyid(key_value):
  """Return the keyid for 'key_value'."""

  # 'keyid' will be generated from an object conformant to 'KEY_SCHEMA',
  # which is the format Metadata files (e.g., root.txt) store keys.
  # 'format_keyval_to_metadata()' returns the object needed by _get_keyid().
  ed25519_key_meta = format_keyval_to_metadata(key_value, private=False)

  # Convert the ed25519 key to JSON Canonical format suitable for adding
  # to digest objects.
  ed25519_key_update_data = tuf.formats.encode_canonical(ed25519_key_meta)

  # Create a digest object and call update(), using the JSON 
  # canonical format of 'ed25519_key_meta' as the update data.
  digest_object = tuf.hash.digest(_KEY_ID_HASH_ALGORITHM)
  digest_object.update(ed25519_key_update_data)

  # 'keyid' becomes the hexadecimal representation of the hash.  
  keyid = digest_object.hexdigest()

  return keyid





def create_signature(ed25519_key_dict, data, use_pynacl=False):
  """
  <Purpose>
    Return a signature dictionary of the form:
    {'keyid': 'a0469d9491e3c0b42dd41fe3455359dbacb3306b6e8fb59...',
     'method': 'ed25519-python',
     'sig': '4b3829671b2c6b90034518a918d2447c722474c878c2431dd...'}

     Note: 'method' may also be 'ed25519-pynacl', if the signature was created
     by the 'nacl' module.

    The signing process will use the public and seed key
    ed25519_key_dict['keyval']['private'],
    ed25519_key_dict['keyval']['public']
    
    and 'data' to generate the signature.
    
    >>> ed25519_key_dict = generate()
    >>> data = 'The quick brown fox jumps over the lazy dog.'
    >>> signature = create_signature(ed25519_key_dict, data)
    >>> tuf.formats.SIGNATURE_SCHEMA.matches(signature)
    True
    >>> len(signature['sig'])
    128
    >>> signature_pynacl = create_signature(ed25519_key_dict, data, True)
    >>> tuf.formats.SIGNATURE_SCHEMA.matches(signature_pynacl)
    True
    >>> len(signature_pynacl['sig'])
    128

  <Arguments>
    ed25519_key_dict:
      A dictionary containing the ed25519 keys and other identifying information.
      'ed25519_key_dict' has the form:
    
      {'keytype': 'ed25519',
       'keyid': keyid,
       'keyval': {'public': '876f5584a9db99b8546c0d8608d6...',
                  'private': 'bf7336055c7638276efe9afe039...'}}

      The public and private keys are 32-byte strings, although hexlified to 64
      bytes.

    data:
      Data object used by create_signature() to generate the signature.
    
    use_pynacl:
      True, if the ed25519 signature should be generated with PyNaCl.  False,
      if the signature should be generated with the pure Python implementation
      of ed25519 (much slower).

  <Exceptions>
    TypeError, if a private key is not defined for 'ed25519_key_dict'.

    tuf.FormatError, if an incorrect format is found for 'ed25519_key_dict'.

    tuf.CryptoError, if a signature cannot be created.

  <Side Effects>
    ed25519.ed25519.signature() or nacl.signing.SigningKey.sign() called to
    generate the actual signature.

  <Returns>
    A signature dictionary conformat to 'tuf.format.SIGNATURE_SCHEMA'.
    ed25519 signatures are 64 bytes, however, the hexlified signature
    (128 bytes) is stored in the dictionary returned.
  """

  # Does 'ed25519_key_dict' have the correct format?
  # This check will ensure 'ed25519_key_dict' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ED25519KEY_SCHEMA.check_match(ed25519_key_dict)

  # Signing the 'data' object requires a seed and public key.
  # 'ed25519.ed25519.py' generates the actual 64-byte signature in pure Python.
  # nacl.signing.SigningKey.sign() generates the signature if 'use_pynacl'
  # is True.
  signature = {}
  private_key = ed25519_key_dict['keyval']['private']
  public_key = ed25519_key_dict['keyval']['public']
  private_key = binascii.unhexlify(private_key)
  public_key = binascii.unhexlify(public_key)

  keyid = ed25519_key_dict['keyid']
  method = None 
  sig = None
 
  # Verify the signature, but only if the private key has been set.  The private
  # key is a NULL string if unset.  Although it may be clearer to explicit check
  # that 'private_key' is not '', we can/should check for a value and not
  # compare identities with the 'is' keyword. 
  if len(private_key):
    if use_pynacl:
      method = 'ed25519-pynacl'
      try:
        nacl_key = nacl.signing.SigningKey(private_key)
        nacl_sig = nacl_key.sign(data)
        sig = nacl_sig.signature
      except (ValueError, nacl.signing.CryptoError):
        message = 'An "ed25519-pynacl" signature could not be created.'
        raise tuf.CryptoError(message)
     
    # Generate an "ed25519-python" (i.e., pure python implementation) signature.
    else:
      # ed25519.ed25519.signature() requires both the seed and public keys.
      # It calculates the SHA512 of the seed key, which is 32 bytes.
      method = 'ed25519-python'
      try:
        sig = ed25519.ed25519.signature(data, private_key, public_key)
      except Exception, e:
        message = 'An "ed25519-python" signature could not be generated.'
        raise tuf.CryptoError(message)
  
  # Raise an exception since the private key is not defined.
  else:
    message = 'The required private key is not defined for "ed25519_key_dict".'
    raise TypeError(message)

  # Build the signature dictionary to be returned.
  # The hexadecimal representation of 'sig' is stored in the signature.
  signature['keyid'] = keyid
  signature['method'] = method
  signature['sig'] = binascii.hexlify(sig)

  return signature





def verify_signature(ed25519_key_dict, signature, data, use_pynacl=False):
  """
  <Purpose>
    Determine whether the seed key belonging to 'ed25519_key_dict' produced
    'signature'.  verify_signature() will use the public key found in
    'ed25519_key_dict', the 'method' and 'sig' objects contained in 'signature',
    and 'data' to complete the verification.  Type-checking performed on both
    'ed25519_key_dict' and 'signature'.

    >>> ed25519_key_dict = generate()
    >>> data = 'The quick brown fox jumps over the lazy dog.'
    >>> signature = create_signature(ed25519_key_dict, data)
    >>> verify_signature(ed25519_key_dict, signature, data)
    True
    >>> verify_signature(ed25519_key_dict, signature, data, True)
    True
    >>> bad_data = 'The sly brown fox jumps over the lazy dog.'
    >>> bad_signature = create_signature(ed25519_key_dict, bad_data)
    >>> verify_signature(ed25519_key_dict, bad_signature, data, True)
    False
  
  <Arguments>
    ed25519_key_dict:
      A dictionary containing the ed25519 keys and other identifying
      information.  'ed25519_key_dict' has the form:
     
      {'keytype': 'ed25519',
       'keyid': 'a0469d9491e3c0b42dd41fe3455359dbacb3306b6e8fb59...',
       'keyval': {'public': '876f5584a9db99b8546c0d8608d6...',
                  'private': 'bf7336055c7638276efe9afe039...'}}

      The public and private keys are 32-byte strings, although hexlified to
      64 bytes.
      
    signature:
      The signature dictionary produced by tuf.ed25519_key.create_signature().
      'signature' has the form:
      
      {'keyid': 'a0469d9491e3c0b42dd41fe3455359dbacb3306b6e8fb59...',
       'method': 'ed25519-python',
       'sig': '4b3829671b2c6b90034518a918d2447c722474c878c2431dd...'}
      
      Conformant to 'tuf.formats.SIGNATURE_SCHEMA'.
      
    data:
      Data object used by tuf.ed25519_key.create_signature() to generate
      'signature'.  'data' is needed here to verify the signature.
    
    use_pynacl:
      True, if the ed25519 signature should be verified with PyNaCl.  False,
      if the signature should be verified with the pure Python implementation
      of ed25519 (much slower).

  <Exceptions>
    tuf.UnknownMethodError.  Raised if the signing method used by
    'signature' is not one supported by tuf.ed25519_key.create_signature().
    
    tuf.FormatError. Raised if either 'ed25519_key_dict'
    or 'signature' do not match their respective tuf.formats schema.
    'ed25519_key_dict' must conform to 'tuf.formats.ED25519KEY_SCHEMA'.
    'signature' must conform to 'tuf.formats.SIGNATURE_SCHEMA'.

  <Side Effects>
    ed25519.ed25519.checkvalid() called to do the actual verification.
    nacl.signing.VerifyKey.verify() called if 'use_pynacl' is True.

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """

  # Does 'ed25519_key_dict' have the correct format?
  # This check will ensure 'ed25519_key_dict' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ED25519KEY_SCHEMA.check_match(ed25519_key_dict)

  # Does 'signature' have the correct format?
  tuf.formats.SIGNATURE_SCHEMA.check_match(signature)

  # Using the public key belonging to 'ed25519_key_dict'
  # (i.e., ed25519_key_dict['keyval']['public']), verify whether 'signature'
  # was produced by ed25519_key_dict's corresponding seed key
  # ed25519_key_dict['keyval']['private'].  Before returning the Boolean result,
  # ensure 'ed25519-python' or 'ed25519-pynacl' was used as the signing method.
  method = signature['method']
  sig = signature['sig']
  sig = binascii.unhexlify(sig)
  public = ed25519_key_dict['keyval']['public']
  public = binascii.unhexlify(public)
  valid_signature = False

  if method in _SUPPORTED_ED25519_SIGNING_METHODS:
    if use_pynacl: 
      try:
        nacl_verify_key = nacl.signing.VerifyKey(public)
        nacl_message = nacl_verify_key.verify(data, sig) 
        if nacl_message == data:
          valid_signature = True
      except nacl.signing.BadSignatureError:
        pass 
    
    # Verify signature with 'ed25519-python' (i.e., pure Python implementation). 
    else:
      try:
        ed25519.ed25519.checkvalid(sig, data, public)
        valid_signature = True
      
      # The pure Python implementation raises 'Exception' if 'signature' is
      # invalid.
      except Exception, e:
        pass
  else:
    message = 'Unsupported ed25519 signing method: '+repr(method)+'.\n'+ \
      'Supported methods: '+repr(_SUPPORTED_ED25519_SIGNING_METHODS)+'.'
    raise tuf.UnknownMethodError(message)

  return valid_signature 



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'ed25519_key.py' as a standalone module.
  # python -B ed25519_key.py
  import doctest
  doctest.testmod()
