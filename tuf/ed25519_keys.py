"""
<Program Name>
  ed25519_keys.py

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
  
  'tuf/ed25519_keys.py' calls 'ed25519.py', which is the pure Python
  implementation of ed25519 optimized for a faster runtime.  The Python
  reference implementation is concise, but very slow (verifying signatures
  takes ~9 seconds on an Intel core 2 duo @ 2.2 ghz x 2).  The optimized
  version can verify signatures in ~2 seconds.

  http://ed25519.cr.yp.to/software.html
  https://github.com/pyca/ed25519
  
  Optionally, ed25519 cryptographic operations may be executed by PyNaCl, which
  is a Python binding to the NaCl library and is faster than the pure python
  implementation.  Verifying signatures can take approximately 0.0009 seconds.
  PyNaCl relies on the libsodium C library.  PyNaCl is required for key and
  signature generation.  Verifying signatures may be done in pure Python.
 
  https://github.com/pyca/pynacl
  https://github.com/jedisct1/libsodium
  http://nacl.cr.yp.to/
  https://github.com/pyca/ed25519
  
  The ed25519-related functions included here are generate(), create_signature()
  and verify_signature().  The 'ed25519' and PyNaCl (i.e., 'nacl') modules used 
  by ed25519_keys.py perform the actual ed25519 computations and the functions
  listed above can be viewed as an easy-to-use public interface.
 """

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# 'binascii' required for hexadecimal conversions.  Signatures and
# public/private keys are hexlified.
import binascii

# TODO:  The 'warnings' module needed to temporarily suppress user warnings
# raised by 'pynacl' (as of version 0.2.3).  Warnings temporarily suppressed
# here to avoid confusing users with an unexpected error message that gives
# no indication of its source.  These warnings are printed when using
# the repository tools, including for clients that request an update.
# http://docs.python.org/2/library/warnings.html#temporarily-suppressing-warnings
import warnings

# 'os' required to generate OS-specific randomness (os.urandom) suitable for
# cryptographic use.
# http://docs.python.org/2/library/os.html#miscellaneous-functions
import os

# Import the python implementation of the ed25519 algorithm provided by pyca,
# which is an optimized version of the one provided by ed25519's authors.
# Note: The pure Python version does not include protection against side-channel
# attacks.  Verifying signatures can take approximately 2 seconds on an intel
# core 2 duo @ 2.2 ghz x 2).  Optionally, the PyNaCl module may be used to
# speed up ed25519 cryptographic operations.
# http://ed25519.cr.yp.to/software.html
# https://github.com/pyca/ed25519
# https://github.com/pyca/pynacl
#
# Import the PyNaCl library, if available.  It is recommended this library be
# used over the pure python implementation of ed25519, due to its speedier
# routines and side-channel protections available in the libsodium library.
# 
# TODO: Version 0.2.3 of 'pynacl' prints: "UserWarning: reimporting '...' might
# overwrite older definitions." when importing 'nacl.signing'.  Suppress user
# warnings temporarily (at least until this issue is fixed by PyNaCl).
#
# Note: A 'pragma: no cover' comment is intended for test 'coverage'.  Lines
# or code blocks with this comment should not be flagged as uncovered.
# pynacl will always be install prior to running the unit tests.
with warnings.catch_warnings():
  warnings.simplefilter('ignore')
  try:
    import nacl.signing
    import nacl.encoding
  
  # PyNaCl's 'cffi' dependency may raise an 'IOError' exception when importing
  # 'nacl.signing'.
  except (ImportError, IOError): # pragma: no cover
    pass

# The optimized pure Python implementation of ed25519 provided by TUF.  If
# PyNaCl cannot be imported and an attempt to use is made in this module, a
# 'tuf.UnsupportedLibraryError' exception is raised.  
import tuf._vendor.ed25519.ed25519

import tuf

# Digest objects needed to generate hashes.
import tuf.hash

# Perform object format-checking.
import tuf.formats

# Supported ed25519 signing method: 'ed25519'.  The pure Python implementation
# (i.e., ed25519') and PyNaCl (i.e., 'nacl', libsodium+Python bindings) modules
# are currently supported in the creationg of 'ed25519' signatures.
# Previously, a distinction was made between signatures made by the pure Python
# implementation and PyNaCl. 
_SUPPORTED_ED25519_SIGNING_METHODS = ['ed25519']


def generate_public_and_private():
  """
  <Purpose> 
    Generate a pair of ed25519 public and private keys with PyNaCl.  The public
    and private keys returned conform to 'tuf.formats.ED25519PULIC_SCHEMA' and
    'tuf.formats.ED25519SEED_SCHEMA', respectively, and have the form:
    
    '\xa2F\x99\xe0\x86\x80%\xc8\xee\x11\xb95T\xd9\...'

    An ed25519 seed key is a random 32-byte string.  Public keys are also 32
    bytes.

    >>> public, private = generate_public_and_private()
    >>> tuf.formats.ED25519PUBLIC_SCHEMA.matches(public)
    True
    >>> tuf.formats.ED25519SEED_SCHEMA.matches(private)
    True

  <Arguments>
    None.

  <Exceptions>
    tuf.UnsupportedLibraryError, if the PyNaCl ('nacl') module is unavailable.

    NotImplementedError, if a randomness source is not found by 'os.urandom'.

  <Side Effects>
    The ed25519 keys are generated by first creating a random 32-byte seed
    with os.urandom() and then calling PyNaCl's nacl.signing.SigningKey().

  <Returns>
    A (public, private) tuple that conform to 'tuf.formats.ED25519PUBLIC_SCHEMA'
    and 'tuf.formats.ED25519SEED_SCHEMA', respectively.
  """

  # Generate ed25519's seed key by calling os.urandom().  The random bytes
  # returned should be suitable for cryptographic use and is OS-specific.
  # Raise 'NotImplementedError' if a randomness source is not found.
  # ed25519 seed keys are fixed at 32 bytes (256-bit keys).
  # http://blog.mozilla.org/warner/2011/11/29/ed25519-keys/ 
  seed = os.urandom(32)
  public = None

  # Generate the public key.  PyNaCl (i.e., 'nacl' module) performs the actual
  # key generation.
  try:
    nacl_key = nacl.signing.SigningKey(seed)
    public = nacl_key.verify_key.encode(encoder=nacl.encoding.RawEncoder())
  
  except NameError: # pragma: no cover
    message = 'The PyNaCl library and/or its dependencies unavailable.'
    raise tuf.UnsupportedLibraryError(message)
  
  return public, seed





def create_signature(public_key, private_key, data):
  """
  <Purpose>
    Return a (signature, method) tuple, where the method is 'ed25519' and is
    always generated by PyNaCl (i.e., 'nacl').  The signature returned conforms
    to 'tuf.formats.ED25519SIGNATURE_SCHEMA', and has the form:
    
    '\xae\xd7\x9f\xaf\x95{bP\x9e\xa8YO Z\x86\x9d...'

    A signature is a 64-byte string.

    >>> public, private = generate_public_and_private()
    >>> data = b'The quick brown fox jumps over the lazy dog'
    >>> signature, method = \
        create_signature(public, private, data)
    >>> tuf.formats.ED25519SIGNATURE_SCHEMA.matches(signature)
    True
    >>> method == 'ed25519'
    True
    >>> signature, method = \
        create_signature(public, private, data)
    >>> tuf.formats.ED25519SIGNATURE_SCHEMA.matches(signature)
    True
    >>> method == 'ed25519'
    True

  <Arguments>
    public:
      The ed25519 public key, which is a 32-byte string.
    
    private:
      The ed25519 private key, which is a 32-byte string.

    data:
      Data object used by create_signature() to generate the signature.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.CryptoError, if a signature cannot be created.

  <Side Effects>
    nacl.signing.SigningKey.sign() called to generate the actual signature.

  <Returns>
    A signature dictionary conformat to 'tuf.format.SIGNATURE_SCHEMA'.
    ed25519 signatures are 64 bytes, however, the hexlified signature is
    stored in the dictionary returned.
  """
  
  # Does 'public_key' have the correct format?
  # This check will ensure 'public_key' conforms to
  # 'tuf.formats.ED25519PUBLIC_SCHEMA', which must have length 32 bytes.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ED25519PUBLIC_SCHEMA.check_match(public_key)

  # Is 'private_key' properly formatted?
  tuf.formats.ED25519SEED_SCHEMA.check_match(private_key)
  
  # Signing the 'data' object requires a seed and public key.
  # nacl.signing.SigningKey.sign() generates the signature.
  public = public_key
  private = private_key

  method = None 
  signature = None
 
  # The private and public keys have been validated above by 'tuf.formats' and
  # should be 32-byte strings.
  method = 'ed25519'
  try:
    nacl_key = nacl.signing.SigningKey(private)
    nacl_sig = nacl_key.sign(data)
    signature = nacl_sig.signature
  
  except NameError: # pragma: no cover
    message = 'The PyNaCl library and/or its dependencies unavailable.'
    raise tuf.UnsupportedLibraryError(message)
  
  except (ValueError, TypeError, nacl.exceptions.CryptoError) as e:
    message = 'An "ed25519" signature could not be created with PyNaCl.'
    raise tuf.CryptoError(message + str(e))
   
  return signature, method





def verify_signature(public_key, method, signature, data, use_pynacl=False):
  """
  <Purpose>
    Determine whether the private key corresponding to 'public_key' produced
    'signature'.  verify_signature() will use the public key, the 'method' and
    'sig', and 'data' arguments to complete the verification.

    >>> public, private = generate_public_and_private()
    >>> data = b'The quick brown fox jumps over the lazy dog'
    >>> signature, method = \
        create_signature(public, private, data)
    >>> verify_signature(public, method, signature, data, use_pynacl=False)
    True
    >>> verify_signature(public, method, signature, data, use_pynacl=True)
    True
    >>> bad_data = b'The sly brown fox jumps over the lazy dog'
    >>> bad_signature, method = \
        create_signature(public, private, bad_data)
    >>> verify_signature(public, method, bad_signature, data, use_pynacl=False)
    False
  
  <Arguments>
    public_key:
      The public key is a 32-byte string.

    method:
      'ed25519' signature method generated by either the pure python
      implementation (i.e., ed25519.py) or PyNacl (i.e., 'nacl').
      
    signature:
      The signature is a 64-byte string. 
      
    data:
      Data object used by tuf.ed25519_keys.create_signature() to generate
      'signature'.  'data' is needed here to verify the signature.
    
    use_pynacl:
      True, if the ed25519 signature should be verified by PyNaCl.  False,
      if the signature should be verified with the pure Python implementation
      of ed25519 (slower).

  <Exceptions>
    tuf.UnknownMethodError.  Raised if the signing method used by
    'signature' is not one supported by tuf.ed25519_keys.create_signature().
    
    tuf.FormatError. Raised if the arguments are improperly formatted. 

  <Side Effects>
    tuf._vendor.ed25519.ed25519.checkvalid() called to do the actual
    verification.  nacl.signing.VerifyKey.verify() called if 'use_pynacl' is
    True.

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """
  
  # Does 'public_key' have the correct format?
  # This check will ensure 'public_key' conforms to
  # 'tuf.formats.ED25519PUBLIC_SCHEMA', which must have length 32 bytes.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ED25519PUBLIC_SCHEMA.check_match(public_key)

  # Is 'method' properly formatted?
  tuf.formats.NAME_SCHEMA.check_match(method)
  
  # Is 'signature' properly formatted?
  tuf.formats.ED25519SIGNATURE_SCHEMA.check_match(signature)
  
  # Is 'use_pynacl' properly formatted?
  tuf.formats.BOOLEAN_SCHEMA.check_match(use_pynacl)

  # Verify 'signature'.  Before returning the Boolean result,
  # ensure 'ed25519' was used as the signing method.
  # Raise 'tuf.UnsupportedLibraryError' if 'use_pynacl' is True but 'nacl' is
  # unavailable.
  public = public_key
  valid_signature = False

  if method in _SUPPORTED_ED25519_SIGNING_METHODS:
    if use_pynacl: 
      try:
        nacl_verify_key = nacl.signing.VerifyKey(public)
        nacl_message = nacl_verify_key.verify(data, signature) 
        valid_signature = True
      
      except NameError: # pragma: no cover
        message = 'The PyNaCl library and/or its dependencies unavailable.'
        raise tuf.UnsupportedLibraryError(message)
      
      except nacl.exceptions.BadSignatureError:
        pass 
    
    # Verify 'ed25519' signature with the pure Python implementation. 
    else:
      try:
        tuf._vendor.ed25519.ed25519.checkvalid(signature, data, public)
        valid_signature = True
      
      # The pure Python implementation raises 'Exception' if 'signature' is
      # invalid.
      except Exception as e:
        pass
  
  else:
    message = 'Unsupported ed25519 signing method: '+repr(method)+'.\n'+ \
      'Supported methods: '+repr(_SUPPORTED_ED25519_SIGNING_METHODS)+'.'
    raise tuf.UnknownMethodError(message)

  return valid_signature 



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'ed25519_keys.py' as a standalone module.
  # python -B ed25519_keys.py
  import doctest
  doctest.testmod()
