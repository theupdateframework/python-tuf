"""
<Program Name>
  pycrypto_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 7, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to support public-key cryptography and RSA
  keys through the PyCrypto library.  The RSA-related functions provided:
  generate_rsa_public_and_private()
  create_rsa_signature()
  verify_rsa_signature()
  create_rsa_encrypted_pem()
  create_rsa_public_and_private_from_encrypted_pem()
  
  PyCrypto (i.e., the 'Crypto' package) performs the actual cryptographic
  operations and the functions listed above can be viewed as an easy-to-use
  public interface. 
  
  https://en.wikipedia.org/wiki/RSA_(algorithm)
  https://github.com/dlitz/pycrypto 
  
  The <keyid>.key files are encrypted with the AES-256-CTR-Mode symmetric key
  algorithm.  User passwords are strengthened with PBKDF2, currently set to
  100,000 passphrase iterations.  The previous evpy implementation used 1,000
  iterations.
 """

import os
import binascii
import json

# Crypto.PublicKey (i.e., PyCrypto's public-key cryptography modules) supports 
# algorithms like the Digital Signature Algorithm (DSA) and the ElGamal
# encryption system.  'Crypto.PublicKey.RSA' is needed here to generate, sign,
# and verify RSA keys.
import Crypto.PublicKey.RSA

# PyCrypto requires 'Crypto.Hash' hash objects to generate PKCS#1 PSS
# signatures (i.e., Crypto.Signature.PKCS1_PSS).
import Crypto.Hash.SHA256

# RSA's probabilistic signature scheme with appendix (RSASSA-PSS).
# PKCS#1 v1.5 is available for compatibility with existing applications, but
# RSASSA-PSS is encouraged for newer applications.  RSASSA-PSS generates
# a random salt to ensure the signature generated is probabilistic rather than
# deterministic (e.g., PKCS#1 v1.5).
# http://en.wikipedia.org/wiki/RSA-PSS#Schemes 
# https://tools.ietf.org/html/rfc3447#section-8.1 
import Crypto.Signature.PKCS1_PSS

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
# 'pycrypto_keys.py'.
import Crypto.Random

# The mode of operation is presently set to CTR (CounTeR Mode) for symmetric
# block encryption (AES-256, where the symmetric key is 256 bits).  PyCrypto
# provides a callable stateful block counter that can update successive blocks
# when needed.  The initial random block, or initialization vector (IV), can
# be set to begin the process of incrementing the 128-bit blocks and allowing
# the AES algorithm to perform cipher block operations on them. 
import Crypto.Util.Counter

# Import the TUF package and TUF-defined exceptions in __init__.py.
import tuf

# Digest objects needed to generate hashes.
import tuf.hash

# Perform object format-checking.
import tuf.formats

import tuf.conf

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.
_DEFAULT_RSA_KEY_BITS = 3072 

# The delimiter symbol used to separate the different sections
# of encrypted files (i.e., salt, iterations, hmac, IV, ciphertext).
# This delimiter is arbitrarily chosen and should not occur in
# the hexadecimal representations of the fields it is separating.
_ENCRYPTION_DELIMITER = '@@@@'

# AES key size.  Default key size = 32 bytes = AES-256.
_AES_KEY_SIZE = 32

# Default salt size, in bytes.  A 128-bit salt (i.e., a random sequence of data
# to protect against attacks that use precomputed rainbow tables to crack
# password hashes) is generated for PBKDF2.  
_SALT_SIZE = 16 

# Default PBKDF2 passphrase iterations.  The current "good enough" number
# of passphrase iterations.  We recommend that important keys, such as root,
# be kept offline.  'tuf.conf.PBKDF2_ITERATIONS' should increase as CPU
# speeds increase, set here at 100,000 iterations by default (in 2013).
# Repository maintainers may opt to modify the default setting according to
# their security needs and computational restrictions.  A strong user password
# is still important.  Modifying the number of iterations will result in a new
# derived key+PBDKF2 combination if the key is loaded and re-saved, overriding
# any previous iteration setting used by the old '<keyid>.key'.
# https://en.wikipedia.org/wiki/PBKDF2
_PBKDF2_ITERATIONS = tuf.conf.PBKDF2_ITERATIONS


def generate_rsa_public_and_private(bits=_DEFAULT_RSA_KEY_BITS):
  """
  <Purpose> 
    Generate public and private RSA keys with modulus length 'bits'.
    The public and private keys returned conform to 'tuf.formats.PEMRSA_SCHEMA'
    and have the form:
    '-----BEGIN RSA PUBLIC KEY----- ...'

    or

    '-----BEGIN RSA PRIVATE KEY----- ...'
    
    The public and private keys are returned as strings in PEM format.

    Although PyCrypto sets a 1024-bit minimum key size,
    generate_rsa_public_and_private() enforces a minimum key size of 2048 bits.
    If 'bits' is unspecified, a 3072-bit RSA key is generated, which is the key
    size recommended by TUF.
    
    >>> public, private = generate_rsa_public_and_private(2048)
    >>> tuf.formats.PEMRSA_SCHEMA.matches(public)
    True
    >>> tuf.formats.PEMRSA_SCHEMA.matches(private)
    True

  <Arguments>
    bits:
      The key size, or key length, of the RSA key.  'bits' must be 2048, or
      greater, and a multiple of 256.

  <Exceptions>
    tuf.FormatError, if 'bits' does not contain the correct format.
    
    ValueError, if an exception occurs in the RSA key generation routine.
    'bits' must be a multiple of 256.  The 'ValueError' exception is raised by
    the PyCrypto key generation function.

  <Side Effects>
    The RSA keys are generated by PyCrypto's Crypto.PublicKey.RSA.generate().

  <Returns>
    A (public, private) tuple containing the RSA keys in PEM format.
  """

  # Does 'bits' have the correct format?
  # This check will ensure 'bits' conforms to 'tuf.formats.RSAKEYBITS_SCHEMA'.
  # 'bits' must be an integer object, with a minimum value of 2048.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.RSAKEYBITS_SCHEMA.check_match(bits)
  
  # Generate the public and private RSA keys.  The PyCrypto module performs
  # the actual key generation.  Raise 'ValueError' if 'bits' is less than 1024 
  # or not a multiple of 256, although a 2048-bit minimum is enforced by
  # tuf.formats.RSAKEYBITS_SCHEMA.check_match().
  rsa_key_object = Crypto.PublicKey.RSA.generate(bits)
  
  # Extract the public & private halves of the RSA key and generate their
  # PEM-formatted representations.  Return the key pair as a (public, private)
  # tuple, where each RSA is a string in PEM format.
  private = rsa_key_object.exportKey(format='PEM')
  rsa_pubkey = rsa_key_object.publickey()
  public = rsa_pubkey.exportKey(format='PEM')

  return public, private





def create_rsa_signature(private_key, data):
  """
  <Purpose>
    Generate an RSASSA-PSS signature.  The signature, and the method (signature
    algorithm) used, is returned as a (signature, method) tuple.

    The signing process will use 'private_key' and 'data' to generate the
    signature.

    RFC3447 - RSASSA-PSS 
    http://www.ietf.org/rfc/rfc3447.txt
    
    >>> public, private = generate_rsa_public_and_private(2048)
    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> signature, method = create_rsa_signature(private, data)
    >>> tuf.formats.NAME_SCHEMA.matches(method)
    True
    >>> method == 'RSASSA-PSS'
    True
    >>> tuf.formats.PYCRYPTOSIGNATURE_SCHEMA.matches(method)
    True

  <Arguments>
    private_key: 
      The private RSA key, a string in PEM format.

    data:
      Data object used by create_rsa_signature() to generate the signature.

  <Exceptions>
    tuf.FormatError, if 'private_key' is improperly formatted.
    
    TypeError, if 'private_key' is unset.

    tuf.CryptoError, if the signature cannot be generated. 

  <Side Effects>
    PyCrypto's 'Crypto.Signature.PKCS1_PSS' called to generate the signature.

  <Returns>
    A (signature, method) tuple, where the signature is a string and the method
    is 'RSASSA-PSS'.
  """
  
  # Does 'private_key' have the correct format?
  # This check will ensure 'private_key' conforms to 'tuf.formats.PEMRSA_SCHEMA'.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PEMRSA_SCHEMA.check_match(private_key)

  # Signing the 'data' object requires a private key.
  # The 'RSASSA-PSS' (i.e., PyCrypto module) signing method is the
  # only method currently supported.
  method = 'RSASSA-PSS'
  signature = None
 
  # Verify the signature, but only if the private key has been set.  The private
  # key is a NULL string if unset.  Although it may be clearer to explicit check
  # that 'private_key' is not '', we can/should check for a value and not
  # compare identities with the 'is' keyword. 
  if len(private_key):
    # Calculate the SHA256 hash of 'data' and generate the hash's PKCS1-PSS
    # signature. 
    try:
      rsa_key_object = Crypto.PublicKey.RSA.importKey(private_key)
      sha256_object = Crypto.Hash.SHA256.new(data)
      pkcs1_pss_signer = Crypto.Signature.PKCS1_PSS.new(rsa_key_object)
      signature = pkcs1_pss_signer.sign(sha256_object)
    except (ValueError, IndexError, TypeError), e:
      message = 'An RSA signature could not be generated.'
      raise tuf.CryptoError(message)
  else:
    raise TypeError('The required private key is unset.')

  return signature, method





def verify_rsa_signature(signature, signature_method, public_key, data):
  """
  <Purpose>
    Determine whether the corresponding private key of 'public_key' produced
    'signature'.  verify_signature() will use the public key, signature method,
    and 'data' to complete the verification.
    
    >>> public, private = generate_rsa_public_and_private(2048)
    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> signature, method = create_rsa_signature(private, data)
    >>> verify_rsa_signature(signature, method, public, data)
    True
    >>> verify_rsa_signature(signature, method, public, 'bad_data')
    False

  <Arguments>
    signature:
      An RSASSA PSS signature as a string.  This is the signature returned
      by create_rsa_signature(). 

    signature_method:
      A string that indicates the signature algorithm used to generate
      'signature'.  'RSASSA-PSS' is currently supported.

    public_key:
      The RSA public key, a string in PEM format.

    data:
      Data object used by tuf.rsa_key.create_signature() to generate
      'signature'.  'data' is needed here to verify the signature.

  <Exceptions>
    tuf.UnknownMethodError.  Raised if the signing method used by
    'signature' is not one supported by tuf.rsa_key.create_signature().
    
    tuf.FormatError. Raised if 'signature', 'signature_method', or 'public_key'
    is improperly formatted.

  <Side Effects>
    Crypto.Signature.PKCS1_PSS.verify() called to do the actual verification.

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """
  
  # Does 'public_key' have the correct format?
  # This check will ensure 'public_key' conforms to 'tuf.formats.PEMRSA_SCHEMA'.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PEMRSA_SCHEMA.check_match(public_key)

  # Does 'signature_method' have the correct format?
  tuf.formats.NAME_SCHEMA.check_match(signature_method)

  # Does 'signature' have the correct format?
  tuf.formats.PYCRYPTOSIGNATURE_SCHEMA.check_match(signature)

  # Verify whether the private key of 'public_key' produced the signature.
  # Before returning the Boolean result, ensure 'RSASSA-PSS' was used
  # as the signing method.
  signature = signature
  method = signature_method
  public = public_key
  valid_signature = False

  # Verify the signature with PyCrypto if the signature method is valid, else
  # raise 'tuf.UnknownMethodError'.
  if method == 'RSASSA-PSS':
    try:
      rsa_key_object = Crypto.PublicKey.RSA.importKey(public_key)
      pkcs1_pss_verifier = Crypto.Signature.PKCS1_PSS.new(rsa_key_object)
      sha256_object = Crypto.Hash.SHA256.new(data)
      valid_signature = pkcs1_pss_verifier.verify(sha256_object, signature)
    except (ValueError, IndexError, TypeError), e:
      message = 'The RSA signature could not be verified.'
      raise tuf.CryptoError(message)
  else:
    raise tuf.UnknownMethodError(method)

  return valid_signature 





def create_rsa_encrypted_pem(private_key, passphrase):
  """
  <Purpose>
    Return a string in PEM format, where the private part of the RSA key is
    encrypted.  The private part of the RSA key is encrypted by the Triple
    Data Encryption Algorithm (3DES) and Cipher-block chaining (CBC) for the 
    mode of operation.  Password-Based Key Derivation Function 1 (PBKF1) + MD5
    is used to strengthen 'passphrase'.

    https://en.wikipedia.org/wiki/Triple_DES
    https://en.wikipedia.org/wiki/PBKDF2

    >>> public, private = generate_rsa_public_and_private(2048)
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)
    >>> tuf.formats.PEMRSA_SCHEMA.matches(encrypted_pem)
    True

  <Arguments>
    private_key:
      The private key string in PEM format.

    passphrase:
      The passphrase, or password, to encrypt the private part of the RSA
      key.  'passphrase' is not used directly as the encryption key, a stronger
      encryption key is derived from it. 

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.CryptoError, if an RSA key in encrypted PEM format cannot be created.

    TypeError, 'private_key' is unset. 

  <Side Effects>
    PyCrypto's Crypto.PublicKey.RSA.exportKey() called to perform the actual
    generation of the PEM-formatted output.

  <Returns>
    A string in PEM format, where the private RSA key is encrypted.
    Conforms to 'tuf.formats.PEMRSA_SCHEMA'.
  """
  
  # Does 'private_key' have the correct format?
  # This check will ensure 'private_key' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PEMRSA_SCHEMA.check_match(private_key)
  
  # Does 'passphrase' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(passphrase)

  # 'private_key' is in PEM format and unencrypted.  The extracted key will be
  # imported and converted to PyCrypto's RSA key object
  # (i.e., Crypto.PublicKey.RSA).  Use PyCrypto's exportKey method, with a
  # passphrase specified, to create the string.  PyCrypto uses PBKDF1+MD5 to
  # strengthen 'passphrase', and 3DES with CBC mode for encryption.
  # 'private_key' may still be a NULL string after the tuf.formats check.
  if len(private_key):
    try:
      rsa_key_object = Crypto.PublicKey.RSA.importKey(private_key)
      encrypted_pem = rsa_key_object.exportKey(format='PEM',
                                               passphrase=passphrase) 
    except (ValueError, IndexError, TypeError), e:
      message = 'An encrypted RSA key in PEM format could not be generated.'
      raise tuf.CryptoError(message)
  else:
    raise TypeError('The required private key is unset.')
    

  return encrypted_pem





def create_rsa_public_and_private_from_encrypted_pem(encrypted_pem, passphrase):
  """
  <Purpose>
    Generate public and private RSA keys from an encrypted PEM.
    The public and private keys returned conform to 'tuf.formats.PEMRSA_SCHEMA'
    and have the form:
    '-----BEGIN RSA PUBLIC KEY----- ...'

    or

    '-----BEGIN RSA PRIVATE KEY----- ...'
    
    The public and private keys are returned as strings in PEM format.

    The private key part of 'encrypted_pem' is encrypted.  PyCrypto's importKey
    method is used, where a passphrase is specified.  PyCrypto uses PBKDF1+MD5
    to strengthen 'passphrase', and 3DES with CBC mode for encryption/decryption.    
    Alternatively, key data may be encrypted with AES-CTR-Mode and the passphrase
    strengthened with PBKDF2+SHA256.  See 'keystore.py'.

    >>> public, private = generate_rsa_public_and_private(2048)
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)
    >>> returned_public, returned_private = \
    create_rsa_public_and_private_from_encrypted_pem(encrypted_pem, passphrase)
    >>> tuf.formats.PEMRSA_SCHEMA.matches(returned_public)
    True
    >>> tuf.formats.PEMRSA_SCHEMA.matches(returned_private)
    True
    >>> public == returned_public
    True
    >>> private == returned_private
    True
  
  <Arguments>
    encrypted_pem:
      A byte string in PEM format, where the private key is encrypted.  It has
      the form:
      
      '-----BEGIN RSA PRIVATE KEY-----\n
      Proc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC ...'

    passphrase:
      The passphrase, or password, to decrypt the private part of the RSA
      key.  'passphrase' is not directly used as the encryption key, instead
      it is used to derive a stronger symmetric key.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    PyCrypto's 'Crypto.PublicKey.RSA.importKey()' called to perform the actual
    conversion from an encrypted RSA private key.

  <Returns>
    A (public, private) tuple containing the RSA keys in PEM format.
  """
  
  # Does 'encryped_pem' have the correct format?
  # This check will ensure 'encrypted_pem' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PEMRSA_SCHEMA.check_match(encrypted_pem)

  # Does 'passphrase' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(passphrase)
  
  try:
    rsa_key_object = Crypto.PublicKey.RSA.importKey(encrypted_pem, passphrase)
  except (ValueError, IndexError, TypeError), e:
    message = 'An RSA key object could not be generated from the encrypted '+\
      'PEM string.'
    # Raise 'tuf.CryptoError' instead of PyCrypto's exception to avoid
    # revealing sensitive error, such as a decryption error due to an
    # invalid passphrase.
    raise tuf.CryptoError(message)

  # Extract the public and private halves of the RSA key and generate their
  # PEM-formatted representations.  The dictionary returned contains the 
  # private and public RSA keys in PEM format, as strings.
  private = rsa_key_object.exportKey(format='PEM') 
  rsa_pubkey = rsa_key_object.publickey()
  public = rsa_pubkey.exportKey(format='PEM')

  return public, private





def encrypt_key(key_object, password):
  """
  <Purpose>
    Return a string in PEM format, where the private part of the RSA key is
    encrypted.  The private part of the RSA key is encrypted by the Triple
    Data Encryption Algorithm (3DES) and Cipher-block chaining (CBC) for the 
    mode of operation.  Password-Based Key Derivation Function 1 (PBKF1) + MD5
    is used to strengthen 'passphrase'.

    https://en.wikipedia.org/wiki/Triple_DES
    https://en.wikipedia.org/wiki/PBKDF2

    >>> public, private = generate_rsa_public_and_private(2048)
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)
    >>> tuf.formats.PEMRSA_SCHEMA.matches(encrypted_pem)
    True

  <Arguments>
    private_key:
      The private key string in PEM format.

    password:
      The password, or passphrase, to encrypt the private part of the RSA
      key.  'password' is not used directly as the encryption key, a stronger
      encryption key is derived from it. 

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.CryptoError, if an RSA key in encrypted PEM format cannot be created.

    TypeError, 'private_key' is unset. 

  <Side Effects>
    PyCrypto's Crypto.PublicKey.RSA.exportKey() called to perform the actual
    generation of the PEM-formatted output.

  <Returns>
    A string in PEM format, where the private RSA key is encrypted.
    Conforms to 'tuf.formats.PEMRSA_SCHEMA'.
  """
  
  # Does the arguments have the correct format?
  # This check ensures arguments have the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.KEY_SCHEMA.check_match(key_object)
  
  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  salt, iterations, derived_key = _generate_derived_key(password)
  derived_key_information = {'salt': salt, 'iterations': iterations,
                             'derived_key': derived_key}

  encrypted_key = _encrypt(json.dumps(key_object), derived_key_information)  

  return encrypted_key





def decrypt_key(encrypted_key, password):
  """
  <Purpose>
    Return a string in PEM format, where the private part of the RSA key is
    encrypted.  The private part of the RSA key is encrypted by the Triple
    Data Encryption Algorithm (3DES) and Cipher-block chaining (CBC) for the 
    mode of operation.  Password-Based Key Derivation Function 1 (PBKF1) + MD5
    is used to strengthen 'passphrase'.

    https://en.wikipedia.org/wiki/Triple_DES
    https://en.wikipedia.org/wiki/PBKDF2

    >>> public, private = generate_rsa_public_and_private(2048)
    >>> passphrase = 'secret'
    >>> encrypted_pem = create_rsa_encrypted_pem(private, passphrase)
    >>> tuf.formats.PEMRSA_SCHEMA.matches(encrypted_pem)
    True

  <Arguments>
    private_key:
      The private key string in PEM format.

    password:
      The password, or passphrase, to encrypt the private part of the RSA
      key.  'password' is not used directly as the encryption key, a stronger
      encryption key is derived from it. 

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.CryptoError, if an RSA key in encrypted PEM format cannot be created.

    TypeError, 'private_key' is unset. 

  <Side Effects>
    PyCrypto's Crypto.PublicKey.RSA.exportKey() called to perform the actual
    generation of the PEM-formatted output.

  <Returns>
    A string in PEM format, where the private RSA key is encrypted.
    Conforms to 'tuf.formats.PEMRSA_SCHEMA'.
  """
  
  # Does the arguments have the correct format?
  # This check ensures arguments have the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ENCRYPTEDKEY_SCHEMA.check_match(encrypted_key)
  
  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

    
  json_data = _decrypt(encrypted_key, password)
  key_object_metadata = tuf.util.load_json_string(json_data) 
  
  return key_object_metadata





def _generate_derived_key(password, salt=None, iterations=None):
  """
  Generate a derived key by feeding 'password' to the Password-Based Key
  Derivation Function (PBKDF2).  PyCrypto's PBKDF2 implementation is
  currently used.  'salt' may be specified so that a previous derived key
  may be regenerated.
  """
  
  if salt is None:
    salt = Crypto.Random.new().read(_SALT_SIZE) 

  if iterations is None:
    iterations = _PBKDF2_ITERATIONS


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
                                           count=iterations,
                                           prf=pseudorandom_function)

  return salt, iterations, derived_key





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
    {'salt': '...',
     'derived_key': '...',
     'iterations': '...'}

  'tuf.CryptoError' raised if the encryption fails.
  """
  
  # Generate a random initialization vector (IV).  The 'iv' is treated as the
  # initial counter block to a stateful counter block function (i.e.,
  # PyCrypto's 'Crypto.Util.Counter').  The AES block cipher operates on 128-bit
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
  
  # Raise generic exception message to avoid revealing sensitive information,
  # such as invalid passwords, encryption keys, etc., that an attacker can use
  # to his advantage.
  except Exception, e:
    message = 'The key data cannot be encrypted.' 
    raise tuf.CryptoError(message)

  # Generate the hmac of the ciphertext to ensure it has not been modified.
  # The decryption routine may verify a ciphertext without having to perform
  # a decryption operation.
  salt = derived_key_information['salt'] 
  hmac_object = Crypto.Hash.HMAC.new(symmetric_key, ciphertext,
                                     Crypto.Hash.SHA256)
  hmac = hmac_object.hexdigest()

  # Store the number of PBKDF2 iterations used to derive the symmetric key so
  # that the decryption routine can regenerate the symmetric key successfully.
  # The pbkdf2 iterations are allowed to vary for the keys loaded and saved.
  iterations = derived_key_information['iterations']

  # Return the salt, iterations, hmac, initialization vector, and ciphertext
  # as a single string.  These five values are delimited by
  # '_ENCRYPTION_DELIMITER' to make extraction easier.  This delimiter is
  # arbitrarily chosen and should not occur in the hexadecimal representations
  # of the fields it is separating.
  return binascii.hexlify(salt) + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(str(iterations)) + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(hmac) + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(iv) + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(ciphertext)





def _decrypt(file_contents, password):
  """
  The corresponding decryption routine for _encrypt().

  'tuf.CryptoError' raised if the decryption fails.
  """
 
  # Extract the salt, iterations, hmac, initialization vector, and ciphertext
  # from 'file_contents'.  These five values are delimited by
  # '_ENCRYPTION_DELIMITER'.  This delimiter is arbitrarily chosen and should
  # not occur in the hexadecimal representations of the fields it is separating.
  salt, iterations, hmac, iv, ciphertext = \
    file_contents.split(_ENCRYPTION_DELIMITER)
  
  # Ensure we have the expected raw data for the delimited cryptographic data. 
  salt = binascii.unhexlify(salt)
  iterations = int(binascii.unhexlify(iterations))
  hmac = binascii.unhexlify(hmac)
  iv = binascii.unhexlify(iv)
  ciphertext = binascii.unhexlify(ciphertext)

  # Generate derived key from 'password'.  The salt and iterations are specified
  # so that the expected derived key is regenerated correctly.  Discard the old
  # "salt" and "iterations" values, as we only need the old derived key.
  junk_old_salt, junk_old_iterations, derived_key = \
    _generate_derived_key(password, salt, iterations)

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
  
  # Raise generic exception message to avoid revealing sensitive information,
  # such as invalid passwords, encryption keys, etc., that an attacker can
  # use to his advantage.
  except Exception, e: 
    raise tuf.CryptoError('Decryption failed.')

  return key_plaintext



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'pycrypto_keys.py' as a standalone module.
  # python -B pycrypto_keys.py
  import doctest
  doctest.testmod()
