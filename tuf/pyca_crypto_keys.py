#!/usr/bin/env python

"""
<Program Name>
  pyca_crypto_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 3, 2015.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to support public-key and general-purpose
  cryptography through the 'pyca/cryptography' library.
  
  The RSA-related functions provided:
  generate_rsa_public_and_private()
  create_rsa_signature()
  verify_rsa_signature()
  create_rsa_encrypted_pem()
  create_rsa_public_and_private_from_encrypted_pem()

  The general-purpose functions include:
  encrypt_key()
  decrypt_key()
  
  'pyca/cryptography' (i.e., the cryptography package) performs the actual
  cryptographic operations and the functions listed above can be viewed as the
  easy-to-use public interface. 
 
  https://github.com/pyca/cryptography
  https://en.wikipedia.org/wiki/RSA_(algorithm)
  https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
  https://en.wikipedia.org/wiki/PBKDF
  http://en.wikipedia.org/wiki/Scrypt

  TUF key files are encrypted with the AES-256-CTR-Mode symmetric key
  algorithm.  User passwords are strengthened with PBKDF2, currently set to
  100,000 passphrase iterations.  The previous evpy implementation used 1,000
  iterations.
  
  PEM-encrypted RSA key files use the Triple Data Encryption Algorithm (3DES)
  and Cipher-block chaining (CBC) for the mode of operation.  Password-Based Key
  Derivation Function 1 (PBKF1) + MD5.
 """

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import binascii
import json


# Needed to generate keys in PEM format.
from cryptography.hazmat.primitives import serialization

# Needed to catch pyca/cryptography exceptions.
import cryptography.exceptions

# cryptography.hazmat.primitives.asymmetric (i.e., pyca/cryptography's
# public-key cryptography modules) supports algorithms like the Digital
# Signature Algorithm (DSA) and the ElGamal encryption system.
# 'rsa' is needed here to generate, sign,
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# pyca/Cryptography requires hash objects to generate PKCS#1 PSS
# signatures (i.e., padding.PSS).
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac

# RSA's probabilistic signature scheme with appendix (RSASSA-PSS).
# PKCS#1 v1.5 is available for compatibility with existing applications, but
# RSASSA-PSS is encouraged for newer applications.  RSASSA-PSS generates
# a random salt to ensure the signature generated is probabilistic rather than
# deterministic (e.g., PKCS#1 v1.5).
# http://en.wikipedia.org/wiki/RSA-PSS#Schemes 
# https://tools.ietf.org/html/rfc3447#section-8.1 
# Needed to generate PSS signatures.
from cryptography.hazmat.primitives.asymmetric import padding

# Import PyCrypto's Key Derivation Function (KDF) module.  'keys.py' needs this
# module to derive a secret key according to the Password-Based Key Derivation
# Function 2 specification.  The derived key is used as the symmetric key to
# encrypt TUF key information.  PyCrypto's implementation:
# Crypto.Protocol.KDF.PBKDF2().  PKCS#5 v2.0 PBKDF2 specification:
# http://tools.ietf.org/html/rfc2898#section-5.2 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# PyCrypto's AES implementation.  AES is a symmetric key algorithm that
# operates on fixed block sizes of 128-bits.
# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# 'Crypto.Random' is a cryptographically strong version of Python's standard
# "random" module.  Random bits of data is needed for salts and 
# initialization vectors suitable for the encryption algorithms used in 
# 'pycrypto_keys.py'.

# The mode of operation is presently set to CTR (CounTeR Mode) for symmetric
# block encryption (AES-256, where the symmetric key is 256 bits).  PyCrypto
# provides a callable stateful block counter that can update successive blocks
# when needed.  The initial random block, or initialization vector (IV), can
# be set to begin the process of incrementing the 128-bit blocks and allowing
# the AES algorithm to perform cipher block operations on them. 
from cryptography.hazmat.primitives.ciphers import modes

# Import the TUF package and TUF-defined exceptions in __init__.py.
import tuf

# Digest objects needed to generate hashes.
import tuf.hash

# Perform object format-checking.
import tuf.formats

# Extract the cryptography library settings.
import tuf.conf

# Import key files containing json data.
import tuf.util

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
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits,
                                         backend=default_backend())

  # Extract the public & private halves of the RSA key and generate their
  # PEM-formatted representations.  Return the key pair as a (public, private)
  # tuple, where each RSA is a string in PEM format.
  private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption())
  
  public_key = private_key.public_key()
  public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
 
  return public_pem, private_pem





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
    >>> data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    >>> signature, method = create_rsa_signature(private, data)
    >>> tuf.formats.NAME_SCHEMA.matches(method)
    True
    >>> method == 'RSASSA-PSS'
    True
    >>> tuf.formats.PYCRYPTOSIGNATURE_SCHEMA.matches(signature)
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
  
  # Signing the 'data' object requires a private key.  The 'RSASSA-PSS' signing
  # method is the only method currently supported.
  method = 'RSASSA-PSS'
  signature = None

  # Verify the signature, but only if the private key has been set.  The private
  # key is a NULL string if unset.  Although it may be clearer to explicitly
  # check that 'private_key' is not '', we can/should check for a value and not
  # compare identities with the 'is' keyword.  Up to this point 'private_key'
  # has variable size and can be an empty string.
  if len(private_key):
   
    # Calculate the SHA256 hash of 'data' and generate the hash's PKCS1-PSS
    # signature. 
    
    # pyca/cryptography's expected exceptions when generating RSA key object:
    # "ValueError/IndexError/TypeError:  When the given key cannot be parsed
    # (possibly because the passphrase is wrong)."
    # If the passphrase is incorrect, pyca/cryptography returns: "".
    try:
      # 'private_pem' must be converted to a pyca/cryptography private key object
      # before a signature can be generated.
      private_key_object = serialization.load_pem_private_key(private_key,
                                                     password=None,
                                                     backend=default_backend())
      rsa_signer = \
        private_key_object.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                           salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    except (ValueError, IndexError, TypeError) as e:
      message = 'Invalid private key or hash data: ' + str(e)
      raise tuf.CryptoError(message)
   
    # Generate RSSA-PSS signature.  Raise 'tuf.CryptoError' for the expected
    # pyca/cryptography exceptions.
    try:
      rsa_signer.update(data)
      signature = rsa_signer.finalize()
    
    except ValueError: #pragma: no cover
      raise tuf.CryptoError('The RSA key too small for given hash algorithm.')
    
    except TypeError:
      raise tuf.CryptoError('Missing required RSA private key.')
   
    except IndexError: # pragma: no cover
      message = 'An RSA signature cannot be generated: ' + str(e)
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
    >>> data = b'The quick brown fox jumps over the lazy dog'
    >>> signature, method = create_rsa_signature(private, data)
    >>> verify_rsa_signature(signature, method, public, data)
    True
    >>> verify_rsa_signature(signature, method, public, b'bad_data')
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
      Data object used by tuf.keys.create_signature() to generate
      'signature'.  'data' is needed here to verify the signature.

  <Exceptions>
    tuf.UnknownMethodError.  Raised if the signing method used by
    'signature' is not one supported by tuf.keys.create_signature().
    
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

  # Verify whether the private key of 'public_key' produced 'signature'.
  # Before returning the 'valid_signature' Boolean result, ensure 'RSASSA-PSS'
  # was used as the signing method.
  valid_signature = False

  # Verify the signature with PyCrypto if the signature method is valid,
  # otherwise raise 'tuf.UnknownMethodError'.
  if signature_method == 'RSASSA-PSS':
    try:
      public_key_object = serialization.load_pem_public_key(public_key,
                                                     backend=default_backend())
       
      verifier = public_key_object.verifier(signature,
                                  padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                  salt_length=padding.PSS.MAX_LENGTH),
                                  hashes.SHA256())

      verifier.update(data)
      
      # verify() raises 'cryptogrpahy.exceptions.InvalidSignature' if the
      # signature is invalid. 
      try: 
        verifier.verify()
        valid_signature = True 
      
      except cryptography.exceptions.InvalidSignature as e:
        pass
    
    except (ValueError, IndexError, TypeError) as e:
      message = 'The RSA signature could not be verified.'
      raise tuf.CryptoError(message)
  
  else:
    raise tuf.UnknownMethodError(signature_method)

  return valid_signature 





def encrypt_key(key_object, password):
  """
  <Purpose>
    Return a string containing 'key_object' in encrypted form. Encrypted strings
    may be safely saved to a file.  The corresponding decrypt_key() function can
    be applied to the encrypted string to restore the original key object.
    'key_object' is a TUF key (e.g., RSAKEY_SCHEMA, ED25519KEY_SCHEMA).  This
    function calls the PyCrypto library to perform the encryption and derive
    a suitable encryption key.
    
    Whereas an encrypted PEM file uses the Triple Data Encryption Algorithm
    (3DES), the Cipher-block chaining (CBC) mode of operation, and the Password
    Based Key Derivation Function 1 (PBKF1) + MD5 to strengthen 'password',
    encrypted TUF keys use AES-256-CTR-Mode and passwords strengthened with
    PBKDF2-HMAC-SHA256 (100K iterations by default, but may be overriden in
    'tuf.conf.PBKDF2_ITERATIONS' by the user).

    http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    http://en.wikipedia.org/wiki/CTR_mode#Counter_.28CTR.29
    https://en.wikipedia.org/wiki/PBKDF2

    >>> ed25519_key = {'keytype': 'ed25519', \
                       'keyid': \
          'd62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d', \
                       'keyval': {'public': \
          '74addb5ad544a4306b34741bc1175a3613a8d7dc69ff64724243efdec0e301ad', \
                                  'private': \
          '1f26964cc8d4f7ee5f3c5da2fbb7ab35811169573ac367b860a537e47789f8c4'}}
    >>> passphrase = 'secret'
    >>> encrypted_key = encrypt_key(ed25519_key, passphrase)
    >>> tuf.formats.ENCRYPTEDKEY_SCHEMA.matches(encrypted_key.encode('utf-8'))
    True

  <Arguments>
    key_object:
      The TUF key object that should contain the private portion of the ED25519
      key.

    password:
      The password, or passphrase, to encrypt the private part of the RSA
      key.  'password' is not used directly as the encryption key, a stronger
      encryption key is derived from it. 

  <Exceptions>
    tuf.FormatError, if any of the arguments are improperly formatted or 
    'key_object' does not contain the private portion of the key.

    tuf.CryptoError, if an ED25519 key in encrypted TUF format cannot be
    created.

  <Side Effects>
    pyca/Cryptography cryptographic operations called to perform the actual
    encryption of 'key_object'.  'password' used to derive a suitable
    encryption key.

  <Returns>
    An encrypted string in 'tuf.formats.ENCRYPTEDKEY_SCHEMA' format.
  """
  
  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ANYKEY_SCHEMA.check_match(key_object)
  
  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  # Ensure the private portion of the key is included in 'key_object'.
  if not key_object['keyval']['private']:
    message = 'Key object does not contain a private part.'
    raise tuf.FormatError(message)

  # Derive a key (i.e., an appropriate encryption key and not the
  # user's password) from the given 'password'.  Strengthen 'password' with
  # PBKDF2-HMAC-SHA256 (100K iterations by default, but may be overriden in
  # 'tuf.conf.PBKDF2_ITERATIONS' by the user).
  salt, iterations, derived_key = _generate_derived_key(password)
 
  # Store the derived key info in a dictionary, the object expected
  # by the non-public _encrypt() routine.
  derived_key_information = {'salt': salt, 'iterations': iterations,
                             'derived_key': derived_key}

  # Convert the key object to json string format and encrypt it with the
  # derived key.
  encrypted_key = _encrypt(json.dumps(key_object), derived_key_information)  

  return encrypted_key





def _generate_derived_key(password, salt=None, iterations=None):
  """
  Generate a derived key by feeding 'password' to the Password-Based Key
  Derivation Function (PBKDF2).  pyca/cryptography's PBKDF2 implementation is
  used in this module.  'salt' may be specified so that a previous derived key
  may be regenerated, otherwise '_SALT_SIZE' is used by default.  'iterations'
  is the number of SHA-256 iterations to perform, otherwise
  '_PBKDF2_ITERATIONS' is used by default.
  """
  
  backend = default_backend()
  
  if salt is None:
    salt = os.urandom(_SALT_SIZE) 

  if iterations is None:
    iterations = _PBKDF2_ITERATIONS
  
  # Derive an AES key with PBKDF2.  The  'length' is the desired key length of
  # the derived key.
  pbkdf_object = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
       iterations=iterations, backend=backend)

  derived_key = pbkdf_object.derive(password.encode('utf-8'))
  
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

  # Generate a random initialization vector (IV).  Follow the provably secure
  # encrypt-then-MAC approach, which affords the ability to verify ciphertext
  # without needing to decrypt it and preventing an attacker from feeding the
  # block cipher malicious data.  Modes like GCM provide both encryption and
  # authentication, whereas CTR only provides encryption.  
  
  # Generate a random 128-bit IV.
  iv = os.urandom(16)
  
  # Construct an AES-CTR Cipher object with the given key and a randomly
  # generated IV.
  symmetric_key = derived_key_information['derived_key'] 
  encryptor = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv),
                     backend=default_backend()).encryptor()
  
  # associated_data will be authenticated but not encrypted,
  # it must also be passed in on decryption.
  #encryptor.authenticate_additional_data(associated_data)

  # Encrypt the plaintext and get the associated ciphertext.
  # Do we need to check for any exceptions?
  ciphertext = encryptor.update(key_data) + encryptor.finalize()

    
  # Cryptography will generate a 128-bit tag when finalizing encryption. You can
  # shorten a tag by truncating it to the desired length but this is not
  # recommended as it lowers the security margins of the authentication (NIST
  # SP-800-38D recommends 96-bits or greater). Applications wishing to allow
  # truncation must pass the min_tag_length parameter.
  #return (iv, ciphertext, encryptor.tag)
  
  # Generate the hmac of the ciphertext to ensure it has not been modified.
  # The decryption routine may verify a ciphertext without having to perform
  # a decryption operation.
  symmetric_key = derived_key_information['derived_key']
  salt = derived_key_information['salt']
  hmac_object = \
    cryptography.hazmat.primitives.hmac.HMAC(symmetric_key, hashes.SHA256(), 
                                             backend=default_backend())
  hmac_object.update(ciphertext)
  hmac_value = binascii.hexlify(hmac_object.finalize())

  # Store the number of PBKDF2 iterations used to derive the symmetric key so
  # that the decryption routine can regenerate the symmetric key successfully.
  # The pbkdf2 iterations are allowed to vary for the keys loaded and saved.
  iterations = derived_key_information['iterations']

  # Return the salt, iterations, hmac, initialization vector, and ciphertext
  # as a single string.  These five values are delimited by
  # '_ENCRYPTION_DELIMITER' to make extraction easier.  This delimiter is
  # arbitrarily chosen and should not occur in the hexadecimal representations
  # of the fields it is separating.
  return binascii.hexlify(salt).decode() + _ENCRYPTION_DELIMITER + \
         str(iterations) + _ENCRYPTION_DELIMITER + \
         hmac_value + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(iv).decode() + _ENCRYPTION_DELIMITER + \
         binascii.hexlify(ciphertext).decode()
  
  



def _decrypt(file_contents, password):
  """
  The corresponding decryption routine for _encrypt().

  'tuf.CryptoError' raised if the decryption fails.
  """
  
  # Extract the salt, iterations, hmac, initialization vector, and ciphertext
  # from 'file_contents'.  These five values are delimited by
  # '_ENCRYPTION_DELIMITER'.  This delimiter is arbitrarily chosen and should
  # not occur in the hexadecimal representations of the fields it is separating.
  # Raise 'tuf.CryptoError', if 'file_contents' does not contains the expected
  # data layout.
  try: 
    salt, iterations, hmac, iv, ciphertext = \
      file_contents.split(_ENCRYPTION_DELIMITER)
  
  except ValueError:
    raise tuf.CryptoError('Invalid encrypted file.') 

  # Ensure we have the expected raw data for the delimited cryptographic data. 
  salt = binascii.unhexlify(salt.encode('utf-8'))
  iterations = int(iterations)
  iv = binascii.unhexlify(iv.encode('utf-8'))
  ciphertext = binascii.unhexlify(ciphertext.encode('utf-8'))

  # Generate derived key from 'password'.  The salt and iterations are specified
  # so that the expected derived key is regenerated correctly.  Discard the old
  # "salt" and "iterations" values, as we only need the old derived key.
  junk_old_salt, junk_old_iterations, derived_key = \
    _generate_derived_key(password, salt, iterations)

  # Verify the hmac to ensure the ciphertext is valid and has not been altered.
  # See the encryption routine for why we use the encrypt-then-MAC approach.
  # The decryption routine may verify a ciphertext without having to perform
  # a decryption operation.
  symmetric_key = derived_key_information['derived_key'] 
  generated_hmac_object = hmac.HMAC(symmetric_key, hashes.SHA256(),
                                    backend=default_backend())
  generated_hmac_object.update(ciphertext)
  generated_hmac = binascii.hexlify(generated_hmac_object.finalize())


  if not tuf.util.digests_are_equal(generated_hmac, hmac):
    raise tuf.CryptoError('Decryption failed.')
    
  # Construct a Cipher object, with the key and iv.
  decryptor = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv),
                     backend=default_backend()).decryptor()

  # We put associated_data back in or the tag will fail to verify when we
  # finalize the decryptor.
  #decryptor.authenticate_additional_data(associated_data)

  # Decryption gets us the authenticated plaintext.
  # If the tag does not match, an InvalidTag exception will be raised.
  plaintext = None
 
  try:
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
  
  # Avoid propogating the exception trace and only raise 'tuf.CryptoError',
  # along with the cause of decryption failure.  Note: decryption failure, due
  # to malicious ciphertext, should not occur here if the hmac check above
  # passed.
  # TODO: Substitute expeceted pyca exceptions.
  except (ValueError, IndexError, TypeError) as e: # pragma: no cover
    raise tuf.CryptoError('Decryption failed: ' + str(e))

  return plaintext 





if __name__ == '__main__':
  # The interactive sessions of the documentation strings can be tested by
  # running 'pyca_crypto_keys.py' as a standalone module:
  # $ python pyca_crypto_keys.py
  import doctest
  doctest.testmod()
