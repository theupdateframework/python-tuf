#!/usr/bin/env python

"""
<Program Name>
  test_pyca_crypto_keys.py

<Author> 
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 3, 2015. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for 'pyca_crypto_keys.py'.
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
import tuf.log
import tuf.ssl_crypto.formats
import tuf.ssl_crypto.pyca_crypto_keys as crypto_keys

logger = logging.getLogger('tuf.test_pyca_crypto_keys')

public_rsa, private_rsa = crypto_keys.generate_rsa_public_and_private()
FORMAT_ERROR_MSG = 'tuf.ssl_commons.exceptions.FormatError raised.' + \
  '  Check object\'s format.'


class TestPyca_crypto_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_rsa_public_and_private(self):
    pub, priv = crypto_keys.generate_rsa_public_and_private()
    
    # Check format of 'pub' and 'priv'.
    self.assertEqual(None, tuf.ssl_crypto.formats.PEMRSA_SCHEMA.check_match(pub),
                     FORMAT_ERROR_MSG)
    self.assertEqual(None, tuf.ssl_crypto.formats.PEMRSA_SCHEMA.check_match(priv),
                     FORMAT_ERROR_MSG)

    # Check for an invalid "bits" argument.  bits >= 2048.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      crypto_keys.generate_rsa_public_and_private, 1024)
   
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      crypto_keys.generate_rsa_public_and_private, '2048')
  
  
  
  def test_create_rsa_signature(self):
    global private_rsa
    global public_rsa
    data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    signature, method = crypto_keys.create_rsa_signature(private_rsa, data)

    # Verify format of returned values.
    self.assertNotEqual(None, signature)
    self.assertEqual(None, tuf.ssl_crypto.formats.NAME_SCHEMA.check_match(method),
                     FORMAT_ERROR_MSG)
    self.assertEqual('RSASSA-PSS', method)

    # Check for improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      crypto_keys.create_rsa_signature, 123, data)
    
    self.assertRaises(ValueError,
                      crypto_keys.create_rsa_signature, '', data)
   
    # Check for invalid 'data'.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      crypto_keys.create_rsa_signature, private_rsa, '')
    
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      crypto_keys.create_rsa_signature, private_rsa, 123)

    # Check for missing private key.
    self.assertRaises(tuf.ssl_commons.exceptions.CryptoError,
                      crypto_keys.create_rsa_signature, public_rsa, data)



  def test_verify_rsa_signature(self):
    global public_rsa
    global private_rsa
    data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    signature, method = crypto_keys.create_rsa_signature(private_rsa, data)

    valid_signature = crypto_keys.verify_rsa_signature(signature, method, public_rsa,
                                                data)
    self.assertEqual(True, valid_signature)

    # Check for improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, crypto_keys.verify_rsa_signature, 123, method,
                                       public_rsa, data)
    
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, crypto_keys.verify_rsa_signature, signature,
                                       123, public_rsa, data)
    
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, crypto_keys.verify_rsa_signature, signature,
                                       method, 123, data)
    
    
    self.assertRaises(tuf.ssl_commons.exceptions.UnknownMethodError, crypto_keys.verify_rsa_signature,
                                                      signature,
                                                      'invalid_method',
                                                      public_rsa, data)
    
    # Check for invalid 'signature', 'public_key', and 'data' arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, crypto_keys.verify_rsa_signature,
                      signature, method, public_rsa, 123)

    self.assertRaises(tuf.ssl_commons.exceptions.CryptoError, crypto_keys.verify_rsa_signature,
                      signature, method, 'bad_key', data)
  
    self.assertEqual(False, crypto_keys.verify_rsa_signature(signature, method,
                            public_rsa, b'mismatched data'))

    mismatched_signature, method = crypto_keys.create_rsa_signature(private_rsa,
                                                             b'mismatched data')
    
    self.assertEqual(False, crypto_keys.verify_rsa_signature(mismatched_signature,
                            method, public_rsa, data))



  def test__decrypt(self):
    # Verify that invalid encrypted file is detected. 
    self.assertRaises(tuf.ssl_commons.exceptions.CryptoError, crypto_keys._decrypt,
                      'bad encrypted file', 'password')



  def test_encrypt_key(self):
    # Normal case. 
    ed25519_key = {'keytype': 'ed25519',
      'keyid': 'd62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d',
      'keyval': {'public': '74addb5ad544a4306b34741bc1175a3613a8d7dc69ff64724243efdec0e301ad',
      'private': '1f26964cc8d4f7ee5f3c5da2fbb7ab35811169573ac367b860a537e47789f8c4'}} 
      
    crypto_keys.encrypt_key(ed25519_key, 'password')
    
    # Verify that a key with a missing 'private' key is rejected.
    del ed25519_key['keyval']['private']
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, crypto_keys.encrypt_key,
                      ed25519_key, 'password')



  def test__decrypt_key(self):
    ed25519_key = {'keytype': 'ed25519',
      'keyid': 'd62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d',
      'keyval': {'public': '74addb5ad544a4306b34741bc1175a3613a8d7dc69ff64724243efdec0e301ad',
      'private': '1f26964cc8d4f7ee5f3c5da2fbb7ab35811169573ac367b860a537e47789f8c4'}} 
   
    encrypted_key = crypto_keys.encrypt_key(ed25519_key, 'password')
    crypto_keys.encrypt_key(ed25519_key, 'password')

    salt, iterations, hmac, iv, ciphertext = \
      encrypted_key.split(crypto_keys._ENCRYPTION_DELIMITER)

    encrypted_key_invalid_hmac = encrypted_key.replace(hmac, '123abc')

    self.assertRaises(tuf.ssl_commons.exceptions.CryptoError, crypto_keys._decrypt,
                      encrypted_key_invalid_hmac, 'password')



  def test_create_rsa_public_and_private_from_encrypted_pem(self):
    self.assertRaises(tuf.ssl_commons.exceptions.CryptoError,
              crypto_keys.create_rsa_public_and_private_from_encrypted_pem,
              'bad_encrypted_key', 'password')



  def test_create_rsa_encrypted_pem(self):
    global private_rsa
    passphrase = 'password'

    # Verify normal case.
    encrypted_pem = crypto_keys.create_rsa_encrypted_pem(private_rsa, passphrase)
   
    self.assertTrue(tuf.ssl_crypto.formats.PEMRSA_SCHEMA.matches(encrypted_pem))

    # Test for invalid arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, crypto_keys.create_rsa_encrypted_pem,
                      1, passphrase)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, crypto_keys.create_rsa_encrypted_pem,
                      private_rsa, 2)

    self.assertRaises(TypeError, crypto_keys.create_rsa_encrypted_pem,
                      '', passphrase)

    self.assertRaises(tuf.ssl_commons.exceptions.CryptoError, crypto_keys.create_rsa_encrypted_pem,
                      'bad_private_pem', passphrase)




# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
