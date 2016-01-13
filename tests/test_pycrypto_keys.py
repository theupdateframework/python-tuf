#!/usr/bin/env python

"""
<Program Name>
  test_pycrypto_keys.py

<Author> 
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 10, 2013. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_pycrypto_keys.py.
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
import tuf.formats
import tuf.pycrypto_keys as pycrypto

logger = logging.getLogger('tuf.test_pycrypto_keys')

public_rsa, private_rsa = pycrypto.generate_rsa_public_and_private()
FORMAT_ERROR_MSG = 'tuf.FormatError raised.  Check object\'s format.'


class TestPycrypto_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_rsa_public_and_private(self):
    pub, priv = pycrypto.generate_rsa_public_and_private()
    
    # Check format of 'pub' and 'priv'.
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(pub),
                     FORMAT_ERROR_MSG)
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(priv),
                     FORMAT_ERROR_MSG)

    # Check for invalid bits argument.  bit >= 2048 and a multiple of 256.
    self.assertRaises(tuf.FormatError,
                      pycrypto.generate_rsa_public_and_private, 1024)
    
    self.assertRaises(ValueError,
                      pycrypto.generate_rsa_public_and_private, 2049)

    self.assertRaises(tuf.FormatError,
                      pycrypto.generate_rsa_public_and_private, '2048')
    

  def test_create_rsa_signature(self):
    global private_rsa
    global public_rsa
    data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    signature, method = pycrypto.create_rsa_signature(private_rsa, data)

    # Verify format of returned values.
    self.assertNotEqual(None, signature)
    self.assertEqual(None, tuf.formats.NAME_SCHEMA.check_match(method),
                     FORMAT_ERROR_MSG)
    self.assertEqual('RSASSA-PSS', method)

    # Check for improperly formatted arguments.
    self.assertRaises(tuf.FormatError,
                      pycrypto.create_rsa_signature, 123, data)
    
    self.assertRaises(TypeError,
                      pycrypto.create_rsa_signature, '', data)
   
    # Check for invalid 'data'.
    self.assertRaises(tuf.FormatError,
                      pycrypto.create_rsa_signature, private_rsa, '')
   
    # create_rsa_signature should reject non-string data.
    self.assertRaises(tuf.FormatError,
                      pycrypto.create_rsa_signature, private_rsa, 123)

    # Check for missing private key.
    self.assertRaises(tuf.CryptoError,
                      pycrypto.create_rsa_signature, public_rsa, data)


  def test_verify_rsa_signature(self):
    global public_rsa
    global private_rsa
    data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    signature, method = pycrypto.create_rsa_signature(private_rsa, data)

    valid_signature = pycrypto.verify_rsa_signature(signature, method, public_rsa,
                                                data)
    self.assertEqual(True, valid_signature)

    # Check for improperly formatted arguments.
    self.assertRaises(tuf.FormatError, pycrypto.verify_rsa_signature, signature,
                                       123, public_rsa, data)
    
    self.assertRaises(tuf.FormatError, pycrypto.verify_rsa_signature, signature,
                                       method, 123, data)
    
    self.assertRaises(tuf.FormatError, pycrypto.verify_rsa_signature, 123, method,
                                       public_rsa, data)
    
    self.assertRaises(tuf.UnknownMethodError, pycrypto.verify_rsa_signature,
                                                      signature,
                                                      'invalid_method',
                                                      public_rsa, data)
    
    # Check for invalid signature and data.
    # Verify_rsa_signature should reject non-string data.
    self.assertRaises(tuf.FormatError, pycrypto.verify_rsa_signature, signature,
                                       method, public_rsa, 123)
   
    self.assertEqual(False, pycrypto.verify_rsa_signature(signature, method,
                            public_rsa, b'mismatched data'))

    mismatched_signature, method = pycrypto.create_rsa_signature(private_rsa,
                                                             b'mismatched data')
    
    self.assertEqual(False, pycrypto.verify_rsa_signature(mismatched_signature,
                            method, public_rsa, data))


  def test_create_rsa_encrypted_pem(self):
    global public_rsa
    global private_rsa
    passphrase = 'pw'

    # Check format of 'public_rsa'.
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(public_rsa),
                     FORMAT_ERROR_MSG)
    
    # Check format of 'passphrase'.
    self.assertEqual(None, tuf.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Generate the encrypted PEM string of 'public_rsa'.
    pem_rsakey = pycrypto.create_rsa_encrypted_pem(private_rsa, passphrase)

    # Check format of 'pem_rsakey'.
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(pem_rsakey),
                     FORMAT_ERROR_MSG)

    # Check for invalid arguments.
    self.assertRaises(tuf.FormatError,
                      pycrypto.create_rsa_encrypted_pem, 1, passphrase)
    self.assertRaises(tuf.FormatError,
                      pycrypto.create_rsa_encrypted_pem, private_rsa, ['pw'])
 
    self.assertRaises(tuf.CryptoError, pycrypto.create_rsa_encrypted_pem,
                                       'abc', passphrase)
    self.assertRaises(TypeError, pycrypto.create_rsa_encrypted_pem, '', passphrase)
 


  def test_create_rsa_public_and_private_from_encrypted_pem(self):
    global private_rsa
    passphrase = 'pw'

    # Generate the encrypted PEM string of 'private_rsa'.
    pem_rsakey = pycrypto.create_rsa_encrypted_pem(private_rsa, passphrase)
   
    # Check format of 'passphrase'.
    self.assertEqual(None, tuf.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Decrypt 'pem_rsakey' and verify the decrypted object is properly
    # formatted.
    public_decrypted, private_decrypted = \
    pycrypto.create_rsa_public_and_private_from_encrypted_pem(pem_rsakey,
                                                             passphrase)
    self.assertEqual(None,
                     tuf.formats.PEMRSA_SCHEMA.check_match(public_decrypted),
                     FORMAT_ERROR_MSG)
    
    self.assertEqual(None,
                     tuf.formats.PEMRSA_SCHEMA.check_match(private_decrypted),
                     FORMAT_ERROR_MSG)

    # Does 'public_decrypted' and 'private_decrypted' match the originals?
    self.assertEqual(public_rsa, public_decrypted)
    self.assertEqual(private_rsa, private_decrypted)

    # Attempt decryption of 'pem_rsakey' using an incorrect passphrase.
    self.assertRaises(tuf.CryptoError,
                      pycrypto.create_rsa_public_and_private_from_encrypted_pem,
                      pem_rsakey, 'bad_pw')

    # Check for non-encrypted PEM strings.
    # create_rsa_public_and_private_from_encrypted_pem()
    # returns a tuple of tuf.formats.PEMRSA_SCHEMA objects if the PEM formatted
    # string is not actually encrypted but still a valid PEM string.
    pub, priv = pycrypto.create_rsa_public_and_private_from_encrypted_pem(
                              private_rsa, passphrase)
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(pub),
                     FORMAT_ERROR_MSG)
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(priv),
                     FORMAT_ERROR_MSG)

    # Check for invalid arguments.
    self.assertRaises(tuf.FormatError,
                      pycrypto.create_rsa_public_and_private_from_encrypted_pem,
                      123, passphrase)
    self.assertRaises(tuf.FormatError,
                      pycrypto.create_rsa_public_and_private_from_encrypted_pem,
                      pem_rsakey, ['pw'])
    
    self.assertRaises(tuf.CryptoError,
                      pycrypto.create_rsa_public_and_private_from_encrypted_pem,
                      'invalid_pem', passphrase)



  def test_encrypt_key(self):
    # Test for valid arguments.
    global public_rsa
    global private_rsa
    passphrase = 'pw'
    
    rsa_key = {'keytype': 'rsa',
    'keyid': 'd62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d',
    'keyval': {'public': public_rsa, 'private': private_rsa}}

    encrypted_rsa_key = tuf.pycrypto_keys.encrypt_key(rsa_key, passphrase)

    # Test for invalid arguments.
    rsa_key['keyval']['private'] = ''
    self.assertRaises(tuf.FormatError, tuf.pycrypto_keys.encrypt_key, rsa_key,
                                       'passphrase')


  def test_decrypt_key(self):
    # Test for valid arguments.
    global public_rsa
    global private_rsa
    passphrase = 'pw'
    
    rsa_key = {'keytype': 'rsa',
    'keyid': 'd62247f817883f593cf6c66a5a55292488d457bcf638ae03207dbbba9dbe457d',
    'keyval': {'public': public_rsa, 'private': private_rsa}}

    encrypted_rsa_key = tuf.pycrypto_keys.encrypt_key(rsa_key, passphrase).encode('utf-8')
    
    decrypted_rsa_key = tuf.pycrypto_keys.decrypt_key(encrypted_rsa_key, passphrase)


    # Test for invalid arguments.
    self.assertRaises(tuf.CryptoError, tuf.pycrypto_keys.decrypt_key, b'bad',
                                       passphrase)

    # Test for invalid encrypted content (i.e., invalid hmac and ciphertext.)
    encryption_delimiter = tuf.pycrypto_keys._ENCRYPTION_DELIMITER 
    salt, iterations, hmac, iv, ciphertext = \
      encrypted_rsa_key.decode('utf-8').split(encryption_delimiter)
   
    # Set an invalid hmac.  The decryption routine sould raise a tuf.CryptoError
    # exception because 'hmac' does not match the hmac calculated by the
    # decryption routine.
    bad_hmac = '12345abcd'
    invalid_encrypted_rsa_key = \
      salt + encryption_delimiter + iterations + encryption_delimiter + \
      bad_hmac + encryption_delimiter + iv + encryption_delimiter + ciphertext
      
    self.assertRaises(tuf.CryptoError, tuf.pycrypto_keys.decrypt_key,
                      invalid_encrypted_rsa_key.encode('utf-8'), passphrase)

    # Test for invalid 'ciphertext'
    bad_ciphertext = '12345abcde'
    invalid_encrypted_rsa_key = \
      salt + encryption_delimiter + iterations + encryption_delimiter + \
      hmac + encryption_delimiter + iv + encryption_delimiter + bad_ciphertext
    
    self.assertRaises(tuf.CryptoError, tuf.pycrypto_keys.decrypt_key,
                      invalid_encrypted_rsa_key.encode('utf-8'), passphrase)



  def test__decrypt_key(self):
    # Test for invalid arguments.
    salt, iterations, derived_key = tuf.pycrypto_keys._generate_derived_key('pw')
    derived_key_information = {'salt': salt, 'derived_key': derived_key,
                               'iterations': iterations}
    
    self.assertRaises(tuf.CryptoError, tuf.pycrypto_keys._encrypt,
                          8, derived_key_information)




# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
