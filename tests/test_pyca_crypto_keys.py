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
import tuf.formats
import tuf.pyca_crypto_keys as crypto_keys

logger = logging.getLogger('tuf.test_pyca_crypto_keys')

public_rsa, private_rsa = crypto_keys.generate_rsa_public_and_private()
FORMAT_ERROR_MSG = 'tuf.FormatError raised.  Check object\'s format.'


class TestPyca_crypto_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_rsa_public_and_private(self):
    pub, priv = crypto_keys.generate_rsa_public_and_private()
    
    # Check format of 'pub' and 'priv'.
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(pub),
                     FORMAT_ERROR_MSG)
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(priv),
                     FORMAT_ERROR_MSG)

    # Check for an invalid "bits" argument.  bits >= 2048.
    self.assertRaises(tuf.FormatError,
                      crypto_keys.generate_rsa_public_and_private, 1024)
   
    self.assertRaises(tuf.FormatError,
                      crypto_keys.generate_rsa_public_and_private, '2048')
  
  
  
  def test_create_rsa_signature(self):
    global private_rsa
    global public_rsa
    data = 'The quick brown fox jumps over the lazy dog'.encode('utf-8')
    signature, method = crypto_keys.create_rsa_signature(private_rsa, data)

    # Verify format of returned values.
    self.assertNotEqual(None, signature)
    self.assertEqual(None, tuf.formats.NAME_SCHEMA.check_match(method),
                     FORMAT_ERROR_MSG)
    self.assertEqual('RSASSA-PSS', method)

    # Check for improperly formatted arguments.
    self.assertRaises(tuf.FormatError,
                      crypto_keys.create_rsa_signature, 123, data)
    
    self.assertRaises(ValueError,
                      crypto_keys.create_rsa_signature, '', data)
   
    # Check for invalid 'data'.
    self.assertRaises(tuf.FormatError,
                      crypto_keys.create_rsa_signature, private_rsa, '')
    
    self.assertRaises(tuf.FormatError,
                      crypto_keys.create_rsa_signature, private_rsa, 123)

    # Check for missing private key.
    self.assertRaises(tuf.CryptoError,
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
    self.assertRaises(tuf.FormatError, crypto_keys.verify_rsa_signature, signature,
                                       123, public_rsa, data)
    
    self.assertRaises(tuf.FormatError, crypto_keys.verify_rsa_signature, signature,
                                       method, 123, data)
    
    self.assertRaises(tuf.FormatError, crypto_keys.verify_rsa_signature, 123, method,
                                       public_rsa, data)
    
    self.assertRaises(tuf.UnknownMethodError, crypto_keys.verify_rsa_signature,
                                                      signature,
                                                      'invalid_method',
                                                      public_rsa, data)
    
    # Check for invalid 'signature', 'public_key', and 'data' arguments.
    self.assertRaises(tuf.FormatError, crypto_keys.verify_rsa_signature,
                      signature, method, public_rsa, 123)
  
   

    self.assertRaises(tuf.CryptoError, crypto_keys.verify_rsa_signature,
                      signature, method, 'bad_key', data)
  
    self.assertEqual(False, crypto_keys.verify_rsa_signature(signature, method,
                            public_rsa, b'mismatched data'))

    mismatched_signature, method = crypto_keys.create_rsa_signature(private_rsa,
                                                             b'mismatched data')
    
    self.assertEqual(False, crypto_keys.verify_rsa_signature(mismatched_signature,
                            method, public_rsa, data))


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
