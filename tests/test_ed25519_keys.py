#!/usr/bin/env/ python

"""
<Program Name>
  test_ed25519_keys.py

<Author> 
  Vladimir Diaz <vladimir.v.diaz@gmail.com> 

<Started>
  October 11, 2013. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_ed25519_keys.py.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import os
import logging

import tuf
import tuf.log
import tuf.formats
import tuf.ed25519_keys as ed25519_keys 

logger = logging.getLogger('tuf.test_ed25519_keys')

public, private = ed25519_keys.generate_public_and_private()
FORMAT_ERROR_MSG = 'tuf.FormatError raised.  Check object\'s format.'


class TestEd25519_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_public_and_private(self):
    pub, priv = ed25519_keys.generate_public_and_private()
    
    # Check format of 'pub' and 'priv'.
    self.assertEqual(True, tuf.formats.ED25519PUBLIC_SCHEMA.matches(pub))
    self.assertEqual(True, tuf.formats.ED25519SEED_SCHEMA.matches(priv))



  def test_create_signature(self):
    global public
    global private
    data = b'The quick brown fox jumps over the lazy dog'
    signature, method = ed25519_keys.create_signature(public, private, data)

    # Verify format of returned values.
    self.assertEqual(True,
                     tuf.formats.ED25519SIGNATURE_SCHEMA.matches(signature))
    
    self.assertEqual(True, tuf.formats.NAME_SCHEMA.matches(method))
    self.assertEqual('ed25519', method)

    # Check for improperly formatted argument.
    self.assertRaises(tuf.FormatError,
                      ed25519_keys.create_signature, 123, private, data)
    
    self.assertRaises(tuf.FormatError,
                      ed25519_keys.create_signature, public, 123, data)
   
    # Check for invalid 'data'.
    self.assertRaises(tuf.CryptoError,
                      ed25519_keys.create_signature, public, private, 123)


  def test_verify_signature(self):
    global public
    global private
    data = b'The quick brown fox jumps over the lazy dog'
    signature, method = ed25519_keys.create_signature(public, private, data)

    valid_signature = ed25519_keys.verify_signature(public, method, signature, data)
    self.assertEqual(True, valid_signature)
    
    # Test with 'pynacl'.
    valid_signature = ed25519_keys.verify_signature(public, method, signature, data,
                                               use_pynacl=True)
    self.assertEqual(True, valid_signature)
   
    # Test with 'pynacl', but a bad signature is provided.
    bad_signature = os.urandom(64)
    valid_signature = ed25519_keys.verify_signature(public, method, bad_signature,
                                               data, use_pynacl=True)
    self.assertEqual(False, valid_signature)
    


    # Check for improperly formatted arguments.
    self.assertRaises(tuf.FormatError, ed25519_keys.verify_signature, 123, method,
                                       signature, data)
    
    # Signature method improperly formatted.
    self.assertRaises(tuf.FormatError, ed25519_keys.verify_signature, public, 123,
                                       signature, data)
   
    # Invalid signature method.
    self.assertRaises(tuf.UnknownMethodError, ed25519_keys.verify_signature, public,
                                       'unsupported_method', signature, data)
   
    # Signature not a string.
    self.assertRaises(tuf.FormatError, ed25519_keys.verify_signature, public, method,
                                       123, data)
   
    # Invalid signature length, which must be exactly 64 bytes..
    self.assertRaises(tuf.FormatError, ed25519_keys.verify_signature, public, method,
                                       'bad_signature', data)
    
    # Check for invalid signature and data.
    # Mismatched data.
    self.assertEqual(False, ed25519_keys.verify_signature(public, method,
                                                     signature, '123'))
   
    # Mismatched signature.
    bad_signature = b'a'*64 
    self.assertEqual(False, ed25519_keys.verify_signature(public, method,
                                                     bad_signature, data))
    
    # Generated signature created with different data.
    new_signature, method = ed25519_keys.create_signature(public, private, 
                                                     b'mismatched data')
    
    self.assertEqual(False, ed25519_keys.verify_signature(public, method,
                                                     new_signature, data))



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
