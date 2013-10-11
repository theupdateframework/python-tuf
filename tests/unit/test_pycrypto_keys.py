"""
<Program Name>
  test_pycrypto_keys.py

<Author> 
  Vladimir Diaz 

<Started>
  October 10, 2013. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_pycrypto_keys.py.
"""

import unittest
import logging

import tuf
import tuf.log
import tuf.formats
import tuf.pycrypto_keys as pycrypto

logger = logging.getLogger('tuf.test_pycrypto_keys')

FORMAT_ERROR_MSG = 'tuf.FormatError raised.  Check object\'s format.'
public_rsa, private_rsa = pycrypto.generate_rsa_public_and_private()


class TestPycrypto_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_rsa_public_and_private(self):
    pass


  def test_create_signature(self):
    pass


  def test_verify_signature(self):
    pass


  def test_create_rsa_encrypted_pem(self):
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
  
  
  def test_create_rsa_public_and_private_from_encrypted_pem(self):
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
 


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
