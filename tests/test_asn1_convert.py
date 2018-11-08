#!/usr/bin/env python

"""
<Program>
  test_asn1_convert.py

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit tests for 'asn1_convert.py' and the lower-level ASN.1 encoding modules.

  NOTE: Run test_asn1_convert.py from the 'tuf/tests/' directory so that the
  module finds the test data and scripts.
"""

# Support some Python3 functionality in Python2:
#    Support print as a function (`print(x)`).
#    Do not use implicit relative imports.
#    Operator `/` performs float division, not floored division.
#    Interpret string literals as unicode. (Treat 'x' like u'x')
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# Standard Library Imports
import unittest
unittest.util._MAX_LENGTH=20000  # DEBUG
import os
import logging
import binascii # for bytes to hex
# Dependency Imports
import asn1crypto as asn1
import asn1crypto.core as asn1_core
# TUF Imports
import tuf
import tuf.log
import tuf.unittest_toolbox as unittest_toolbox
import tuf.exceptions
import tuf.repository_tool as repo_tool
import tuf.encoding.asn1_convert as asn1_convert
import tuf.encoding.asn1_metadata_definitions as asn1_defs

logger = logging.getLogger('tuf.test_asn1_convert')

TEST_DATA_DIR = os.getcwd()

class TestASN1(unittest_toolbox.Modified_TestCase):
  def setUp(self):
    """
    """

    unittest_toolbox.Modified_TestCase.setUp(self)




  # Stop server process and perform clean up.
  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)




  def test_baseline(self):
    """
    Fail if basic asn1crypto functionality is broken.
    Use Integer and VisibleString.
    """

    i = asn1_core.Integer(5)
    self.assertEqual(5, i.native)

    i_der = i.dump()
    self.assertEqual(b'\x02\x01\x05', i_der)

    # Convert back and test.
    self.assertEqual(5, asn1_core.load(i_der).native)
    self.assertEqual(5, asn1_core.Integer.load(i_der).native)


    s = 'testword'
    expected_der_of_string = b'\x1a\x08testword'

    s_asn1 = asn1_core.VisibleString(s)
    self.assertEqual(s, s_asn1.native)

    s_der = s_asn1.dump()
    self.assertEqual(expected_der_of_string, s_der)

    self.assertEqual(s_asn1, asn1_core.load(s_der))
    self.assertEqual(s_asn1, asn1_core.VisibleString.load(s_der))

    self.assertEqual(s, asn1_core.load(s_der).native)
    self.assertEqual(s, asn1_core.VisibleString.load(s_der).native)





  def test_to_asn1_primitives(self):

    # Begin with basic objects: integers, strings, and octet strings.

    integer_asn1 = asn1_convert.to_asn1(123, asn1_core.Integer)
    self.assertEqual(123, integer_asn1.native)
    self.assertIsInstance(integer_asn1, asn1_core.Integer)

    # Repeat the check using conversion_check.
    self.conversion_check(
        data=123,
        datatype=asn1_core.Integer,
        expected_der=b'\x02\x01{')


    string_asn1 = asn1_convert.to_asn1(
        'alphabeta', asn1_core.VisibleString)
    self.assertEqual('alphabeta', string_asn1.native)
    self.assertIsInstance(string_asn1, asn1_core.VisibleString)

    # Repeat the check using conversion_check.
    self.conversion_check(
        data='alphabeta',
        datatype=asn1_core.VisibleString,
        expected_der=None) # TODO: Fill in expected_der.



    octets_asn1 = asn1_convert.to_asn1(
        '01234567890abcdef0', asn1_core.OctetString)
    self.assertEqual(
        '01234567890abcdef0',
        asn1_convert.hex_str_from_asn1_octets(octets_asn1))
    self.assertIsInstance(octets_asn1, asn1_core.OctetString)

    # Repeat the check using conversion_check.
    self.conversion_check(
        data='01234567890abcdef0',
        datatype=asn1_core.OctetString,
        expected_der=None) # TODO: Fill in expected_der.





  def test_hex_str_to_asn1_octets(self):
    hex_str = '3132333b3435361f373839'
    octets_asn1 = asn1_convert.hex_str_to_asn1_octets(hex_str)

    self.assertEqual(b'\x04\x0b123;456\x1f789', octets_asn1.dump())

    # Redundant checks in case test code changes.
    octets = bytes.fromhex(hex_str)
    self.assertEqual(octets, octets_asn1.native)





  def test_hex_str_from_asn1_octets(self):

    octets = b'123\x3b456\x1f789'
    octets_asn1 = asn1_core.OctetString(octets)

    hex_str = asn1_convert.hex_str_from_asn1_octets(octets_asn1)

    self.assertEqual(hex_str, '3132333b3435361f373839')

    # Redundant checks in case the test code changes.
    tuf.formats.HEX_SCHEMA.check_match(hex_str)
    self.assertEqual(octets, octets_asn1.native)
    self.assertEqual(len(hex_str), 2 * len(octets))





  def test_structlike_dict_conversions(self):
    """
    Tests _structlike_dict_to_asn1 and _structlike_dict_from_asn1
    """

    # Try a Signature object, which is a good example of a "struct-like" dict
    # and happens to contain only primitives.
    sig = {'keyid': '123456', 'sig': 'abcdef1234567890'}

    expected_der = (
        b'0\x0f\x04\x03\x124V\x04\x08\xab\xcd\xef\x124Vx\x90')

    # Test by calling the helper functions directly.
    self.conversion_check(
      data=sig,
      datatype=asn1_defs.Signature,
      expected_der=expected_der,
      to_asn1_func=asn1_convert._structlike_dict_to_asn1,
      from_asn1_func=asn1_convert._structlike_dict_from_asn1)

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    self.conversion_check(
        data=sig,
        datatype=asn1_defs.Signature,
        expected_der=expected_der)


    # TODO: Consider testing more complex objects here that would recurse
    # further through to_asn1 (further than just base cases).  Those'll be
    # tested in to_asn1 tests, though.


    # Manual, without using conversion_check:

    # Go to the helper function directly.
    sig_asn1_direct = asn1_convert._structlike_dict_to_asn1(
        sig, asn1_defs.Signature)

    # Call the function expected to call the helper function.
    sig_asn1 = asn1_convert.to_asn1(sig, asn1_defs.Signature)

    # Make sure the two calls yield comparable results.
    self.assert_asn1_obj_equivalent(sig_asn1_direct, sig_asn1)

    # The signature example is almost simple enough to convert back using purely
    # asn1crypto code, so try that to make sure the conversion worked:
    sig_again = dict(sig_asn1.native)
    sig_again['keyid'] = binascii.hexlify(sig_again['keyid']).decode('utf-8')
    sig_again['sig'] = binascii.hexlify(sig_again['sig']).decode('utf-8')
    self.assertEqual(sig, sig_again)

    # Convert to DER and test the result.
    sig_der = asn1_convert.asn1_to_der(sig_asn1)
    self.assertEqual(expected_der, sig_der)


    # Convert from DER to ASN.1 and make sure the result is the same.
    # Do this two ways:
    #   - use the ASN.1 definitions in tuf.encoding.asn1_metadata_definitions
    #     to know the exact expected structure of the data, including key names
    #   - skip using the ASN.1 definitions -- convert as if you don't know what
    #     the data will look like, or you don't know what kind of data it is
    #     before decoding. ("sig_asn1_again_rough")
    sig_asn1_again = asn1_convert.asn1_from_der(sig_der, asn1_defs.Signature)
    sig_asn1_again_rough = asn1_convert.asn1_from_der(sig_der) # without specifying class; loses info

    self.assert_asn1_obj_equivalent(sig_asn1, sig_asn1_again)

    # The rough conversion won't look the same to human eyes, but it should
    # still encode as the same DER.
    # i.e. test:   original --> ASN.1 --> DER -*-> ASN.1 --> DER)
    #   where -*-> is a conversion back without definitions (see comment above)
    self.assertNotEqual(sig_asn1, sig_asn1_again_rough)
    self.assertEqual(expected_der, sig_asn1_again_rough.dump())


    # Now convert back from ASN.1 to original format:
    #   original --> ASN.1 --> original
    #   original --> ASN.1 --> DER --> ASN.1 --> original
    self.assertEqual(sig, asn1_convert.from_asn1(sig_asn1))
    self.assertEqual(sig, asn1_convert.from_asn1(sig_asn1_again))






  def test_list_conversions(self):
    """
    Tests _list_to_asn1 and _list_from_asn1
    """

    # Try key ID hash algorithms, which is a good example of a list in
    # TUF-internal metadata that is converted to a SequenceOf containing only
    # primitives in ASN.1
    keyid_hash_algos = ["sha256", "sha512"]

    expected_der = b'0\x10\x1a\x06sha256\x1a\x06sha512'

    # Test by calling the helper functions directly.
    self.conversion_check(
      data=keyid_hash_algos,
      datatype=asn1_defs.VisibleStrings,
      expected_der=expected_der,
      to_asn1_func=asn1_convert._list_to_asn1,
      from_asn1_func=asn1_convert._list_from_asn1)

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    self.conversion_check(
        data=keyid_hash_algos,
        datatype=asn1_defs.VisibleStrings,
        expected_der=expected_der)





  def test_listlike_conversions(self):

    # # Try a Hashes object
    hashes = {
      'sha256':
        '65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da',
      'sha512':
        '467430a68afae8e9f9c0771ea5d78bf0b3a0d79a2d3d3b40c69fde4dd42c4614'
        '48aef76fcef4f5284931a1ffd0ac096d138ba3a0d6ca83fa8d7285a47a296f77'
    }

    expected_der = (
        b'1x0*\x1a\x06sha256\x04 e\xb8\xc6\x7fQ\xc9\x93\xd8\x98%\x0f@\xaaW\xa3\x17\xd8T\x90\x0b:\x04\x89Td1>HxT@\xda0J\x1a\x06sha512\x04@Ft0\xa6\x8a\xfa\xe8\xe9\xf9\xc0w\x1e\xa5\xd7\x8b\xf0\xb3\xa0\xd7\x9a-=;@\xc6\x9f\xdeM\xd4,F\x14H\xae\xf7o\xce\xf4\xf5(I1\xa1\xff\xd0\xac\tm\x13\x8b\xa3\xa0\xd6\xca\x83\xfa\x8dr\x85\xa4z)ow')


    # Test by calling the helper functions directly.
    self.conversion_check(
      data=hashes,
      datatype=asn1_defs.Hashes,
      expected_der=expected_der,
      to_asn1_func=asn1_convert._listlike_dict_to_asn1,
      from_asn1_func=asn1_convert._listlike_dict_from_asn1)

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    self.conversion_check(
        data=hashes,
        datatype=asn1_defs.Hashes,
        expected_der=expected_der)





  def test_key_conversion(self):

    # Import some public keys.
    ed_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'timestamp_key.pub')
    rsa_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'root_key.pub')

    ed_pub = repo_tool.import_ed25519_publickey_from_file(ed_pub_fname)
    rsa_pub = repo_tool.import_rsa_publickey_from_file(rsa_pub_fname)

    # Expected DER results from converting the keys:
    ed_key_expected_der = (
        b'0\x81\x94\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X\x1a\x07ed25519\x1a\x07ed255190L0J\x1a\x06public\x1a@82ccf6ac47298ff43bfa0cd639868894e305a99c723ff0515ae2e9856eb5bbf40\x10\x1a\x06sha256\x1a\x06sha512')
    rsa_key_expected_der = (
        b'0\x82\x02\xdd\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb\x1a\x03rsa\x1a\x11rsassa-pss-sha2560\x82\x02\x8d0\x82\x02|\x1a\x06public\x1a\x82\x02p-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0GjPoVrjS9eCqzoQ8VRe\nPkC0cI6ktiEgqPfHESFzyxyjC490Cuy19nuxPcJuZfN64MC48oOkR+W2mq4pM51i\nxmdG5xjvNOBRkJ5wUCc8fDCltMUTBlqt9y5eLsf/4/EoBU+zC4SW1iPU++mCsity\nfQQ7U6LOn3EYCyrkH51hZ/dvKC4o9TPYMVxNecJ3CL1q02Q145JlyjBTuM3Xdqsa\nndTHoXSRPmmzgB/1dL/c4QjMnCowrKW06mFLq9RAYGIaJWfM/0CbrOJpVDkATmEc\nMdpGJYDfW/sRQvRdlHNPo24ZW7vkQUCqdRxvnTWkK5U81y7RtjLt1yskbWXBIbOV\nz94GXsgyzANyCT9qRjHXDDz2mkLq+9I2iKtEqaEePcWRu3H6RLahpM/TxFzw684Y\nR47weXdDecPNxWyiWiyMGStRFP4Cg9trcwAGnEm1w8R2ggmWphznCd5dXGhPNjfA\na82yNFY8ubnOUVJOf0nXGg3Edw9iY3xyjJb2+nrsk5f3AgMBAAE=\n-----END PUBLIC KEY-----0\x0b\x1a\x07private\x1a\x000\x10\x1a\x06sha256\x1a\x06sha512')

    # Test by calling the helper functions directly.
    self.conversion_check(
      data=ed_pub,
      datatype=asn1_defs.Key,
      #expected_der=ed_key_expected_der,
      to_asn1_func=asn1_convert._structlike_dict_to_asn1,
      from_asn1_func=asn1_convert._structlike_dict_from_asn1)
    self.conversion_check(
      data=rsa_pub,
      datatype=asn1_defs.Key,
      #expected_der=rsa_key_expected_der,
      to_asn1_func=asn1_convert._structlike_dict_to_asn1,
      from_asn1_func=asn1_convert._structlike_dict_from_asn1)

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    self.conversion_check(
        data=ed_pub,
        datatype=asn1_defs.Key,
        #expected_der=ed_key_expected_der
        )
    self.conversion_check(
        data=rsa_pub,
        datatype=asn1_defs.Key,
        #expected_der=rsa_key_expected_der
        )





  def test_signed_portion_of_root_conversion(self):
    root = {
      'signatures': [
        {
         'keyid': '4e777de0d275f9d28588dd9a1606cc748e548f9e22b6795b7cb3f63f98035fcb',
         'sig': '2dd47f039360e64bd8c6365809507d9316b8615deb8b56d7e50cfdbd9fb59798dd4025922662b30bbd19c2c12ddce768f04489ded70b0ec987a732dcb36d03d3eea3f4bf99a12a4e21381335279cb813d32b024ae666dd851b4a41e1023eb6a138f80e95e39f98b114945e790c4654eed9954ca0a081c16880a72665c06c3f8fadf05e4088fae522ff03b050fcd9b4f4f168739c8e10d42ff647770527186a7f5b7e131b8fc591016d178ce9829f12759c866e4663b4c2e8d9c5b519cdfd4ae877c66a9a630127fcb63575e7f22c20d29f955c42818a864780472fa976ab571813a24913d5b800f6de1cca485c02378d4a2c032e61893d321f7ef17f84a3792ba694d3c01ec0f500fbc2442bd235515b27ade79bcebfd13a8e68d8336829337e38e6a69614455b7550de522d6a74abaefa19ba2e26b5d0854a2187738b900d7b8c30c8d5b75a07ea461856828142356a9de4f329dfbd399b2534b50b103fc10c67444dfa576005f1852beda0bf07401ac5d9d54b0e51dc143261c48bde3169c4'
        }
      ],
      'signed': {
        '_type': 'root',
        'consistent_snapshot': False,
        'expires': '2030-01-01T00:00:00Z',
        'keys': {
          '4e777de0d275f9d28588dd9a1606cc748e548f9e22b6795b7cb3f63f98035fcb': {
            'keyid_hash_algorithms': ['sha256', 'sha512'],
            'keytype': 'rsa',
            'keyval': {'public': '-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0GjPoVrjS9eCqzoQ8VRe\nPkC0cI6ktiEgqPfHESFzyxyjC490Cuy19nuxPcJuZfN64MC48oOkR+W2mq4pM51i\nxmdG5xjvNOBRkJ5wUCc8fDCltMUTBlqt9y5eLsf/4/EoBU+zC4SW1iPU++mCsity\nfQQ7U6LOn3EYCyrkH51hZ/dvKC4o9TPYMVxNecJ3CL1q02Q145JlyjBTuM3Xdqsa\nndTHoXSRPmmzgB/1dL/c4QjMnCowrKW06mFLq9RAYGIaJWfM/0CbrOJpVDkATmEc\nMdpGJYDfW/sRQvRdlHNPo24ZW7vkQUCqdRxvnTWkK5U81y7RtjLt1yskbWXBIbOV\nz94GXsgyzANyCT9qRjHXDDz2mkLq+9I2iKtEqaEePcWRu3H6RLahpM/TxFzw684Y\nR47weXdDecPNxWyiWiyMGStRFP4Cg9trcwAGnEm1w8R2ggmWphznCd5dXGhPNjfA\na82yNFY8ubnOUVJOf0nXGg3Edw9iY3xyjJb2+nrsk5f3AgMBAAE=\n-----END PUBLIC KEY-----'},
            'scheme': 'rsassa-pss-sha256'},
          '59a4df8af818e9ed7abe0764c0b47b4240952aa0d179b5b78346c470ac30278d': {
            'keyid_hash_algorithms': ['sha256', 'sha512'],
            'keytype': 'ed25519',
            'keyval': {'public': 'edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd'},
            'scheme': 'ed25519'},
          '65171251a9aff5a8b3143a813481cb07f6e0de4eb197c767837fe4491b739093': {
            'keyid_hash_algorithms': ['sha256', 'sha512'],
            'keytype': 'ed25519',
            'keyval': {'public': '89f28bd4ede5ec3786ab923fd154f39588d20881903e69c7b08fb504c6750815'},
            'scheme': 'ed25519'},
          '8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758': {
            'keyid_hash_algorithms': ['sha256', 'sha512'],
            'keytype': 'ed25519',
            'keyval': {'public': '82ccf6ac47298ff43bfa0cd639868894e305a99c723ff0515ae2e9856eb5bbf4'},
            'scheme': 'ed25519'}},
        'roles': {
          'root': {
            'keyids': ['4e777de0d275f9d28588dd9a1606cc748e548f9e22b6795b7cb3f63f98035fcb'],
            'threshold': 1},
          'snapshot': {
            'keyids': ['59a4df8af818e9ed7abe0764c0b47b4240952aa0d179b5b78346c470ac30278d'],
            'threshold': 1},
          'targets': {
            'keyids': ['65171251a9aff5a8b3143a813481cb07f6e0de4eb197c767837fe4491b739093'],
            'threshold': 1},
          'timestamp': {
            'keyids': ['8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758'],
            'threshold': 1}},
        'spec_version': '1.0',
        'version': 1
      }
    }

    root_data_expected_der = (
        b'0\x82\x05K\x1a\x04root\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x01\x01\x01\x000\x82\x04y0\x82\x02\xc8\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb0\x82\x02\xa2\x1a\x03rsa\x1a\x11rsassa-pss-sha2560\x82\x02t\x1a\x82\x02p-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0GjPoVrjS9eCqzoQ8VRe\nPkC0cI6ktiEgqPfHESFzyxyjC490Cuy19nuxPcJuZfN64MC48oOkR+W2mq4pM51i\nxmdG5xjvNOBRkJ5wUCc8fDCltMUTBlqt9y5eLsf/4/EoBU+zC4SW1iPU++mCsity\nfQQ7U6LOn3EYCyrkH51hZ/dvKC4o9TPYMVxNecJ3CL1q02Q145JlyjBTuM3Xdqsa\nndTHoXSRPmmzgB/1dL/c4QjMnCowrKW06mFLq9RAYGIaJWfM/0CbrOJpVDkATmEc\nMdpGJYDfW/sRQvRdlHNPo24ZW7vkQUCqdRxvnTWkK5U81y7RtjLt1yskbWXBIbOV\nz94GXsgyzANyCT9qRjHXDDz2mkLq+9I2iKtEqaEePcWRu3H6RLahpM/TxFzw684Y\nR47weXdDecPNxWyiWiyMGStRFP4Cg9trcwAGnEm1w8R2ggmWphznCd5dXGhPNjfA\na82yNFY8ubnOUVJOf0nXGg3Edw9iY3xyjJb2+nrsk5f3AgMBAAE=\n-----END PUBLIC KEY-----0\x10\x1a\x06sha256\x1a\x06sha5120\x81\x8c\x04 Y\xa4\xdf\x8a\xf8\x18\xe9\xedz\xbe\x07d\xc0\xb4{B@\x95*\xa0\xd1y\xb5\xb7\x83F\xc4p\xac0\'\x8d0h\x1a\x07ed25519\x1a\x07ed255190B\x1a@edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd0\x10\x1a\x06sha256\x1a\x06sha5120\x81\x8c\x04 e\x17\x12Q\xa9\xaf\xf5\xa8\xb3\x14:\x814\x81\xcb\x07\xf6\xe0\xdeN\xb1\x97\xc7g\x83\x7f\xe4I\x1bs\x90\x930h\x1a\x07ed25519\x1a\x07ed255190B\x1a@89f28bd4ede5ec3786ab923fd154f39588d20881903e69c7b08fb504c67508150\x10\x1a\x06sha256\x1a\x06sha5120\x81\x8c\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X0h\x1a\x07ed25519\x1a\x07ed255190B\x1a@82ccf6ac47298ff43bfa0cd639868894e305a99c723ff0515ae2e9856eb5bbf40\x10\x1a\x06sha256\x1a\x06sha5120\x81\xa40\'0"\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb\x02\x01\x010\'0"\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X\x02\x01\x010\'0"\x04 Y\xa4\xdf\x8a\xf8\x18\xe9\xedz\xbe\x07d\xc0\xb4{B@\x95*\xa0\xd1y\xb5\xb7\x83F\xc4p\xac0\'\x8d\x02\x01\x010\'0"\x04 e\x17\x12Q\xa9\xaf\xf5\xa8\xb3\x14:\x814\x81\xcb\x07\xf6\xe0\xdeN\xb1\x97\xc7g\x83\x7f\xe4I\x1bs\x90\x93\x02\x01\x01')

    root_signable_expected_der = (
        b'0\x82\x06\xfd0\x82\x01\xaa0\x82\x01\xa6\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb\x04\x82\x01\x80-\xd4\x7f\x03\x93`\xe6K\xd8\xc66X\tP}\x93\x16\xb8a]\xeb\x8bV\xd7\xe5\x0c\xfd\xbd\x9f\xb5\x97\x98\xdd@%\x92&b\xb3\x0b\xbd\x19\xc2\xc1-\xdc\xe7h\xf0D\x89\xde\xd7\x0b\x0e\xc9\x87\xa72\xdc\xb3m\x03\xd3\xee\xa3\xf4\xbf\x99\xa1*N!8\x135\'\x9c\xb8\x13\xd3+\x02J\xe6f\xdd\x85\x1bJA\xe1\x02>\xb6\xa18\xf8\x0e\x95\xe3\x9f\x98\xb1\x14\x94^y\x0cFT\xee\xd9\x95L\xa0\xa0\x81\xc1h\x80\xa7&e\xc0l?\x8f\xad\xf0^@\x88\xfa\xe5"\xff\x03\xb0P\xfc\xd9\xb4\xf4\xf1hs\x9c\x8e\x10\xd4/\xf6Gw\x05\'\x18j\x7f[~\x13\x1b\x8f\xc5\x91\x01m\x17\x8c\xe9\x82\x9f\x12u\x9c\x86nFc\xb4\xc2\xe8\xd9\xc5\xb5\x19\xcd\xfdJ\xe8w\xc6j\x9ac\x01\'\xfc\xb65u\xe7\xf2, \xd2\x9f\x95\\B\x81\x8a\x86G\x80G/\xa9v\xabW\x18\x13\xa2I\x13\xd5\xb8\x00\xf6\xde\x1c\xcaH\\\x027\x8dJ,\x03.a\x89=2\x1f~\xf1\x7f\x84\xa3y+\xa6\x94\xd3\xc0\x1e\xc0\xf5\x00\xfb\xc2D+\xd25Q[\'\xad\xe7\x9b\xce\xbf\xd1:\x8eh\xd83h)3~8\xe6\xa6\x96\x14E[uP\xdeR-jt\xab\xae\xfa\x19\xba.&\xb5\xd0\x85J!\x87s\x8b\x90\r{\x8c0\xc8\xd5\xb7Z\x07\xeaF\x18V\x82\x81B5j\x9d\xe4\xf3)\xdf\xbd9\x9b%4\xb5\x0b\x10?\xc1\x0cgDM\xfaW`\x05\xf1\x85+\xed\xa0\xbf\x07@\x1a\xc5\xd9\xd5K\x0eQ\xdc\x142a\xc4\x8b\xde1i\xc40\x82\x05K\x1a\x04root\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x01\x01\x01\x000\x82\x04y0\x82\x02\xc8\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb0\x82\x02\xa2\x1a\x03rsa\x1a\x11rsassa-pss-sha2560\x82\x02t\x1a\x82\x02p-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0GjPoVrjS9eCqzoQ8VRe\nPkC0cI6ktiEgqPfHESFzyxyjC490Cuy19nuxPcJuZfN64MC48oOkR+W2mq4pM51i\nxmdG5xjvNOBRkJ5wUCc8fDCltMUTBlqt9y5eLsf/4/EoBU+zC4SW1iPU++mCsity\nfQQ7U6LOn3EYCyrkH51hZ/dvKC4o9TPYMVxNecJ3CL1q02Q145JlyjBTuM3Xdqsa\nndTHoXSRPmmzgB/1dL/c4QjMnCowrKW06mFLq9RAYGIaJWfM/0CbrOJpVDkATmEc\nMdpGJYDfW/sRQvRdlHNPo24ZW7vkQUCqdRxvnTWkK5U81y7RtjLt1yskbWXBIbOV\nz94GXsgyzANyCT9qRjHXDDz2mkLq+9I2iKtEqaEePcWRu3H6RLahpM/TxFzw684Y\nR47weXdDecPNxWyiWiyMGStRFP4Cg9trcwAGnEm1w8R2ggmWphznCd5dXGhPNjfA\na82yNFY8ubnOUVJOf0nXGg3Edw9iY3xyjJb2+nrsk5f3AgMBAAE=\n-----END PUBLIC KEY-----0\x10\x1a\x06sha256\x1a\x06sha5120\x81\x8c\x04 Y\xa4\xdf\x8a\xf8\x18\xe9\xedz\xbe\x07d\xc0\xb4{B@\x95*\xa0\xd1y\xb5\xb7\x83F\xc4p\xac0\'\x8d0h\x1a\x07ed25519\x1a\x07ed255190B\x1a@edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd0\x10\x1a\x06sha256\x1a\x06sha5120\x81\x8c\x04 e\x17\x12Q\xa9\xaf\xf5\xa8\xb3\x14:\x814\x81\xcb\x07\xf6\xe0\xdeN\xb1\x97\xc7g\x83\x7f\xe4I\x1bs\x90\x930h\x1a\x07ed25519\x1a\x07ed255190B\x1a@89f28bd4ede5ec3786ab923fd154f39588d20881903e69c7b08fb504c67508150\x10\x1a\x06sha256\x1a\x06sha5120\x81\x8c\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X0h\x1a\x07ed25519\x1a\x07ed255190B\x1a@82ccf6ac47298ff43bfa0cd639868894e305a99c723ff0515ae2e9856eb5bbf40\x10\x1a\x06sha256\x1a\x06sha5120\x81\xa40\'0"\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb\x02\x01\x010\'0"\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X\x02\x01\x010\'0"\x04 Y\xa4\xdf\x8a\xf8\x18\xe9\xedz\xbe\x07d\xc0\xb4{B@\x95*\xa0\xd1y\xb5\xb7\x83F\xc4p\xac0\'\x8d\x02\x01\x010\'0"\x04 e\x17\x12Q\xa9\xaf\xf5\xa8\xb3\x14:\x814\x81\xcb\x07\xf6\xe0\xdeN\xb1\x97\xc7g\x83\x7f\xe4I\x1bs\x90\x93\x02\x01\x01')

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    # 'signed' subsection first.
    self.conversion_check(
        data=root['signed'],
        datatype=asn1_defs.RootMetadata,
        expected_der=root_data_expected_der)

    # Then the whole thing.
    self.conversion_check(
        data=root,
        datatype=asn1_defs.RootEnvelope,
        expected_der=root_signable_expected_der)





  def test_signed_portion_of_timestamp_conversion(self):
    timestamp = {
      'signatures': [
        {
         'keyid': '8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758',
         'sig': '7dddbfe94d6d80253433551700ea6dfe4171a33f1227a07830e951900b8325d67c3dce6410b9cf55abefa3dfca0b57814a4965c2d6ee60bb0336755cd0557e03'
        }
      ],
      'signed': {
        "_type": "timestamp",
        "expires": "2030-01-01T00:00:00Z",
        "meta": {
         "snapshot.json": {
          "hashes": {
           "sha256": "6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f"
          },
          "length": 554,
          "version": 1
         }
        },
        "spec_version": "1.0",
        "version": 1
      }
    }

    timestamp_data_expected_der = (
        b"0s\x1a\ttimestamp\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x011H0F\x1a\rsnapshot.json051,0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/\x02\x02\x02*\x02\x01\x01")

    timestamp_signable_expected_der = (
        b"0\x81\xdd0f0d\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X\x04@}\xdd\xbf\xe9Mm\x80%43U\x17\x00\xeam\xfeAq\xa3?\x12'\xa0x0\xe9Q\x90\x0b\x83%\xd6|=\xced\x10\xb9\xcfU\xab\xef\xa3\xdf\xca\x0bW\x81JIe\xc2\xd6\xee`\xbb\x036u\\\xd0U~\x030s\x1a\ttimestamp\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x011H0F\x1a\rsnapshot.json051,0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/\x02\x02\x02*\x02\x01\x01")

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    # 'signed' subsection first.
    self.conversion_check(
        data=timestamp['signed'],
        datatype=asn1_defs.TimestampMetadata,
        expected_der=timestamp_data_expected_der)

    # Then the whole thing.
    self.conversion_check(
        data=timestamp,
        datatype=asn1_defs.TimestampEnvelope,
        expected_der=timestamp_signable_expected_der)





  def test_signed_portion_of_snapshot_conversion(self):
    snapshot = {
      'signatures': [
        {
         'keyid': '59a4df8af818e9ed7abe0764c0b47b4240952aa0d179b5b78346c470ac30278d',
         'sig': 'd78e9013bab1da2a8425caa48143cd79a21632dce021ad7e1b883d83775035df333a8b26c9c952d832edaf9dc7be2ef612bdb21326fcc9849346d7e3a162050e'
        }
      ],
      'signed': {
        "_type": "snapshot",
        "expires": "2030-01-01T00:00:00Z",
        "spec_version": "1.0",
        "version": 1,
        "meta": {
          "role1.json": {
            "version": 1},
          "role2.json": {
            "version": 1},
          "root.json": {
            "version": 1},
          "targets.json": {
            "version": 1}
        }
      }
    }

    snapshot_data_expected_der = (
        b"0w\x1a\x08snapshot\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x010M0\x11\x1a\nrole1.json0\x03\x02\x01\x010\x11\x1a\nrole2.json0\x03\x02\x01\x010\x10\x1a\troot.json0\x03\x02\x01\x010\x13\x1a\x0ctargets.json0\x03\x02\x01\x01")

    snapshot_signable_expected_der = (
        b"0\x81\xe10f0d\x04 Y\xa4\xdf\x8a\xf8\x18\xe9\xedz\xbe\x07d\xc0\xb4{B@\x95*\xa0\xd1y\xb5\xb7\x83F\xc4p\xac0'\x8d\x04@\xd7\x8e\x90\x13\xba\xb1\xda*\x84%\xca\xa4\x81C\xcdy\xa2\x162\xdc\xe0!\xad~\x1b\x88=\x83wP5\xdf3:\x8b&\xc9\xc9R\xd82\xed\xaf\x9d\xc7\xbe.\xf6\x12\xbd\xb2\x13&\xfc\xc9\x84\x93F\xd7\xe3\xa1b\x05\x0e0w\x1a\x08snapshot\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x010M0\x11\x1a\nrole1.json0\x03\x02\x01\x010\x11\x1a\nrole2.json0\x03\x02\x01\x010\x10\x1a\troot.json0\x03\x02\x01\x010\x13\x1a\x0ctargets.json0\x03\x02\x01\x01")

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    # 'signed' subsection first.
    self.conversion_check(
        data=snapshot['signed'],
        datatype=asn1_defs.SnapshotMetadata,
        expected_der=snapshot_data_expected_der)

    # Then the whole thing.
    self.conversion_check(
        data=snapshot,
        datatype=asn1_defs.SnapshotEnvelope,
        expected_der=snapshot_signable_expected_der)





  def test_targets_conversion(self):
    targets = {
        "signatures": [
          {
            "keyid": "65171251a9aff5a8b3143a813481cb07f6e0de4eb197c767837fe4491b739093",
            "sig": "52ca8ecf32ead7030e8ee2c2a28e52bd0e6d03fc3c07821bbec0f3ba42a7d92a8eb0ff931ed581db3b6782bb53f8daa645dabecaa06c66bf8861669d7157d002"
          }
        ],
        "signed": {
          "_type": "targets",
          "delegations": {
           "keys": {
            "c8022fa1e9b9cb239a6b362bbdffa9649e61ad2cb699d2e4bc4fdf7930a0e64a": {
             "keyid_hash_algorithms": [
              "sha256",
              "sha512"
             ],
             "keytype": "ed25519",
             "keyval": {
              "public": "fcf224e55fa226056adf113ef1eb3d55e308b75b321c8c8316999d8c4fd9e0d9"
             },
             "scheme": "ed25519"
            }
           },
           "roles": [
            {
             "keyids": [
              "c8022fa1e9b9cb239a6b362bbdffa9649e61ad2cb699d2e4bc4fdf7930a0e64a"
             ],
             "name": "role1",
             "paths": [
              "file3.txt"
             ],
             "terminating": False,
             "threshold": 1
            }
           ]
          },
          "expires": "2030-01-01T00:00:00Z",
          "spec_version": "1.0",
          "targets": {
           "file1.txt": {
            "custom": {
             "file_permissions": "644"
            },
            "hashes": {
             "sha256": "65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da",
             "sha512": "467430a68afae8e9f9c0771ea5d78bf0b3a0d79a2d3d3b40c69fde4dd42c461448aef76fcef4f5284931a1ffd0ac096d138ba3a0d6ca83fa8d7285a47a296f77"
            },
            "length": 31
           },
           "file2.txt": {
            "hashes": {
             "sha256": "452ce8308500d83ef44248d8e6062359211992fd837ea9e370e561efb1a4ca99",
             "sha512": "052b49a21e03606b28942db69aa597530fe52d47ee3d748ba65afcd14b857738e36bc1714c4f4adde46c3e683548552fe5c96722e0e0da3acd9050c2524902d8"
            },
            "length": 39
           }
          },
          "version": 1
        }
    }

    targets_data_expected_der = (
        b'0\x82\x025\x1a\x07targets\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x010\x82\x0160\x81\xa6\x1a\tfile1.txt0\x81\x98\x02\x01\x1f1x0*\x1a\x06sha256\x04 e\xb8\xc6\x7fQ\xc9\x93\xd8\x98%\x0f@\xaaW\xa3\x17\xd8T\x90\x0b:\x04\x89Td1>HxT@\xda0J\x1a\x06sha512\x04@Ft0\xa6\x8a\xfa\xe8\xe9\xf9\xc0w\x1e\xa5\xd7\x8b\xf0\xb3\xa0\xd7\x9a-=;@\xc6\x9f\xdeM\xd4,F\x14H\xae\xf7o\xce\xf4\xf5(I1\xa1\xff\xd0\xac\tm\x13\x8b\xa3\xa0\xd6\xca\x83\xfa\x8dr\x85\xa4z)ow0\x190\x17\x1a\x10file_permissions\x1a\x036440\x81\x8a\x1a\tfile2.txt0}\x02\x01\'1x0*\x1a\x06sha256\x04 E,\xe80\x85\x00\xd8>\xf4BH\xd8\xe6\x06#Y!\x19\x92\xfd\x83~\xa9\xe3p\xe5a\xef\xb1\xa4\xca\x990J\x1a\x06sha512\x04@\x05+I\xa2\x1e\x03`k(\x94-\xb6\x9a\xa5\x97S\x0f\xe5-G\xee=t\x8b\xa6Z\xfc\xd1K\x85w8\xe3k\xc1qLOJ\xdd\xe4l>h5HU/\xe5\xc9g"\xe0\xe0\xda:\xcd\x90P\xc2RI\x02\xd80\x81\xd10\x81\x8f0\x81\x8c\x04 \xc8\x02/\xa1\xe9\xb9\xcb#\x9ak6+\xbd\xff\xa9d\x9ea\xad,\xb6\x99\xd2\xe4\xbcO\xdfy0\xa0\xe6J0h\x1a\x07ed25519\x1a\x07ed255190B\x1a@fcf224e55fa226056adf113ef1eb3d55e308b75b321c8c8316999d8c4fd9e0d90\x10\x1a\x06sha256\x1a\x06sha5120=0;\x1a\x05role10"\x04 \xc8\x02/\xa1\xe9\xb9\xcb#\x9ak6+\xbd\xff\xa9d\x9ea\xad,\xb6\x99\xd2\xe4\xbcO\xdfy0\xa0\xe6J0\x0b\x1a\tfile3.txt\x02\x01\x01')

    targets_signable_expected_der = (
        b'0\x82\x02\xa10f0d\x04 e\x17\x12Q\xa9\xaf\xf5\xa8\xb3\x14:\x814\x81\xcb\x07\xf6\xe0\xdeN\xb1\x97\xc7g\x83\x7f\xe4I\x1bs\x90\x93\x04@R\xca\x8e\xcf2\xea\xd7\x03\x0e\x8e\xe2\xc2\xa2\x8eR\xbd\x0em\x03\xfc<\x07\x82\x1b\xbe\xc0\xf3\xbaB\xa7\xd9*\x8e\xb0\xff\x93\x1e\xd5\x81\xdb;g\x82\xbbS\xf8\xda\xa6E\xda\xbe\xca\xa0lf\xbf\x88af\x9dqW\xd0\x020\x82\x025\x1a\x07targets\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x010\x82\x0160\x81\xa6\x1a\tfile1.txt0\x81\x98\x02\x01\x1f1x0*\x1a\x06sha256\x04 e\xb8\xc6\x7fQ\xc9\x93\xd8\x98%\x0f@\xaaW\xa3\x17\xd8T\x90\x0b:\x04\x89Td1>HxT@\xda0J\x1a\x06sha512\x04@Ft0\xa6\x8a\xfa\xe8\xe9\xf9\xc0w\x1e\xa5\xd7\x8b\xf0\xb3\xa0\xd7\x9a-=;@\xc6\x9f\xdeM\xd4,F\x14H\xae\xf7o\xce\xf4\xf5(I1\xa1\xff\xd0\xac\tm\x13\x8b\xa3\xa0\xd6\xca\x83\xfa\x8dr\x85\xa4z)ow0\x190\x17\x1a\x10file_permissions\x1a\x036440\x81\x8a\x1a\tfile2.txt0}\x02\x01\'1x0*\x1a\x06sha256\x04 E,\xe80\x85\x00\xd8>\xf4BH\xd8\xe6\x06#Y!\x19\x92\xfd\x83~\xa9\xe3p\xe5a\xef\xb1\xa4\xca\x990J\x1a\x06sha512\x04@\x05+I\xa2\x1e\x03`k(\x94-\xb6\x9a\xa5\x97S\x0f\xe5-G\xee=t\x8b\xa6Z\xfc\xd1K\x85w8\xe3k\xc1qLOJ\xdd\xe4l>h5HU/\xe5\xc9g"\xe0\xe0\xda:\xcd\x90P\xc2RI\x02\xd80\x81\xd10\x81\x8f0\x81\x8c\x04 \xc8\x02/\xa1\xe9\xb9\xcb#\x9ak6+\xbd\xff\xa9d\x9ea\xad,\xb6\x99\xd2\xe4\xbcO\xdfy0\xa0\xe6J0h\x1a\x07ed25519\x1a\x07ed255190B\x1a@fcf224e55fa226056adf113ef1eb3d55e308b75b321c8c8316999d8c4fd9e0d90\x10\x1a\x06sha256\x1a\x06sha5120=0;\x1a\x05role10"\x04 \xc8\x02/\xa1\xe9\xb9\xcb#\x9ak6+\xbd\xff\xa9d\x9ea\xad,\xb6\x99\xd2\xe4\xbcO\xdfy0\xa0\xe6J0\x0b\x1a\tfile3.txt\x02\x01\x01')

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    # 'signed' subsection first.
    self.conversion_check(
        data=targets['signed'],
        datatype=asn1_defs.TargetsMetadata,
        expected_der=targets_data_expected_der)

    # Then the whole thing.
    self.conversion_check(
        data=targets,
        datatype=asn1_defs.TargetsEnvelope,
        expected_der=targets_signable_expected_der)





  # def _call_func(func, one, two):
  #   """
  #   Painfully specific function that calls provided function 'func' and passes
  #   it the 'one' argument, but only passes the 'two' argument if 'two' is not
  #   None.  This is used to generalize conversion_check so that it can deal both
  #   with datatype-specific converters (that expect only one argument, the data),
  #   and generic converters (which also expect a second argument "datatype")
  #   """
  #   if two is None:
  #     return func(one)
  #   else:
  #     return func(one, two)



  def conversion_check(self,
      data,
      datatype,
      expected_der=None,                            # if None, will not check
      to_asn1_func=asn1_convert.to_asn1,            # cannot be None
      to_der_func=asn1_convert.asn1_to_der,         # cannot be None
      from_asn1_func=asn1_convert.from_asn1,        # if None, will skip revert
      from_der_func=asn1_convert.asn1_from_der):    # cannot be None
    """
    By default:
     - Convert data to ASN.1 using "to_asn1_func" argument.
     - Encode ASN.1 to DER.
     - Decode DER to ASN.1 again.
     - Test equality with originally-generated ASN.1
     - Return the ASN.1 and DER values produced in case the caller wants to use
       them to perform additional tests.

    Optionally:
     - Compare the provided expected DER data to what was produced.
     - Using optional from_asn1_func:
         - Convert [original -> ASN.1 -> original] and test.
         - Convert [original -> ASN.1 -> DER -> ASN.1 -> original] and test.
     - Passes the given datatype to "func_to_asn1" and (if provided)
       "from_asn1_func" when calling. This is of use for general conversion
       functions that must be told which datatype to convert to/from (like
       "to_asn1" and "from_asn1").
    """

    data_asn1 = to_asn1_func(data, datatype)

    data_der = to_der_func(data_asn1)

    if expected_der is not None:
      self.assertEqual(expected_der, data_der)

    else:
      print('Original data: ' + str(data))
      print('DER data: ' + str(data_der))


    # Whether or not we have the definitions (arg "datatype"), we can decode
    # the DER, kinda.  It may end up as the wrong type, a Sequence instead of
    # a SequenceOf or Set or SetOf.  It will also be missing things like field
    # names.  The ASN.1 will be much more bare-bones, but it should still
    # encode to the same DER, so we'll test that.
    data_asn1_again_blind = from_der_func(data_der)

    # Even if we decode with limited info, we should be able to turn around and
    # encode the data the same way. (Distinguished Encoding Rules emphasizes
    # this.)
    if expected_der is not None:
      self.assertEqual(expected_der, data_asn1_again_blind.dump())

    # Now decode the DER using the datatype (the ASN.1 definition).
    # Definitions-aided decoding, knowing structure.
    data_asn1_again = from_der_func(data_der, datatype)

    if expected_der is not None:
      self.assertEqual(expected_der, data_asn1_again.dump())


    # We can expect the decoded ASN.1 to be identical to the originally
    # generated ASN.1 this way.
    # We can't test strict equality of the two objects, because asn1crypto
    # objects contain various cached values, have some things lazily loaded,
    # etc.  So we'll test everything we care about:
    self.assert_asn1_obj_equivalent(data_asn1, data_asn1_again)


    # And we can expect that even if it's not identical to the blind decoding,
    # it will still encode as the same DER.
    self.assertEqual(data_asn1_again_blind.dump(), data_asn1_again.dump())


    if from_asn1_func is not None:

      # Convert original->pyasn1 data back and test it.
      self.assertEqual(data, from_asn1_func(data_asn1))

      # Convert original->pyasn1->der data back and test it.
      # If when we decoded the DER into ASN.1, we knew the exact ASN.1
      # definition, then we can expect the result to be identical to the
      # original data.
      self.assertEqual(data, from_asn1_func(data_asn1_again))

      # # If we DIDN'T know the exact ASN.1 definition when we decoded the DER,
      # # the result will share important properties with the original, but
      # # things may be missing, like field names.  Equality will fail.  Have to
      # # tune this test....
      # # TODO: <~> Improve this test to deal with the preceding comment.
      # # NOTE THAT this does NOT use from_asn1_func, but always uses
      # # asn1_convert.from_asn1.  This is because the given function can't be
      # # expected to run with something that may no longer have the right type,
      # # and the blindly parsed DER might use Sequence instead of SequenceOf and
      # # won't know about custom subclasses, etc.  It's not clear this is a
      # # useful test, but here we go....
      # self.assertEqual(data, asn1_convert.from_asn1(data_asn1_again_blind))

    # Also return the values produced in case there is additional testing that
    # is to be done, specific to the particular data.
    return data_asn1, data_der





  def assert_asn1_obj_equivalent(self, obj1, obj2):
    """
    Fail the test that called this function if asn1crypto objects obj1 and obj2
    are not identical in all relevant respects:
      - .dump()      (DER encoding)
      - .native      (native Python values when converted back)
      - ._children   (child info)
      - ._contents   (similar to _children)
      - ._fields     (Sequence/Set member type)
      - ._child_spec (SequenceOf/SetOf member type)
    """
    self.assertEqual(obj1.dump(), obj2.dump())

    # Note that it's good to touch .native on both of these before conducting
    # the next tests so that lazily-updated fields like _children will be
    # populated.
    self.assertEqual(obj1.native, obj2.native)


    for field in ['_contents', '_children', '_child_spec', '_fields']:

      # Do not replace these checks with getattr(, , None) -- not the same.

      self.assertEqual(hasattr(obj1, field), hasattr(obj2, field))

      if hasattr(obj1, field):
        self.assertEqual(getattr(obj1, field), getattr(obj2, field))



# Run unit test.
if __name__ == '__main__':
  unittest.main()
