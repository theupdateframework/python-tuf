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
unittest.util._MAX_LENGTH=2000  # DEBUG
import os
import logging
import binascii # for bytes to hex
# Dependency Imports
import asn1crypto as asn1
import asn1crypto.core as asn1_core
'''
import pyasn1
import pyasn1.type.univ as pyasn1_univ
import pyasn1.type.char as pyasn1_char
import pyasn1.codec.der.encoder as pyasn1_der_encoder
'''
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
    sig = {'keyid': '123456', 'method': 'magical', 'value': 'abcdef1234567890'}

    expected_der = \
        b'0\x18\x04\x03\x124V\x1a\x07magical\x04\x08\xab\xcd\xef\x124Vx\x90'

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
    sig_again['value'] = binascii.hexlify(sig_again['value']).decode('utf-8')
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

    # Try a KeyIDHashAlgorithms object, which is a good example of a list in
    # TUF-internal metadata that is converted to a SequenceOf containing only
    # primitives in ASN.1
    keyid_hash_algos = ["sha256", "sha512"]

    expected_der = b'0\x10\x1a\x06sha256\x1a\x06sha512'

    # Test by calling the helper functions directly.
    self.conversion_check(
      data=keyid_hash_algos,
      datatype=asn1_defs.KeyIDHashAlgorithms,
      expected_der=expected_der,
      to_asn1_func=asn1_convert._list_to_asn1,
      from_asn1_func=asn1_convert._list_from_asn1)

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    self.conversion_check(
        data=keyid_hash_algos,
        datatype=asn1_defs.KeyIDHashAlgorithms,
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
        b'1x0*\x1a\x06sha256\x04 e\xb8\xc6\x7fQ\xc9\x93\xd8\x98%\x0f@\xaaW\xa3'
        b'\x17\xd8T\x90\x0b:\x04\x89Td1>HxT@\xda0J\x1a\x06sha512\x04@Ft0\xa6'
        b'\x8a\xfa\xe8\xe9\xf9\xc0w\x1e\xa5\xd7\x8b\xf0\xb3\xa0\xd7\x9a-=;@'
        b'\xc6\x9f\xdeM\xd4,F\x14H\xae\xf7o\xce\xf4\xf5(I1\xa1\xff\xd0\xac\tm'
        b'\x13\x8b\xa3\xa0\xd6\xca\x83\xfa\x8dr\x85\xa4z)ow')


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
        b'0\x81\x94\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5'
        b'\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X\x1a\x07'
        b'ed25519\x1a\x07ed255190L0J\x1a\x06public\x1a@82ccf6ac47298ff43bf'
        b'a0cd639868894e305a99c723ff0515ae2e9856eb5bbf40\x10\x1a\x06sha256'
        b'\x1a\x06sha512')
    rsa_key_expected_der = (
        b'0\x82\x02\xdd\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct'
        b'\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb\x1a\x03rsa\x1a\x11'
        b'rsassa-pss-sha2560\x82\x02\x8d0\x82\x02|\x1a\x06public\x1a\x82\x02'
        b'p-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBig'
        b'KCAYEA0GjPoVrjS9eCqzoQ8VRe\nPkC0cI6ktiEgqPfHESFzyxyjC490Cuy19nuxPcJ'
        b'uZfN64MC48oOkR+W2mq4pM51i\nxmdG5xjvNOBRkJ5wUCc8fDCltMUTBlqt9y5eLsf/'
        b'4/EoBU+zC4SW1iPU++mCsity\nfQQ7U6LOn3EYCyrkH51hZ/dvKC4o9TPYMVxNecJ3C'
        b'L1q02Q145JlyjBTuM3Xdqsa\nndTHoXSRPmmzgB/1dL/c4QjMnCowrKW06mFLq9RAYG'
        b'IaJWfM/0CbrOJpVDkATmEc\nMdpGJYDfW/sRQvRdlHNPo24ZW7vkQUCqdRxvnTWkK5U'
        b'81y7RtjLt1yskbWXBIbOV\nz94GXsgyzANyCT9qRjHXDDz2mkLq+9I2iKtEqaEePcWR'
        b'u3H6RLahpM/TxFzw684Y\nR47weXdDecPNxWyiWiyMGStRFP4Cg9trcwAGnEm1w8R2g'
        b'gmWphznCd5dXGhPNjfA\na82yNFY8ubnOUVJOf0nXGg3Edw9iY3xyjJb2+nrsk5f3Ag'
        b'MBAAE=\n-----END PUBLIC KEY-----0\x0b\x1a\x07private\x1a\x000\x10'
        b'\x1a\x06sha256\x1a\x06sha512')

    # Test by calling the helper functions directly.
    self.conversion_check(
      data=ed_pub,
      datatype=asn1_defs.PublicKey,
      expected_der=ed_key_expected_der,
      to_asn1_func=asn1_convert._structlike_dict_to_asn1,
      from_asn1_func=asn1_convert._structlike_dict_from_asn1)
    self.conversion_check(
      data=rsa_pub,
      datatype=asn1_defs.PublicKey,
      expected_der=rsa_key_expected_der,
      to_asn1_func=asn1_convert._structlike_dict_to_asn1,
      from_asn1_func=asn1_convert._structlike_dict_from_asn1)

    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    self.conversion_check(
        data=ed_pub,
        datatype=asn1_defs.PublicKey,
        expected_der=ed_key_expected_der
        )
    self.conversion_check(
        data=rsa_pub,
        datatype=asn1_defs.PublicKey,
        expected_der=rsa_key_expected_der
        )


  def test_signed_portion_of_root_conversion(self):
    r = {
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
        'version': 1}

    root_expected_der = (
      b'0\x82\x05\xa1\x1a\x04root\x1a\x031.0\x1a\x142030-01-01T00:00:00Z\x02\x01\x01\x01\x01\x000\x82\x04\xa30\x82\x02\xd4\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb0\x82\x02\xae\x1a\x03rsa\x1a\x11rsassa-pss-sha2560\x82\x02\x800\x82\x02|\x1a\x06public\x1a\x82\x02p-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0GjPoVrjS9eCqzoQ8VRe\nPkC0cI6ktiEgqPfHESFzyxyjC490Cuy19nuxPcJuZfN64MC48oOkR+W2mq4pM51i\nxmdG5xjvNOBRkJ5wUCc8fDCltMUTBlqt9y5eLsf/4/EoBU+zC4SW1iPU++mCsity\nfQQ7U6LOn3EYCyrkH51hZ/dvKC4o9TPYMVxNecJ3CL1q02Q145JlyjBTuM3Xdqsa\nndTHoXSRPmmzgB/1dL/c4QjMnCowrKW06mFLq9RAYGIaJWfM/0CbrOJpVDkATmEc\nMdpGJYDfW/sRQvRdlHNPo24ZW7vkQUCqdRxvnTWkK5U81y7RtjLt1yskbWXBIbOV\nz94GXsgyzANyCT9qRjHXDDz2mkLq+9I2iKtEqaEePcWRu3H6RLahpM/TxFzw684Y\nR47weXdDecPNxWyiWiyMGStRFP4Cg9trcwAGnEm1w8R2ggmWphznCd5dXGhPNjfA\na82yNFY8ubnOUVJOf0nXGg3Edw9iY3xyjJb2+nrsk5f3AgMBAAE=\n-----END PUBLIC KEY-----0\x10\x1a\x06sha256\x1a\x06sha5120\x81\x96\x04 Y\xa4\xdf\x8a\xf8\x18\xe9\xedz\xbe\x07d\xc0\xb4{B@\x95*\xa0\xd1y\xb5\xb7\x83F\xc4p\xac0\'\x8d0r\x1a\x07ed25519\x1a\x07ed255190L0J\x1a\x06public\x1a@edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd0\x10\x1a\x06sha256\x1a\x06sha5120\x81\x96\x04 e\x17\x12Q\xa9\xaf\xf5\xa8\xb3\x14:\x814\x81\xcb\x07\xf6\xe0\xdeN\xb1\x97\xc7g\x83\x7f\xe4I\x1bs\x90\x930r\x1a\x07ed25519\x1a\x07ed255190L0J\x1a\x06public\x1a@89f28bd4ede5ec3786ab923fd154f39588d20881903e69c7b08fb504c67508150\x10\x1a\x06sha256\x1a\x06sha5120\x81\x96\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X0r\x1a\x07ed25519\x1a\x07ed255190L0J\x1a\x06public\x1a@82ccf6ac47298ff43bfa0cd639868894e305a99c723ff0515ae2e9856eb5bbf40\x10\x1a\x06sha256\x1a\x06sha5120\x81\xd00/\x1a\x04root0\'0"\x04 Nw}\xe0\xd2u\xf9\xd2\x85\x88\xdd\x9a\x16\x06\xcct\x8eT\x8f\x9e"\xb6y[|\xb3\xf6?\x98\x03_\xcb\x02\x01\x0103\x1a\x08snapshot0\'0"\x04 Y\xa4\xdf\x8a\xf8\x18\xe9\xedz\xbe\x07d\xc0\xb4{B@\x95*\xa0\xd1y\xb5\xb7\x83F\xc4p\xac0\'\x8d\x02\x01\x0102\x1a\x07targets0\'0"\x04 e\x17\x12Q\xa9\xaf\xf5\xa8\xb3\x14:\x814\x81\xcb\x07\xf6\xe0\xdeN\xb1\x97\xc7g\x83\x7f\xe4I\x1bs\x90\x93\x02\x01\x0104\x1a\ttimestamp0\'0"\x04 \x8a\x1cJ:\xc2\xd5\x15\xde\xc9\x82\xba\x99\x10\xc5\xfdy\xb9\x1a\xe5\x7fb[\x9c\xff%\xd0k\xf0\xa6\x1c\x17X\x02\x01\x01')



    # Test by calling the general to_asn1 and from_asn1 calls that will call
    # the helper functions.
    self.conversion_check(
        data=r,
        datatype=asn1_defs.RootMetadata,
        expected_der=root_expected_der
        )




  '''



  def test_to_pyasn1_hashes(self):

    # Try a Hash object, of similar complexity as Signature.
    # First, produce it using the other functions, and compare it to the result
    # when produced by to_pyasn1.
    hash_type = 'sha256'
    hash_value = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'
    hash_pyasn1_alt = asn1_convert.hash_to_pyasn1(hash_type, hash_value)
    hash_der_alt = asn1_convert.pyasn1_to_der(hash_pyasn1_alt)
    hash_pyasn1_again_alt = asn1_convert.pyasn1_from_der(hash_der_alt)

    h = {'function': hash_type, 'digest': hash_value}

    h_expected_der = \
        b'0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/'

    self.conversion_check_pyasn1(
        h,
        asn1_convert.to_pyasn1,
        #from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=h_expected_der,
        second_arg=asn1_defs.Hash)


    # # Manual, without conversion_check:
    # hash_pyasn1 = asn1_convert.to_pyasn1(h, asn1_defs.Hash)
    # hash_der = asn1_convert.pyasn1_to_der(hash_pyasn1)
    # hash_pyasn1_again = asn1_convert.pyasn1_from_der(hash_der)

    # self.assertEqual(hash_pyasn1_alt, hash_pyasn1)
    # self.assertEqual(hash_der_alt, hash_der)
    # self.assertEqual(hash_pyasn1_again_alt, hash_pyasn1_again)
    # self.assertEqual(hash_pyasn1, hash_pyasn1_again)


    # Try a Hashes object, more complex yet.
    # First, produce it using the other functions, and compare it to the result
    # when produced by to_pyasn1.
    hash_type1 = 'sha256'
    hash_value1 = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'
    hash_type2 = 'sha512'
    hash_value2 = '1234567890abcdef0000000002173b903a5dff46b17b1bc3fe1e6ca0d0844f2f6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    hashes_dict = {hash_type1: hash_value1, hash_type2: hash_value2}
    expected_der = b'1x0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/0J\x1a\x06sha512\x04@\x124Vx\x90\xab\xcd\xef\x00\x00\x00\x00\x02\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/'


    # Test using the custom converter for hashes, hashes_to_pyasn1.
    hashes_asn1_alt, junk = self.conversion_check_pyasn1(
        hashes_dict,
        asn1_convert.hashes_to_pyasn1,
        #from_asn1_func=asn1_convert.hashes_from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK; func not yet written?
        expected_der=expected_der)

    # Test using the generic converter, to_pyasn1.
    hashes_asn1, junk = self.conversion_check_pyasn1(
        hashes_dict,
        asn1_convert.to_pyasn1,
        #from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=expected_der,
        second_arg=asn1_defs.Hashes)

    # Compare the two ASN.1 results (from specific and generic converters) to
    # each other.
    self.assertEqual(hashes_asn1_alt, hashes_asn1)



    # Test manually, without conversion_check

    # hashes_pyasn1_alt = asn1_convert.hashes_to_pyasn1(hashes_dict)

    # hashes_pyasn1 = asn1_convert.to_pyasn1(
    #     hashes_dict, asn1_defs.Hashes)

    # # Repeat the same conversion. This catches some odd errors that I won't
    # # explain here -- see the comments in asn1_convert.py pertaining to the
    # # line that reads:
    # #          sample_component_obj = type(datatype.componentType)()
    # hashes_pyasn1 = asn1_convert.to_pyasn1(
    #     hashes_dict, asn1_defs.Hashes)

    # # Both methods of generating Hashes objects should yield the same result.
    # self.assertEqual(hashes_pyasn1_alt, hashes_pyasn1)

    # hashes_der_alt = asn1_convert.pyasn1_to_der(hashes_pyasn1_alt)
    # hashes_der = asn1_convert.pyasn1_to_der(hashes_pyasn1)

    # self.assertEqual(expected_der, hashes_der_alt)
    # self.assertEqual(expected_der, hashes_der)





  def test_to_pyasn1_keys(self):

    # Import some public keys.
    ed_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'timestamp_key.pub')
    rsa_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'root_key.pub')

    ed_pub = repo_tool.import_ed25519_publickey_from_file(ed_pub_fname)
    rsa_pub = repo_tool.import_rsa_publickey_from_file(rsa_pub_fname)

    # Expected DER results from converting the keys:
    ed_key_expected_der = \
        b'0&\x1a\x07ed25519\x1a\x07ed255191\x000\x10\x1a\x06sha256\x1a\x06sha512'
    rsa_key_expected_der = \
        b'0,\x1a\x03rsa\x1a\x11rsassa-pss-sha2561\x000\x10\x1a\x06sha256\x1a\x06sha512'


    # Convert them and test along the way.
    self.conversion_check_pyasn1(
        ed_pub,
        asn1_convert.to_pyasn1,
        # from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=ed_key_expected_der,
        second_arg=asn1_defs.PublicKey)

    self.conversion_check_pyasn1(
        rsa_pub,
        asn1_convert.to_pyasn1,
        # from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=rsa_key_expected_der,
        second_arg=asn1_defs.PublicKey)





  def test_to_pyasn1_timestamp_hash_of_snapshot(self):
    # First, try the HashOfSnapshot piece of the Timestamp data.

    # First, let's build the JSON-compatible metadata dict.
    snapshot_fname = 'snapshot.json'
    snapshot_hash_func = 'sha256'
    snapshot_hash_digest = \
        '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    # Construct the JSON-compatible, TUF-internal piece of hash metadata, as it
    # would exist inside timestamp.json.
    hashes_of_snapshot = {
        snapshot_fname: {'hashes': {snapshot_hash_func: snapshot_hash_digest}}}


    # Next, let's manually construct the HashOfSnapshot object, to see if the
    # converter gets it right.

    # First, construct the hashes. We'll just use one in this test.

    h = asn1_defs.Hash()
    h['function'] = snapshot_hash_func
    h['digest'] = pyasn1_univ.OctetString(hexValue=snapshot_hash_digest)

    hashes = asn1_defs.Hashes()
    hashes[0] = h

    # Note: HashesContainer is a vapid layer of the ASN.1 metadata which
    # exists to map to a similarly vapid layer of the JSON-compatible metadata.
    hashes_container = asn1_defs.HashesContainer()
    hashes_container['hashes'] = hashes


    expected_pyasn1 = asn1_defs.HashOfSnapshot()
    expected_pyasn1['filename'] = snapshot_fname
    # expected_pyasn1['num-hashes'] = len(snapshot_hash[snapshot_fname]['hashes'])
    expected_pyasn1['hashes'] = hashes_container

    expected_der = asn1_convert.pyasn1_to_der(expected_pyasn1)


    hashes_of_snapshot_pyasn1, hashes_of_snapshot_der = self.conversion_check_pyasn1(
        hashes_of_snapshot,
        asn1_convert.to_pyasn1,
        # from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=expected_der,
        second_arg=asn1_defs.HashOfSnapshot)

    # In addition to testing the conversion and the expected DER, let's test
    # the expected ASN.1:
    self.assertEqual(expected_pyasn1, hashes_of_snapshot_pyasn1)





  # def test_to_pyasn1_timestamp(self):

  #   sample_timestamp = {
  #       "signatures": [
  #         {
  #           "keyid": "8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758",
  #           "sig": "7dddbfe94d6d80253433551700ea6dfe4171a33f1227a07830e951900b8325d67c3dce6410b9cf55abefa3dfca0b57814a4965c2d6ee60bb0336755cd0557e03"
  #         }
  #       ],
  #       "signed": {
  #         "_type": "timestamp",
  #         "expires": "2030-01-01T00:00:00Z",
  #         "meta": {
  #           "snapshot.json": {
  #             "hashes": {
  #               "sha256": "6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f"
  #             },
  #             "length": 554,
  #             "version": 1
  #           }
  #         },
  #         "spec_version": "1.0",
  #         "version": 1
  #       }}

  #   TimestampMetadata







  def test_hash_to_pyasn1(self):
    # This doesn't use conversion_check because the hash_to_pyasn1 function
    # takes two arguments.
    hash_type = 'sha256'
    hash_value = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    hash_pyasn1 = asn1_convert.hash_to_pyasn1(hash_type, hash_value)

    asn1_convert.pyasn1_to_der(hash_pyasn1)






  def test_hashes_to_pyasn1(self):

    hash_type1 = 'sha256'
    hash_value1 = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'
    hash_type2 = 'sha512'
    hash_value2 = '1234567890abcdef0000000002173b903a5dff46b17b1bc3fe1e6ca0d0844f2f6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    hashes_dict = {hash_type1: hash_value1, hash_type2: hash_value2}
    expected_der = b'1x0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/0J\x1a\x06sha512\x04@\x124Vx\x90\xab\xcd\xef\x00\x00\x00\x00\x02\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/'

    hashes_pyasn1, hashes_der = self.conversion_check_pyasn1(
        hashes_dict, asn1_convert.hashes_to_pyasn1, expected_der=expected_der)

    self.assertEqual(len(hashes_dict), len(hashes_pyasn1))
    self.assertEqual(hash_type1, str(hashes_pyasn1[0]['function']))
    self.assertEqual(hash_type2, str(hashes_pyasn1[1]['function']))

    # These two are probably redundant, given conversion_check call above,
    # but they do test hex_str_from_pyasn1_octets.
    self.assertEqual(hash_value1,
        asn1_convert.hex_str_from_pyasn1_octets(hashes_pyasn1[0]['digest']))
    self.assertEqual(hash_value2,
        asn1_convert.hex_str_from_pyasn1_octets(hashes_pyasn1[1]['digest']))





  def test_public_key_to_pyasn1(self):

    # Import some keys.

    ed_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'timestamp_key.pub')
    rsa_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'root_key.pub')

    ed_pub = repo_tool.import_ed25519_publickey_from_file(ed_pub_fname)
    rsa_pub = repo_tool.import_rsa_publickey_from_file(rsa_pub_fname)

    # Convert them.

    ed_pub_pyasn1 = asn1_convert.public_key_to_pyasn1(ed_pub)
    rsa_pub_pyasn1 = asn1_convert.public_key_to_pyasn1(rsa_pub)


  '''


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
