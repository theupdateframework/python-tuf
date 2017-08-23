#!/usr/bin/env python

"""
<Program Name>
  test_sig.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 28, 2012.  Based on a previous version of this module.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for for sig.py.
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
import tuf.keydb
import tuf.roledb
import tuf.sig
import tuf.exceptions

import securesystemslib
import securesystemslib.keys

logger = logging.getLogger('tuf.test_sig')

# Setup the keys to use in our test cases.
KEYS = []
for _ in range(3):
  KEYS.append(securesystemslib.keys.generate_rsa_key(2048))



class TestSig(unittest.TestCase):
  def setUp(self):
    pass

  def tearDown(self):
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()


  def test_get_signature_status_no_role(self):
    signable = {'signed': 'test', 'signatures': []}

    # A valid, but empty signature status.
    sig_status = tuf.sig.get_signature_status(signable)
    self.assertTrue(securesystemslib.formats.SIGNATURESTATUS_SCHEMA.matches(sig_status))

    self.assertEqual(0, sig_status['threshold'])
    self.assertEqual([], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([], sig_status['unknown_sigs'])
    self.assertEqual([], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    # A valid signable, but non-existent role argument.
    self.assertRaises(tuf.exceptions.UnknownRoleError,
      tuf.sig.get_signature_status, signable, 'unknown_role')

    # Should verify we are not adding a duplicate signature
    # when doing the following action.  Here we know 'signable'
    # has only one signature so it's okay.
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    tuf.keydb.add_key(KEYS[0])

    # Improperly formatted role.
    self.assertRaises(securesystemslib.exceptions.FormatError,
      tuf.sig.get_signature_status, signable, 1)

    # Not allowed to call verify() without having specified a role.
    args = (signable, None)
    self.assertRaises(securesystemslib.exceptions.Error, tuf.sig.verify, *args)

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])


  def test_get_signature_status_bad_sig(self):
    signable = {'signed' : 'test', 'signatures' : []}

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))
    signable['signed'] += 'signature no longer matches signed data'

    tuf.keydb.add_key(KEYS[0])
    threshold = 1
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    sig_status = tuf.sig.get_signature_status(signable, 'Root')

    self.assertEqual(1, sig_status['threshold'])
    self.assertEqual([], sig_status['good_sigs'])
    self.assertEqual([KEYS[0]['keyid']], sig_status['bad_sigs'])
    self.assertEqual([], sig_status['unknown_sigs'])
    self.assertEqual([], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    self.assertFalse(tuf.sig.verify(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_unknown_signing_scheme(self):
    signable = {'signed' : 'test', 'signatures' : []}

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    valid_scheme = KEYS[0]['scheme']
    KEYS[0]['scheme'] = 'unknown_signing_scheme'
    tuf.keydb.add_key(KEYS[0])
    threshold = 1
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid']], threshold)
    tuf.roledb.add_role('root', roleinfo)

    sig_status = tuf.sig.get_signature_status(signable, 'root')

    self.assertEqual(1, sig_status['threshold'])
    self.assertEqual([], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([], sig_status['unknown_sigs'])
    self.assertEqual([], sig_status['untrusted_sigs'])
    self.assertEqual([KEYS[0]['keyid']],
                    sig_status['unknown_signing_schemes'])

    self.assertFalse(tuf.sig.verify(signable, 'root'))

    # Done.  Let's remove the added key(s) from the key database.
    KEYS[0]['scheme'] = valid_scheme
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    # Remove the role.
    tuf.roledb.remove_role('root')


  def test_get_signature_status_single_key(self):
    signable = {'signed' : 'test', 'signatures' : []}

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    threshold = 1
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid']], threshold)

    tuf.roledb.add_role('Root', roleinfo)
    tuf.keydb.add_key(KEYS[0])

    sig_status = tuf.sig.get_signature_status(signable, 'Root')

    self.assertEqual(1, sig_status['threshold'])
    self.assertEqual([KEYS[0]['keyid']], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([], sig_status['unknown_sigs'])
    self.assertEqual([], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    self.assertTrue(tuf.sig.verify(signable, 'Root'))

    # Test for an unknown signature when 'role' is left unspecified.
    sig_status = tuf.sig.get_signature_status(signable)

    self.assertEqual(0, sig_status['threshold'])
    self.assertEqual([], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([KEYS[0]['keyid']], sig_status['unknown_sigs'])
    self.assertEqual([], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_below_threshold(self):
    signable = {'signed' : 'test', 'signatures' : []}

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    tuf.keydb.add_key(KEYS[0])
    threshold = 2
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid'],
        KEYS[2]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    sig_status = tuf.sig.get_signature_status(signable, 'Root')

    self.assertEqual(2, sig_status['threshold'])
    self.assertEqual([KEYS[0]['keyid']], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([], sig_status['unknown_sigs'])
    self.assertEqual([], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    self.assertFalse(tuf.sig.verify(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])

    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_below_threshold_unrecognized_sigs(self):
    signable = {'signed' : 'test', 'signatures' : []}

    # Two keys sign it, but only one of them will be trusted.
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[2], signable['signed']))

    tuf.keydb.add_key(KEYS[0])
    tuf.keydb.add_key(KEYS[1])
    threshold = 2
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid'],
        KEYS[1]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    sig_status = tuf.sig.get_signature_status(signable, 'Root')

    self.assertEqual(2, sig_status['threshold'])
    self.assertEqual([KEYS[0]['keyid']], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([KEYS[2]['keyid']], sig_status['unknown_sigs'])
    self.assertEqual([], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    self.assertFalse(tuf.sig.verify(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    tuf.keydb.remove_key(KEYS[1]['keyid'])

    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_below_threshold_unauthorized_sigs(self):
    signable = {'signed' : 'test', 'signatures' : []}

    # Two keys sign it, but one of them is only trusted for a different
    # role.
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[1], signable['signed']))

    tuf.keydb.add_key(KEYS[0])
    tuf.keydb.add_key(KEYS[1])
    threshold = 2
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid'], KEYS[2]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[1]['keyid'], KEYS[2]['keyid']], threshold)
    tuf.roledb.add_role('Release', roleinfo)

    sig_status = tuf.sig.get_signature_status(signable, 'Root')

    self.assertEqual(2, sig_status['threshold'])
    self.assertEqual([KEYS[0]['keyid']], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([], sig_status['unknown_sigs'])
    self.assertEqual([KEYS[1]['keyid']], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    self.assertFalse(tuf.sig.verify(signable, 'Root'))

    self.assertRaises(tuf.exceptions.UnknownRoleError,
                      tuf.sig.get_signature_status, signable, 'unknown_role')

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    tuf.keydb.remove_key(KEYS[1]['keyid'])

    # Remove the roles.
    tuf.roledb.remove_role('Root')
    tuf.roledb.remove_role('Release')



  def test_check_signatures_no_role(self):
    signable = {'signed' : 'test', 'signatures' : []}

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    tuf.keydb.add_key(KEYS[0])

    # No specific role we're considering. It's invalid to use the
    # function tuf.sig.verify() without a role specified because
    # tuf.sig.verify() is checking trust, as well.
    args = (signable, None)
    self.assertRaises(securesystemslib.exceptions.Error, tuf.sig.verify, *args)

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])



  def test_verify_single_key(self):
    signable = {'signed' : 'test', 'signatures' : []}
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    tuf.keydb.add_key(KEYS[0])
    threshold = 1
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    # This will call verify() and return True if 'signable' is valid,
    # False otherwise.
    self.assertTrue(tuf.sig.verify(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])

    # Remove the roles.
    tuf.roledb.remove_role('Root')


  def test_verify_unrecognized_sig(self):
    signable = {'signed' : 'test', 'signatures' : []}

    # Two keys sign it, but only one of them will be trusted.
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))
    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[2], signable['signed']))

    tuf.keydb.add_key(KEYS[0])
    tuf.keydb.add_key(KEYS[1])
    threshold = 2
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid'], KEYS[1]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    self.assertFalse(tuf.sig.verify(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    tuf.keydb.remove_key(KEYS[1]['keyid'])

    # Remove the roles.
    tuf.roledb.remove_role('Root')



  def test_generate_rsa_signature(self):
    signable = {'signed' : 'test', 'signatures' : []}

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    self.assertEqual(1, len(signable['signatures']))
    signature = signable['signatures'][0]
    self.assertEqual(KEYS[0]['keyid'], signature['keyid'])

    returned_signature = tuf.sig.generate_rsa_signature(signable['signed'], KEYS[0])
    self.assertTrue(securesystemslib.formats.SIGNATURE_SCHEMA.matches(returned_signature))

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[1], signable['signed']))

    self.assertEqual(2, len(signable['signatures']))
    signature = signable['signatures'][1]
    self.assertEqual(KEYS[1]['keyid'], signature['keyid'])



  def test_may_need_new_keys(self):
    # One untrusted key in 'signable'.
    signable = {'signed' : 'test', 'signatures' : []}

    signable['signatures'].append(securesystemslib.keys.create_signature(
                                  KEYS[0], signable['signed']))

    tuf.keydb.add_key(KEYS[1])
    threshold = 1
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[1]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    sig_status = tuf.sig.get_signature_status(signable, 'Root')

    self.assertTrue(tuf.sig.may_need_new_keys(sig_status))


    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[1]['keyid'])

    # Remove the roles.
    tuf.roledb.remove_role('Root')


  def test_signable_has_invalid_format(self):
    # get_signature_status() and verify() validate 'signable' before continuing.
    # 'signable' must be of the form: {'signed': , 'signatures': [{}]}.
    # Object types are checked as well.
    signable = {'not_signed' : 'test', 'signatures' : []}
    args = (signable['not_signed'], KEYS[0])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.sig.get_signature_status, *args)

    # 'signatures' value must be a list.  Let's try a dict.
    signable = {'signed' : 'test', 'signatures' : {}}
    args = (signable['signed'], KEYS[0])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.sig.get_signature_status, *args)



# Run unit test.
if __name__ == '__main__':
  unittest.main()
