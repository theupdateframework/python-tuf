#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_sig.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 28, 2012.  Based on a previous version of this module.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

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
import copy

import tuf
import tuf.log
import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.sig
import tuf.exceptions
import tuf.encoding.util

import securesystemslib
import securesystemslib.keys

logger = logging.getLogger('tuf.test_sig')

# Setup the keys to use in our test cases.
KEYS = []
for _ in range(3):
  KEYS.append(securesystemslib.keys.generate_rsa_key(2048))


tuf.DEBUG = False # TODO: <~> REMOVE THIS!  This was for a particular test.

# An example of a piece of signable metadata that has no signatures yet.
SIGNABLE_TIMESTAMP = {
    "signatures": [
      # a valid signature, for reference:
      # {"keyid": "8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758", "sig": "7dddbfe94d6d80253433551700ea6dfe4171a33f1227a07830e951900b8325d67c3dce6410b9cf55abefa3dfca0b57814a4965c2d6ee60bb0336755cd0557e03"}
    ],
    "signed": {
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


class TestSig(unittest.TestCase):
  def setUp(self):
    pass

  def tearDown(self):
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()


  def test_get_signature_status_no_role(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    # A valid, but empty signature status.
    signable['signatures'] = []
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
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))

    tuf.keydb.add_key(KEYS[0])

    # Improperly formatted role.
    self.assertRaises(securesystemslib.exceptions.FormatError,
      tuf.sig.get_signature_status, signable, 1)

    # Not allowed to call verify_signable() without having specified a role.
    with self.assertRaises(securesystemslib.exceptions.Error):
      tuf.sig.verify_signable(signable, None)

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])


  def test_get_signature_status_bad_sig(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))

    # Alter the metadata so that the signature over it is no longer correct.
    signable['signed']['version'] += 1

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

    self.assertFalse(tuf.sig.verify_signable(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_unknown_signing_scheme(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))

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

    self.assertFalse(tuf.sig.verify_signable(signable, 'root'))

    # Done.  Let's remove the added key(s) from the key database.
    KEYS[0]['scheme'] = valid_scheme
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    # Remove the role.
    tuf.roledb.remove_role('root')


  def test_get_signature_status_single_key(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))

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

    self.assertTrue(tuf.sig.verify_signable(signable, 'Root'))

    # <~> (remove this comment and add to commit summary)
    # The old behavior was wrong, I think.  The key is known -----
    # If get_signature_status is not provided authorized keyids and threshold,
    # and is also not provided a role to use to determine what keyids and
    # threshold are authorized, then we expect any good signature to come back
    # as untrustworthy, and any bad signature to come back as a bad signature.
    # tuf.DEBUG = True # TODO: <~> Remove this.
    sig_status = tuf.sig.get_signature_status(signable)
    # tuf.DEBUG = False

    self.assertEqual(0, sig_status['threshold'])
    self.assertEqual([], sig_status['good_sigs'])
    self.assertEqual([], sig_status['bad_sigs'])
    self.assertEqual([], sig_status['unknown_sigs'])
    self.assertEqual([KEYS[0]['keyid']], sig_status['untrusted_sigs'])
    self.assertEqual([], sig_status['unknown_signing_schemes'])

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_below_threshold(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))

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

    self.assertFalse(tuf.sig.verify_signable(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])

    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_below_threshold_unrecognized_sigs(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    # Two keys sign it, but only one of them will be trusted.
    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))
    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[2], tuf.encoding.util.serialize(signable['signed'])))

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

    self.assertFalse(tuf.sig.verify_signable(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    tuf.keydb.remove_key(KEYS[1]['keyid'])

    # Remove the role.
    tuf.roledb.remove_role('Root')


  def test_get_signature_status_below_threshold_unauthorized_sigs(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    # Two keys sign it, but one of them is only trusted for a different
    # role.
    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))
    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[1], tuf.encoding.util.serialize(signable['signed'])))

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

    self.assertFalse(tuf.sig.verify_signable(signable, 'Root'))

    self.assertRaises(tuf.exceptions.UnknownRoleError,
                      tuf.sig.get_signature_status, signable, 'unknown_role')

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    tuf.keydb.remove_key(KEYS[1]['keyid'])

    # Remove the roles.
    tuf.roledb.remove_role('Root')
    tuf.roledb.remove_role('Release')



  def test_check_signatures_no_role(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))

    tuf.keydb.add_key(KEYS[0])

    # No specific role we're considering. It's invalid to use the
    # function tuf.sig.verify_signable() without a role specified because
    # tuf.sig.verify_signable() is checking trust, as well.
    with self.assertRaises(securesystemslib.exceptions.Error):
      tuf.sig.verify_signable(signable, None)

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])



  def test_verify_single_key(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)
    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))

    tuf.keydb.add_key(KEYS[0])
    threshold = 1
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    # This will call verify_signable() and return True if 'signable' is valid,
    # False otherwise.
    self.assertTrue(tuf.sig.verify_signable(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])

    # Remove the roles.
    tuf.roledb.remove_role('Root')


  def test_verify_unrecognized_sig(self):
    signable = copy.deepcopy(SIGNABLE_TIMESTAMP)

    # Two keys sign it, but only one of them will be trusted.
    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[0], tuf.encoding.util.serialize(signable['signed'])))
    signable['signatures'].append(securesystemslib.keys.create_signature(
        KEYS[2], tuf.encoding.util.serialize(signable['signed'])))

    tuf.keydb.add_key(KEYS[0])
    tuf.keydb.add_key(KEYS[1])
    threshold = 2
    roleinfo = tuf.formats.make_role_metadata(
        [KEYS[0]['keyid'], KEYS[1]['keyid']], threshold)
    tuf.roledb.add_role('Root', roleinfo)

    self.assertFalse(tuf.sig.verify_signable(signable, 'Root'))

    # Done.  Let's remove the added key(s) from the key database.
    tuf.keydb.remove_key(KEYS[0]['keyid'])
    tuf.keydb.remove_key(KEYS[1]['keyid'])

    # Remove the roles.
    tuf.roledb.remove_role('Root')





  def test_signable_has_invalid_format(self):
    # get_signature_status() and verify_signable() verify 'signable' before
    # continuing.
    # 'signable' must be of the form: {'signed': , 'signatures': [{}]}.
    # Object types are checked as well.
    signable = {'not_signed' : {'test'}, 'signatures' : []}
    args = (signable['not_signed'], KEYS[0])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.sig.get_signature_status, *args)

    # 'signatures' value must be a list.  Let's try a dict.
    signable = {'signed' : {'type': 'some_role'}, 'signatures' : {}}
    args = (signable['signed'], KEYS[0])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.sig.get_signature_status, *args)



# Run unit test.
if __name__ == '__main__':
  unittest.main()
