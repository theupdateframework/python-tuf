#!/usr/bin/env python

# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_tuf_api.py

<Author>
  Joshua Lock <jlock@vmware.com>

<Started>
  June 30, 2020.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit tests for tuf.api
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import os
import shutil
import tempfile
import unittest

from datetime import timedelta
from dateutil.relativedelta import relativedelta

from tuf.api.metadata import (
  Snapshot,
  Timestamp,
)
from tuf.api.keys import (
  KeyRing,
  RAMKey,
  Threshold,
  VaultKey,
)

logger = logging.getLogger(__name__)


class TestTufApi(unittest.TestCase):
  # TODO: Start Vault in a dev mode, and export VAULT_ADDR as well as VAULT_TOKEN.
  # TODO: Enable the Vault Transit secrets engine.
  @classmethod
  def setUpClass(cls):

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownClass() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    test_repo_data = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), 'repository_data')

    cls.repo_dir = os.path.join(cls.temporary_directory, 'repository')
    shutil.copytree(os.path.join(test_repo_data, 'repository'), cls.repo_dir)

    cls.keystore_dir = os.path.join(cls.temporary_directory, 'keystore')
    shutil.copytree(os.path.join(test_repo_data, 'keystore'), cls.keystore_dir)


  # TODO: Shut down Vault.
  @classmethod
  def tearDownClass(cls):

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
    shutil.rmtree(cls.temporary_directory)



  def _load_key_ring(self):
    key_list = []
    root_key = RAMKey.read_from_file(os.path.join(self.keystore_dir, 'root_key'),
                                     'rsassa-pss-sha256', 'password')
    key_list.append(root_key)

    for key_file in os.listdir(self.keystore_dir):
      if key_file.endswith('.pub'):
        # ignore public keys
        continue

      if key_file.startswith('root_key'):
        # root key is loaded
        continue

      key = RAMKey.read_from_file(os.path.join(self.keystore_dir, key_file),
                                  'ed25519', 'password')
      key_list.append(key)
    threshold = Threshold(1, 5)
    return KeyRing(threshold=threshold, keys=key_list)

  def test_metadata_base(self):
    # Use of Snapshot is arbitrary, we're just testing the base class features
    # with real data
    snapshot_path = os.path.join(self.repo_dir, 'metadata', 'snapshot.json')
    md = Snapshot.read_from_json(snapshot_path)

    self.assertEqual(md.signed.version, 1)
    md.signed.bump_version()
    self.assertEqual(md.signed.version, 2)
    self.assertEqual(md.signed.expires, '2030-01-01T00:00:00Z')
    md.signed.bump_expiration()
    self.assertEqual(md.signed.expires, '2030-01-02T00:00:00Z')
    md.signed.bump_expiration(timedelta(days=365))
    self.assertEqual(md.signed.expires, '2031-01-02T00:00:00Z')


  def test_metadata_snapshot(self):
    snapshot_path = os.path.join(self.repo_dir, 'metadata', 'snapshot.json')
    snapshot = Snapshot.read_from_json(snapshot_path)

    key_ring = self._load_key_ring()
    snapshot.verify(key_ring)

    # Create a dict representing what we expect the updated data to be
    fileinfo = snapshot.signed.meta
    hashes = {'sha256': 'c2986576f5fdfd43944e2b19e775453b96748ec4fe2638a6d2f32f1310967095'}
    fileinfo['role1.json']['version'] = 2
    fileinfo['role1.json']['hashes'] = hashes
    fileinfo['role1.json']['length'] = 123

    snapshot.signed.update('role1', 2, 123, hashes)
    self.assertEqual(snapshot.signed.meta, fileinfo)

    # snapshot.signable()

    # snapshot.sign()

    # snapshot.verify()

    # snapshot.write_to_json(os.path.join(cls.temporary_directory, 'api_snapshot.json'))


  def test_metadata_timestamp(self):
    timestamp_path = os.path.join(self.repo_dir, 'metadata', 'timestamp.json')
    timestamp = Timestamp.read_from_json(timestamp_path)

    key_ring = self._load_key_ring()
    timestamp.verify(key_ring)

    self.assertEqual(timestamp.signed.version, 1)
    timestamp.signed.bump_version()
    self.assertEqual(timestamp.signed.version, 2)

    self.assertEqual(timestamp.signed.expires, '2030-01-01T00:00:00Z')
    timestamp.signed.bump_expiration()
    self.assertEqual(timestamp.signed.expires, '2030-01-02T00:00:00Z')
    timestamp.signed.bump_expiration(timedelta(days=365))
    self.assertEqual(timestamp.signed.expires, '2031-01-02T00:00:00Z')

    # Test whether dateutil.relativedelta works, this provides a much easier to
    # use interface for callers
    delta = relativedelta(days=1)
    timestamp.signed.bump_expiration(delta)
    self.assertEqual(timestamp.signed.expires, '2031-01-03T00:00:00Z')
    delta = relativedelta(years=5)
    timestamp.signed.bump_expiration(delta)
    self.assertEqual(timestamp.signed.expires, '2036-01-03T00:00:00Z')

    hashes = {'sha256': '0ae9664468150a9aa1e7f11feecb32341658eb84292851367fea2da88e8a58dc'}
    fileinfo = timestamp.signed.meta['snapshot.json']
    fileinfo['hashes'] = hashes
    fileinfo['version'] = 2
    fileinfo['length'] = 520
    timestamp.signed.update(2, 520, hashes)
    self.assertEqual(timestamp.signed.meta['snapshot.json'], fileinfo)

    # timestamp.sign()

    # timestamp.write_to_json()

  def test_Threshold(self):
    # test default values
    Threshold()
    # test correct arguments
    Threshold(least=4, most=5)

    # test incorrect input
    self.assertRaises(ValueError, Threshold, 5, 4)
    self.assertRaises(ValueError, Threshold, 0, 5)
    self.assertRaises(ValueError, Threshold, 5, 0)


  def test_KeyRing(self):
    key_list = []
    root_key = RAMKey.read_from_file(os.path.join(self.keystore_dir, 'root_key'),
                                     'rsassa-pss-sha256', 'password')
    root_key2 = RAMKey.read_from_file(os.path.join(self.keystore_dir, 'root_key2'),
                                      'ed25519', 'password')
    key_list.append(root_key)
    key_list.append(root_key2)
    threshold = Threshold(1, 2)
    keyring = KeyRing(threshold, key_list)
    self.assertEqual(keyring.threshold, threshold)
    self.assertEqual(keyring.keys, key_list)


  def test_VaultKey_Ed25519(self):
    VAULT_ADDR = os.environ['VAULT_ADDR']
    VAULT_TOKEN = os.environ['VAULT_TOKEN']
    KEY_TYPE = VaultKey.KeyTypes.ED25519.value
    NAME = f'test-{KEY_TYPE}-key'

    for hash_algorithm in {h.value for h in VaultKey.HashAlgorithms}:
      self.assertRaises(
        ValueError,
        VaultKey.create_key,
        VAULT_ADDR,
        VAULT_TOKEN,
        NAME,
        KEY_TYPE,
        hash_algorithm=hash_algorithm,
      )

    for marshaling_algorithm in {m.value for m in VaultKey.MarshalingAlgorithms}:
      self.assertRaises(
        ValueError,
        VaultKey.create_key,
        VAULT_ADDR,
        VAULT_TOKEN,
        NAME,
        KEY_TYPE,
        marshaling_algorithm=marshaling_algorithm,
      )

    for signature_algorithm in {s.value for s in VaultKey.SignatureAlgorithms}:
      self.assertRaises(
        ValueError,
        VaultKey.create_key,
        VAULT_ADDR,
        VAULT_TOKEN,
        NAME,
        KEY_TYPE,
        signature_algorithm=signature_algorithm,
      )

    key = VaultKey.create_key(VAULT_ADDR, VAULT_TOKEN, NAME, KEY_TYPE)
    signed = f'Hello, {KEY_TYPE}!'
    signature = key.sign(signed)
    self.assertTrue(key.verify(signed, signature))


  def test_VaultKey_ECDSA(self):
    VAULT_ADDR = os.environ['VAULT_ADDR']
    VAULT_TOKEN = os.environ['VAULT_TOKEN']

    def test(key_type, hash_algorithm, hash_algorithms):
      NAME = f'test-{key_type}-key'

      for marshaling_algorithm in {m.value for m in VaultKey.MarshalingAlgorithms}:
        key = VaultKey.create_key(
          VAULT_ADDR,
          VAULT_TOKEN,
          NAME,
          key_type,
          hash_algorithm=hash_algorithm,
          marshaling_algorithm=marshaling_algorithm,
        )
        signed = f'Hello, {key_type}!'
        signature = key.sign(signed)
        self.assertTrue(key.verify(signed, signature))

      for hash_algorithm in hash_algorithms:
        self.assertRaises(
          ValueError,
          VaultKey.create_key,
          VAULT_ADDR,
          VAULT_TOKEN,
          NAME,
          key_type,
          hash_algorithm=hash_algorithm
        )

      for signature_algorithm in {s.value for s in VaultKey.SignatureAlgorithms}:
        self.assertRaises(
          ValueError,
          VaultKey.create_key,
          VAULT_ADDR,
          VAULT_TOKEN,
          NAME,
          key_type,
          signature_algorithm=signature_algorithm
        )

    test(
      VaultKey.KeyTypes.P_256.value,
      VaultKey.HashAlgorithms.SHA2_256.value,
      {
        VaultKey.HashAlgorithms.SHA2_224.value,
        VaultKey.HashAlgorithms.SHA2_384.value,
        VaultKey.HashAlgorithms.SHA2_512.value
      }
    )

    # FIXME: Unfortunately, py-TUF does not yet support P-384.
    # https://github.com/hvac/hvac/pull/606
    # test(
    #   VaultKey.KeyTypes.P_384.value,
    #   VaultKey.HashAlgorithms.SHA2_384.value,
    #   {
    #     VaultKey.HashAlgorithms.SHA2_224.value,
    #     VaultKey.HashAlgorithms.SHA2_256.value,
    #     VaultKey.HashAlgorithms.SHA2_512.value
    #   }
    # )

    # FIXME: Unfortunately, py-TUF does not yet support P-521.
    # https://github.com/hvac/hvac/pull/608
    # test(
    #   VaultKey.KeyTypes.P_521.value,
    #   VaultKey.HashAlgorithms.SHA2_512.value,
    #   {
    #     VaultKey.HashAlgorithms.SHA2_224.value,
    #     VaultKey.HashAlgorithms.SHA2_256.value,
    #     VaultKey.HashAlgorithms.SHA2_384.value
    #   }
    # )


  def test_VaultKey_RSA(self):
    VAULT_ADDR = os.environ['VAULT_ADDR']
    VAULT_TOKEN = os.environ['VAULT_TOKEN']

    for key_type in {
      VaultKey.KeyTypes.RSA_2048.value,
      # https://github.com/hvac/hvac/issues/605
      VaultKey.KeyTypes.RSA_3072.value,
      VaultKey.KeyTypes.RSA_4096.value
    }:
      NAME = f'test-{key_type}-key'

      for signature_algorithm in {s.value for s in VaultKey.SignatureAlgorithms}:
        for hash_algorithm in {h.value for h in VaultKey.HashAlgorithms}:
          for marshaling_algorithm in {m.value for m in VaultKey.MarshalingAlgorithms}:
            self.assertRaises(
              ValueError,
              VaultKey.create_key,
              VAULT_ADDR,
              VAULT_TOKEN,
              NAME,
              key_type,
              marshaling_algorithm=marshaling_algorithm,
            )

          key = VaultKey.create_key(
            VAULT_ADDR,
            VAULT_TOKEN,
            NAME,
            key_type,
            hash_algorithm=hash_algorithm,
            signature_algorithm=signature_algorithm,
          )
          signed = f'Hello, {key_type}!'
          signature = key.sign(signed)
          self.assertTrue(key.verify(signed, signature))


# Run unit test.
if __name__ == '__main__':
  unittest.main()
