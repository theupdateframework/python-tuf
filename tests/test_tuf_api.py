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
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import logging
import tempfile
import shutil
import sys
import errno
import os
from datetime import timedelta
from dateutil.relativedelta import relativedelta

from tuf.api import metadata
from tuf.api import keys

import iso8601
import six

logger = logging.getLogger(__name__)


class TestTufApi(unittest.TestCase):
  @classmethod
  def setUpClass(cls):

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownClass() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())
    test_repo_data = os.path.join('repository_data', 'repository')
    cls.repo_dir = os.path.join(cls.temporary_directory, 'repository')
    shutil.copytree(test_repo_data, cls.repo_dir)
    test_repo_keys = os.path.join('repository_data', 'keystore')
    cls.keystore_dir = os.path.join(cls.temporary_directory, 'keystore')
    shutil.copytree(test_repo_keys, cls.keystore_dir)



  @classmethod
  def tearDownClass(cls):

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
    shutil.rmtree(cls.temporary_directory)



  def _load_key_ring(self):
    key_list = []
    root_key = keys.RAMKey.read_from_file(os.path.join(self.keystore_dir, 'root_key'),
                                          'RSA', 'password')
    key_list.append(root_key)

    for key_file in os.listdir(self.keystore_dir):
      if key_file.endswith('.pub'):
        # ignore public keys
        continue

      if key_file.startswith('root_key'):
        # root key is loaded
        continue

      key = keys.RAMKey.read_from_file(os.path.join(self.keystore_dir, key_file),
                                                    'ED25519', 'password')
      key_list.append(key)
    threshold = keys.Threshold(1, 1)
    return keys.KeyRing(threshold=threshold, keys=key_list)

  def test_metadata_base(self):
    # Use of Snapshot is arbitrary, we're just testing the base class features
    # with real data
    snapshot_path = os.path.join(self.repo_dir, 'metadata', 'snapshot.json')
    md = metadata.Snapshot.read_from_json(snapshot_path)

    self.assertEqual(md.version, 1)
    md.bump_version()
    self.assertEqual(md.version, 2)

    self.assertEqual(md.expiration,
                     iso8601.parse_date("2030-01-01").replace(tzinfo=None))
    md.bump_expiration()
    self.assertEqual(md.expiration,
                     iso8601.parse_date("2030-01-02").replace(tzinfo=None))
    md.bump_expiration(timedelta(days=365))
    self.assertEqual(md.expiration,
                     iso8601.parse_date("2031-01-02").replace(tzinfo=None))


  def test_metadata_snapshot(self):
    snapshot_path = os.path.join(self.repo_dir, 'metadata', 'snapshot.json')
    snapshot = metadata.Snapshot.read_from_json(snapshot_path)

    key_ring = self._load_key_ring()
    snapshot.keyring = key_ring
    snapshot.verify()

    # Create a dict representing what we expect the updated data to be
    fileinfo = snapshot.signed['meta']
    hashes = {'sha256': 'c2986576f5fdfd43944e2b19e775453b96748ec4fe2638a6d2f32f1310967095'}
    fileinfo['role1.json']['version'] = 2
    fileinfo['role1.json']['hashes'] = hashes
    fileinfo['role1.json']['length'] = 123

    snapshot.update('role1', 2, 123, hashes)
    self.assertEqual(snapshot.signed['meta'], fileinfo)

    # snapshot.signable()

    # snapshot.sign()

    # snapshot.verify()

    # snapshot.write_to_json(os.path.join(cls.temporary_directory, 'api_snapshot.json'))


  def test_metadata_timestamp(self):
    timestamp_path = os.path.join(self.repo_dir, 'metadata', 'timestamp.json')
    timestamp = metadata.Timestamp.read_from_json(timestamp_path)

    key_ring = self._load_key_ring()
    timestamp.keyring = key_ring
    timestamp.verify()

    self.assertEqual(timestamp.version, 1)
    timestamp.bump_version()
    self.assertEqual(timestamp.version, 2)

    self.assertEqual(timestamp.expiration,
                     iso8601.parse_date("2030-01-01").replace(tzinfo=None))
    timestamp.bump_expiration()
    self.assertEqual(timestamp.expiration,
                     iso8601.parse_date("2030-01-02").replace(tzinfo=None))
    timestamp.bump_expiration(timedelta(days=365))
    self.assertEqual(timestamp.expiration,
                     iso8601.parse_date("2031-01-02").replace(tzinfo=None))

    # Test whether dateutil.relativedelta works, this provides a much easier to
    # use interface for callers
    saved_expiration = timestamp.expiration
    delta = relativedelta(days=1)
    timestamp.bump_expiration(delta)
    self.assertEqual(timestamp.expires, "2031-01-03T00:00:00Z")
    delta = relativedelta(years=5)
    timestamp.bump_expiration(delta)
    self.assertEqual(timestamp.expires, "2036-01-03T00:00:00Z")

    hashes = {'sha256': '0ae9664468150a9aa1e7f11feecb32341658eb84292851367fea2da88e8a58dc'}
    fileinfo = timestamp.signed['meta']['snapshot.json']
    fileinfo['hashes'] = hashes
    fileinfo['version'] = 2
    fileinfo['length'] = 520
    timestamp.update(2, 520, hashes)
    self.assertEqual(timestamp.signed['meta']['snapshot.json'], fileinfo)

    # timestamp.sign()

    # timestamp.write_to_json()

def test_Threshold(self):
  # test default values
  keys.Threshold()
  # test correct arguments
  keys.Threshold(least=4, most=5)

  # test incorrect input
  self.assertRaises(ValueError, keys.Threshold, 5, 4)
  self.assertRaises(ValueError, keys.Threshold, 0, 5)
  self.assertRaises(ValueError, keys.Threshold, 5, 0)


def test_KeyRing(self):
  key_list = []
  root_key = keys.RAMKey.read_from_file(os.path.join(self.keystore_dir, 'root_key'),
                                        'RSA', 'password')
  root_key2 = keys.RAMKey.read_from_file(os.path.join(self.keystore_dir, 'root_key2'),
                                         'ED25519', 'password')
  key_list.append(root_key)
  key_list.append(root_key2)
  threshold = keys.Threshold()
  keyring = keys.KeyRing(threshold, key_list)
  self.assertEqual(keyring.threshold, threshold)
  self.assertEqual(keyring.keys, key_list)


def test_RAMKey_read_from_file(self):
  filename = os.path.join(self.keystore_dir, 'root_key')
  algorithm = 'RSA'
  passphrase = 'password'

  self.assertTrue(isinstance(keys.RAMKey.read_from_file(filename, algorithm, passphrase), keys.RAMKey))

# TODO:
# def test_RAMKey(self):

# Run unit test.
if __name__ == '__main__':
  unittest.main()
