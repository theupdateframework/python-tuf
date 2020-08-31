#!/usr/bin/env python

# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
""" Unit tests for api/metadata.py

"""

import json
import sys
import logging
import os
import shutil
import tempfile
import unittest

from datetime import timedelta
from dateutil.relativedelta import relativedelta

# TODO: Remove case handling when fully dropping support for versions >= 3.6
IS_PY_VERSION_SUPPORTED = sys.version_info >= (3, 6)

# Use setUpModule to tell unittest runner to skip this test module gracefully.
def setUpModule():
    if not IS_PY_VERSION_SUPPORTED:
        raise unittest.SkipTest("requires Python 3.6 or higher")

# Since setUpModule is called after imports we need to import conditionally.
if IS_PY_VERSION_SUPPORTED:
    from tuf.api.metadata import (
        Metadata,
        Snapshot,
        Timestamp,
        Targets
    )


logger = logging.getLogger(__name__)


class TestMetadata(unittest.TestCase):
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
        shutil.copytree(
                os.path.join(test_repo_data, 'repository'), cls.repo_dir)

        cls.keystore_dir = os.path.join(cls.temporary_directory, 'keystore')
        shutil.copytree(
                os.path.join(test_repo_data, 'keystore'), cls.keystore_dir)

        # Load keys into memory
        cls.keystore = {}
        for role in ['delegation', 'snapshot', 'targets', 'timestamp']:
            cls.keystore[role] = {
                'private': import_ed25519_privatekey_from_file(
                        os.path.join(cls.keystore_dir, role + '_key'),
                        password="password"),
                'public': import_ed25519_publickey_from_file(
                        os.path.join(cls.keystore_dir, role + '_key.pub'))
            }


    # TODO: Shut down Vault.
    @classmethod
    def tearDownClass(cls):

        # Remove the temporary repository directory, which should contain all the
        # metadata, targets, and key files generated for the test cases.
        shutil.rmtree(cls.temporary_directory)



    # def _load_key_ring(self):
    #     key_list = []
    #     root_key = RAMKey.read_from_file(os.path.join(self.keystore_dir, 'root_key'),
    #                                    'rsassa-pss-sha256', 'password')
    #     key_list.append(root_key)

    #     for key_file in os.listdir(self.keystore_dir):
    #         if key_file.endswith('.pub'):
    #             # ignore public keys
    #             continue

    #         if key_file.startswith('root_key'):
    #             # root key is loaded
    #         continue

    #         key = RAMKey.read_from_file(os.path.join(self.keystore_dir, key_file),
    #                                 'ed25519', 'password')
    #         key_list.append(key)

    #     threshold = Threshold(1, 5)
    #     return KeyRing(threshold=threshold, keys=key_list)

    def test_generic_read(self):
        for metadata, inner_metadata_cls in [
                ("snapshot", Snapshot),
                ("timestamp", Timestamp),
                ("targets", Targets)]:

            path = os.path.join(self.repo_dir, 'metadata', metadata + '.json')
            metadata_obj = Metadata.read_from_json(path)

            # Assert that generic method ...
            # ... instantiates the right inner class for each metadata type
            self.assertTrue(
                    isinstance(metadata_obj.signed, inner_metadata_cls))
            # ... and reads the same metadata file as the corresponding method
            # on the inner class would do (compare their dict representation)
            self.assertDictEqual(
                    metadata_obj.as_dict(),
                    inner_metadata_cls.read_from_json(path).as_dict())

        # Assert that it chokes correctly on an unknown metadata type
        bad_metadata_path = 'bad-metadata.json'
        bad_metadata = {'signed': {'_type': 'bad-metadata'}}
        with open(bad_metadata_path, 'wb') as f:
            f.write(json.dumps(bad_metadata).encode('utf-8'))

        with self.assertRaises(ValueError):
            Metadata.read_from_json(bad_metadata_path)

        os.remove(bad_metadata_path)

    def test_compact_json(self):
        path = os.path.join(self.repo_dir, 'metadata', 'targets.json')
        metadata_obj = Metadata.read_from_json(path)
        self.assertTrue(
                len(metadata_obj.as_json(compact=True)) <
                len(metadata_obj.as_json()))


    def test_read_write_read_compare(self):
        for metadata in ["snapshot", "timestamp", "targets"]:
            path = os.path.join(self.repo_dir, 'metadata', metadata + '.json')
            metadata_obj = Metadata.read_from_json(path)

            path_2 = path + '.tmp'
            metadata_obj.write_to_json(path_2)
            metadata_obj_2 = Metadata.read_from_json(path_2)

            self.assertDictEqual(
                    metadata_obj.as_dict(),
                    metadata_obj_2.as_dict())

            os.remove(path_2)


    def test_sign_verify(self):
        # Load sample metadata (targets) and assert ...
        path = os.path.join(self.repo_dir, 'metadata', 'targets.json')
        metadata_obj = Metadata.read_from_json(path)

        # ... it has a single existing signature,
        self.assertTrue(len(metadata_obj.signatures) == 1)
        # ... valid for the correct key, but
        self.assertTrue(metadata_obj.verify(
                self.keystore['targets']['public']))
        # ... invalid for an unrelated key.
        self.assertFalse(metadata_obj.verify(
                self.keystore['snapshot']['public']))

        # Append a new signature with the unrelated key and assert that ...
        metadata_obj.sign(self.keystore['snapshot']['private'], append=True)
        # ... there are now two signatures, and
        self.assertTrue(len(metadata_obj.signatures) == 2)
        # ... both are valid for the corresponding keys.
        self.assertTrue(metadata_obj.verify(
                self.keystore['targets']['public']))
        self.assertTrue(metadata_obj.verify(
                self.keystore['snapshot']['public']))

        # Create and assign (don't append) a new signature and assert that ...
        metadata_obj.sign(self.keystore['timestamp']['private'], append=False)
        # ... there now is only one signature,
        self.assertTrue(len(metadata_obj.signatures) == 1)
        # ... valid for that key.
        self.assertTrue(metadata_obj.verify(
                self.keystore['timestamp']['public']))


        # Update the metadata, invalidating the existing signature, append
        # a new signature with the same key, and assert that ...
        metadata_obj.signed.bump_version()
        metadata_obj.sign(self.keystore['timestamp']['private'], append=True)
        # ... verify returns False, because all signatures identified by a
        # keyid must be valid
        self.assertFalse(metadata_obj.verify(
                self.keystore['timestamp']['public']))


    def test_metadata_base(self):
        # Use of Snapshot is arbitrary, we're just testing the base class features
        # with real data
        snapshot_path = os.path.join(
                self.repo_dir, 'metadata', 'snapshot.json')
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
        snapshot_path = os.path.join(
                self.repo_dir, 'metadata', 'snapshot.json')
        snapshot = Snapshot.read_from_json(snapshot_path)

        # key_ring = self._load_key_ring()
        # snapshot.verify(key_ring)

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
        timestamp_path = os.path.join(
                self.repo_dir, 'metadata', 'timestamp.json')
        timestamp = Timestamp.read_from_json(timestamp_path)

        # key_ring = self._load_key_ring()
        # timestamp.verify(key_ring)

        self.assertEqual(timestamp.signed.version, 1)
        timestamp.signed.bump_version()
        self.assertEqual(timestamp.signed.version, 2)

        self.assertEqual(timestamp.signed.expires, '2030-01-01T00:00:00Z')
        timestamp.signed.bump_expiration()
        self.assertEqual(timestamp.signed.expires, '2030-01-02T00:00:00Z')
        timestamp.signed.bump_expiration(timedelta(days=365))
        self.assertEqual(timestamp.signed.expires, '2031-01-02T00:00:00Z')

        # Test whether dateutil.relativedelta works, this provides a much
        # easier to use interface for callers
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


# Run unit test.
if __name__ == '__main__':
    unittest.main()
