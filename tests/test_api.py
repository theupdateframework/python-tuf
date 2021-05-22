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
import copy

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

from tests import utils

import tuf.exceptions
from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    Timestamp,
    Targets,
    Key,
    Role,
    MetaFile,
    TargetFile,
    Delegations,
    DelegatedRole,
)

from tuf.api.serialization import (
    DeserializationError
)

from tuf.api.serialization.json import (
    JSONSerializer,
    JSONDeserializer,
    CanonicalJSONSerializer
)

from securesystemslib.interface import (
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file
)

from securesystemslib.signer import (
    SSlibSigner
)

logger = logging.getLogger(__name__)


class TestMetadata(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a temporary directory to store the repository, metadata, and
        # target files.  'temporary_directory' must be deleted in
        # TearDownClass() so that temporary files are always removed, even when
        # exceptions occur.
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


    @classmethod
    def tearDownClass(cls):
        # Remove the temporary repository directory, which should contain all
        # the metadata, targets, and key files generated for the test cases.
        shutil.rmtree(cls.temporary_directory)


    def test_generic_read(self):
        for metadata, inner_metadata_cls in [
                ('root', Root),
                ('snapshot', Snapshot),
                ('timestamp', Timestamp),
                ('targets', Targets)]:

            # Load JSON-formatted metdata of each supported type from file
            # and from out-of-band read JSON string
            path = os.path.join(self.repo_dir, 'metadata', metadata + '.json')
            metadata_obj = Metadata.from_file(path)
            with open(path, 'rb') as f:
                metadata_obj2 = Metadata.from_bytes(f.read())

            # Assert that both methods instantiate the right inner class for
            # each metadata type and ...
            self.assertTrue(
                    isinstance(metadata_obj.signed, inner_metadata_cls))
            self.assertTrue(
                    isinstance(metadata_obj2.signed, inner_metadata_cls))

            # ... and return the same object (compared by dict representation)
            self.assertDictEqual(
                    metadata_obj.to_dict(), metadata_obj2.to_dict())

        # Assert that it chokes correctly on an unknown metadata type
        bad_metadata_path = 'bad-metadata.json'
        bad_metadata = {'signed': {'_type': 'bad-metadata'}}
        bad_string = json.dumps(bad_metadata).encode('utf-8')
        with open(bad_metadata_path, 'wb') as f:
            f.write(bad_string)

        with self.assertRaises(DeserializationError):
            Metadata.from_file(bad_metadata_path)
        with self.assertRaises(DeserializationError):
            Metadata.from_bytes(bad_string)

        os.remove(bad_metadata_path)


    def test_compact_json(self):
        path = os.path.join(self.repo_dir, 'metadata', 'targets.json')
        metadata_obj = Metadata.from_file(path)
        self.assertTrue(
                len(JSONSerializer(compact=True).serialize(metadata_obj)) <
                len(JSONSerializer().serialize(metadata_obj)))


    def test_read_write_read_compare(self):
        for metadata in ['root', 'snapshot', 'timestamp', 'targets']:
            path = os.path.join(self.repo_dir, 'metadata', metadata + '.json')
            metadata_obj = Metadata.from_file(path)

            path_2 = path + '.tmp'
            metadata_obj.to_file(path_2)
            metadata_obj_2 = Metadata.from_file(path_2)

            self.assertDictEqual(
                    metadata_obj.to_dict(),
                    metadata_obj_2.to_dict())

            os.remove(path_2)


    def test_sign_verify(self):
        # Load sample metadata (targets) and assert ...
        path = os.path.join(self.repo_dir, 'metadata', 'targets.json')
        metadata_obj = Metadata.from_file(path)

        # ... it has a single existing signature,
        self.assertTrue(len(metadata_obj.signatures) == 1)
        # ... which is valid for the correct key.
        self.assertTrue(metadata_obj.verify(
                self.keystore['targets']['public']))

        sslib_signer = SSlibSigner(self.keystore['snapshot']['private'])
        # Append a new signature with the unrelated key and assert that ...
        metadata_obj.sign(sslib_signer, append=True)
        # ... there are now two signatures, and
        self.assertTrue(len(metadata_obj.signatures) == 2)
        # ... both are valid for the corresponding keys.
        self.assertTrue(metadata_obj.verify(
                self.keystore['targets']['public']))
        self.assertTrue(metadata_obj.verify(
                self.keystore['snapshot']['public']))

        sslib_signer.key_dict = self.keystore['timestamp']['private']
        # Create and assign (don't append) a new signature and assert that ...
        metadata_obj.sign(sslib_signer, append=False)
        # ... there now is only one signature,
        self.assertTrue(len(metadata_obj.signatures) == 1)
        # ... valid for that key.
        self.assertTrue(metadata_obj.verify(
                self.keystore['timestamp']['public']))

        # Assert exception if there are more than one signatures for a key
        metadata_obj.sign(sslib_signer, append=True)
        with self.assertRaises(tuf.exceptions.Error) as ctx:
            metadata_obj.verify(self.keystore['timestamp']['public'])
        self.assertTrue(
                '2 signatures for key' in str(ctx.exception),
                str(ctx.exception))

        # Assert exception if there is no signature for a key
        with self.assertRaises(tuf.exceptions.Error) as ctx:
            metadata_obj.verify(self.keystore['targets']['public'])
        self.assertTrue(
                'no signature for' in str(ctx.exception),
                str(ctx.exception))


    def test_metadata_base(self):
        # Use of Snapshot is arbitrary, we're just testing the base class features
        # with real data
        snapshot_path = os.path.join(
                self.repo_dir, 'metadata', 'snapshot.json')
        md = Metadata.from_file(snapshot_path)

        self.assertEqual(md.signed.version, 1)
        md.signed.bump_version()
        self.assertEqual(md.signed.version, 2)
        self.assertEqual(md.signed.expires, datetime(2030, 1, 1, 0, 0))
        md.signed.bump_expiration()
        self.assertEqual(md.signed.expires, datetime(2030, 1, 2, 0, 0))
        md.signed.bump_expiration(timedelta(days=365))
        self.assertEqual(md.signed.expires, datetime(2031, 1, 2, 0, 0))

        # Test is_expired with reference_time provided
        is_expired = md.signed.is_expired(md.signed.expires)
        self.assertTrue(is_expired)
        is_expired = md.signed.is_expired(md.signed.expires + timedelta(days=1))
        self.assertTrue(is_expired)
        is_expired = md.signed.is_expired(md.signed.expires - timedelta(days=1))
        self.assertFalse(is_expired)

        # Test is_expired without reference_time,
        # manipulating md.signed.expires
        expires = md.signed.expires
        md.signed.expires = datetime.utcnow()
        is_expired = md.signed.is_expired()
        self.assertTrue(is_expired)
        md.signed.expires = datetime.utcnow() + timedelta(days=1)
        is_expired = md.signed.is_expired()
        self.assertFalse(is_expired)
        md.signed.expires = expires


    def test_metafile_class(self):
        # Test from_dict and to_dict with all attributes.
        data = {
            "hashes": {
                "sha256": "8f88e2ba48b412c3843e9bb26e1b6f8fc9e98aceb0fbaa97ba37b4c98717d7ab"
            },
            "length": 515,
            "version": 1
        }
        metafile_obj = MetaFile.from_dict(copy.copy(data))
        self.assertEqual(metafile_obj.to_dict(), data)

        # Test from_dict and to_dict without length.
        del data["length"]
        metafile_obj = MetaFile.from_dict(copy.copy(data))
        self.assertEqual(metafile_obj.to_dict(), data)

        # Test from_dict and to_dict without length and hashes.
        del data["hashes"]
        metafile_obj = MetaFile.from_dict(copy.copy(data))
        self.assertEqual(metafile_obj.to_dict(), data)


    def test_targetfile_class(self):
        # Test from_dict and to_dict with all attributes.
        data = {
            "custom": {
                "file_permissions": "0644"
            },
            "hashes": {
                "sha256": "65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da",
                "sha512": "467430a68afae8e9f9c0771ea5d78bf0b3a0d79a2d3d3b40c69fde4dd42c461448aef76fcef4f5284931a1ffd0ac096d138ba3a0d6ca83fa8d7285a47a296f77"
            },
            "length": 31
        }
        targetfile_obj = TargetFile.from_dict(copy.copy(data))
        self.assertEqual(targetfile_obj.to_dict(), data)

        # Test from_dict and to_dict without custom.
        del data["custom"]
        targetfile_obj = TargetFile.from_dict(copy.copy(data))
        self.assertEqual(targetfile_obj.to_dict(), data)


    def test_metadata_snapshot(self):
        snapshot_path = os.path.join(
                self.repo_dir, 'metadata', 'snapshot.json')
        snapshot = Metadata.from_file(snapshot_path)

        # Create a MetaFile instance representing what we expect
        # the updated data to be.
        hashes = {'sha256': 'c2986576f5fdfd43944e2b19e775453b96748ec4fe2638a6d2f32f1310967095'}
        fileinfo = MetaFile(2, 123, hashes)

        self.assertNotEqual(
            snapshot.signed.meta['role1.json'].to_dict(), fileinfo.to_dict()
        )
        snapshot.signed.update('role1', fileinfo)
        self.assertEqual(
            snapshot.signed.meta['role1.json'].to_dict(), fileinfo.to_dict()
        )

        # Test from_dict and to_dict without hashes and length.
        snapshot_dict = snapshot.to_dict()
        del snapshot_dict['signed']['meta']['role1.json']['length']
        del snapshot_dict['signed']['meta']['role1.json']['hashes']
        test_dict = copy.deepcopy(snapshot_dict['signed'])
        snapshot = Snapshot.from_dict(test_dict)
        self.assertEqual(snapshot_dict['signed'], snapshot.to_dict())

    def test_metadata_timestamp(self):
        timestamp_path = os.path.join(
                self.repo_dir, 'metadata', 'timestamp.json')
        timestamp = Metadata.from_file(timestamp_path)

        self.assertEqual(timestamp.signed.version, 1)
        timestamp.signed.bump_version()
        self.assertEqual(timestamp.signed.version, 2)

        self.assertEqual(timestamp.signed.expires, datetime(2030, 1, 1, 0, 0))
        timestamp.signed.bump_expiration()
        self.assertEqual(timestamp.signed.expires, datetime(2030, 1, 2, 0, 0))
        timestamp.signed.bump_expiration(timedelta(days=365))
        self.assertEqual(timestamp.signed.expires, datetime(2031, 1, 2, 0, 0))

        # Test whether dateutil.relativedelta works, this provides a much
        # easier to use interface for callers
        delta = relativedelta(days=1)
        timestamp.signed.bump_expiration(delta)
        self.assertEqual(timestamp.signed.expires, datetime(2031, 1, 3, 0, 0))
        delta = relativedelta(years=5)
        timestamp.signed.bump_expiration(delta)
        self.assertEqual(timestamp.signed.expires, datetime(2036, 1, 3, 0, 0))

        # Create a MetaFile instance representing what we expect
        # the updated data to be.
        hashes = {'sha256': '0ae9664468150a9aa1e7f11feecb32341658eb84292851367fea2da88e8a58dc'}
        fileinfo = MetaFile(2, 520, hashes)

        self.assertNotEqual(
            timestamp.signed.meta['snapshot.json'].to_dict(), fileinfo.to_dict()
        )
        timestamp.signed.update(fileinfo)
        self.assertEqual(
            timestamp.signed.meta['snapshot.json'].to_dict(), fileinfo.to_dict()
        )

        # Test from_dict and to_dict without hashes and length.
        timestamp_dict = timestamp.to_dict()
        del timestamp_dict['signed']['meta']['snapshot.json']['length']
        del timestamp_dict['signed']['meta']['snapshot.json']['hashes']
        test_dict = copy.deepcopy(timestamp_dict['signed'])
        timestamp_test = Timestamp.from_dict(test_dict)
        self.assertEqual(timestamp_dict['signed'], timestamp_test.to_dict())

    def test_key_class(self):
        keys = {
            "59a4df8af818e9ed7abe0764c0b47b4240952aa0d179b5b78346c470ac30278d":{
                "keytype": "ed25519",
                "keyval": {
                    "public": "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"
                },
                "scheme": "ed25519"
            },
        }
        for key_dict in keys.values():
            # Testing that the workflow of deserializing and serializing
            # a key dictionary doesn't change the content.
            test_key_dict = key_dict.copy()
            key_obj = Key.from_dict("id", test_key_dict)
            self.assertEqual(key_dict, key_obj.to_dict())
            # Test creating an instance without a required attribute.
            for key in key_dict.keys():
                test_key_dict = key_dict.copy()
                del test_key_dict[key]
                with self.assertRaises(KeyError):
                    Key.from_dict("id", test_key_dict)
            # Test creating a Key instance with wrong keyval format.
            key_dict["keyval"] = {}
            with self.assertRaises(ValueError):
                Key.from_dict("id", key_dict)


    def test_role_class(self):
        roles = {
            "root": {
                "keyids": [
                    "4e777de0d275f9d28588dd9a1606cc748e548f9e22b6795b7cb3f63f98035fcb"
                ],
                "threshold": 1
            },
            "snapshot": {
                "keyids": [
                    "59a4df8af818e9ed7abe0764c0b47b4240952aa0d179b5b78346c470ac30278d"
                ],
                "threshold": 1
            },
        }
        for role_dict in roles.values():
            # Testing that the workflow of deserializing and serializing
            # a role dictionary doesn't change the content.
            test_role_dict = role_dict.copy()
            role_obj = Role.from_dict(test_role_dict)
            self.assertEqual(role_dict, role_obj.to_dict())
            # Test creating an instance without a required attribute.
            for role_attr in role_dict.keys():
                test_role_dict = role_dict.copy()
                del test_role_dict[role_attr]
                with self.assertRaises(KeyError):
                    Key.from_dict("id", test_role_dict)
            # Test creating a Role instance with keyid dublicates.
            # for keyid in role_dict["keyids"]:
            role_dict["keyids"].append(role_dict["keyids"][0])
            test_role_dict = role_dict.copy()
            with self.assertRaises(ValueError):
                Role.from_dict(test_role_dict)


    def test_metadata_root(self):
        root_path = os.path.join(
                self.repo_dir, 'metadata', 'root.json')
        root = Metadata.from_file(root_path)

        # Add a second key to root role
        root_key2 =  import_ed25519_publickey_from_file(
                    os.path.join(self.keystore_dir, 'root_key2.pub'))


        keyid = root_key2['keyid']
        key_metadata = Key(keyid, root_key2['keytype'], root_key2['scheme'],
            root_key2['keyval'])

        # Assert that root does not contain the new key
        self.assertNotIn(keyid, root.signed.roles['root'].keyids)
        self.assertNotIn(keyid, root.signed.keys)

        # Add new root key
        root.signed.add_key('root', key_metadata)

        # Assert that key is added
        self.assertIn(keyid, root.signed.roles['root'].keyids)
        self.assertIn(keyid, root.signed.keys)

        # Confirm that the newly added key does not break
        # the object serialization
        root.to_dict()

        # Try adding the same key again and assert its ignored.
        pre_add_keyid = root.signed.roles['root'].keyids.copy()
        root.signed.add_key('root', key_metadata)
        self.assertEqual(pre_add_keyid, root.signed.roles['root'].keyids)

        # Remove the key
        root.signed.remove_key('root', keyid)

        # Assert that root does not contain the new key anymore
        self.assertNotIn(keyid, root.signed.roles['root'].keyids)
        self.assertNotIn(keyid, root.signed.keys)

        with self.assertRaises(KeyError):
            root.signed.remove_key('root', 'nosuchkey')

        # Test serializing and deserializing without consistent_snapshot.
        root_dict = root.to_dict()
        del root_dict["signed"]["consistent_snapshot"]
        root = Root.from_dict(copy.deepcopy(root_dict["signed"]))
        self.assertEqual(root_dict["signed"], root.to_dict())

    def test_delegated_role_class(self):
        roles = [
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
        for role in roles:
            # Testing that the workflow of deserializing and serializing
            # a delegation role dictionary doesn't change the content.
            key_obj = DelegatedRole.from_dict(role.copy())
            self.assertEqual(role, key_obj.to_dict())

            # Test creating a DelegatedRole object with both "paths" and
            # "path_hash_prefixes" set.
            role["path_hash_prefixes"] = "foo"
            with self.assertRaises(ValueError):
                DelegatedRole.from_dict(role.copy())

            # Test creating DelegatedRole only with "path_hash_prefixes" (an empty one)
            del role["paths"]
            role["path_hash_prefixes"] = []
            role_obj = DelegatedRole.from_dict(role.copy())
            self.assertEqual(role_obj.to_dict(), role)

            # Test creating DelegatedRole only with "paths" (now an empty one)
            del role["path_hash_prefixes"]
            role["paths"] = []
            role_obj = DelegatedRole.from_dict(role.copy())
            self.assertEqual(role_obj.to_dict(), role)

            # Test creating DelegatedRole without "paths" and
            # "path_hash_prefixes" set
            del role["paths"]
            role_obj = DelegatedRole.from_dict(role.copy())
            self.assertEqual(role_obj.to_dict(), role)


    def test_delegation_class(self):
        roles = [
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
        keys = {
                "59a4df8af818e9ed7abe0764c0b47b4240952aa0d179b5b78346c470ac30278d":{
                    "keytype": "ed25519",
                    "keyval": {
                        "public": "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"
                    },
                    "scheme": "ed25519"
                },
            }
        delegations_dict = {"keys": keys, "roles": roles}
        delegations = Delegations.from_dict(copy.deepcopy(delegations_dict))
        self.assertEqual(delegations_dict, delegations.to_dict())

        # empty keys and roles
        delegations_dict = {"keys":{}, "roles":[]}
        delegations = Delegations.from_dict(delegations_dict.copy())
        self.assertEqual(delegations_dict, delegations.to_dict())

        # Test some basic missing or broken input
        invalid_delegations_dicts = [
            {},
            {"keys":None, "roles":None},
            {"keys":{"foo":0}, "roles":[]},
            {"keys":{}, "roles":["foo"]},
        ]
        for d in invalid_delegations_dicts:
            with self.assertRaises((KeyError, AttributeError)):
                Delegations.from_dict(d)

    def test_metadata_targets(self):
        targets_path = os.path.join(
                self.repo_dir, 'metadata', 'targets.json')
        targets = Metadata.from_file(targets_path)

        # Create a fileinfo dict representing what we expect the updated data to be
        filename = 'file2.txt'
        hashes = {
            "sha256": "141f740f53781d1ca54b8a50af22cbf74e44c21a998fa2a8a05aaac2c002886b",
            "sha512": "ef5beafa16041bcdd2937140afebd485296cd54f7348ecd5a4d035c09759608de467a7ac0eb58753d0242df873c305e8bffad2454aa48f44480f15efae1cacd0"
        },

        fileinfo = TargetFile(length=28, hashes=hashes)

        # Assert that data is not aleady equal
        self.assertNotEqual(
            targets.signed.targets[filename].to_dict(), fileinfo.to_dict()
        )
        # Update an already existing fileinfo
        targets.signed.update(filename, fileinfo)
        # Verify that data is updated
        self.assertEqual(
            targets.signed.targets[filename].to_dict(), fileinfo.to_dict()
        )

        # Test from_dict/to_dict Targets without delegations
        targets_dict = targets.to_dict()
        del targets_dict["signed"]["delegations"]
        tmp_dict = copy.deepcopy(targets_dict["signed"])
        targets_obj = Targets.from_dict(tmp_dict)
        self.assertEqual(targets_dict["signed"], targets_obj.to_dict())

    def setup_dict_with_unrecognized_field(self, file_path, field, value):
        json_dict = {}
        with open(file_path) as f:
            json_dict = json.loads(f.read())
        # We are changing the json dict without changing the signature.
        # This could be a problem if we want to do verification on this dict.
        json_dict["signed"][field] = value
        return json_dict

    def test_support_for_unrecognized_fields(self):
        for metadata in ["root", "timestamp", "snapshot", "targets"]:
            path = os.path.join(self.repo_dir, "metadata", metadata + ".json")
            dict1 = self.setup_dict_with_unrecognized_field(path, "f", "b")
            # Test that the metadata classes store unrecognized fields when
            # initializing and passes them when casting the instance to a dict.

            # Add unrecognized fields to all metadata sub (helper) classes.
            if metadata == "root":
                for keyid in dict1["signed"]["keys"].keys():
                    dict1["signed"]["keys"][keyid]["d"] = "c"
                for role_str in dict1["signed"]["roles"].keys():
                    dict1["signed"]["roles"][role_str]["e"] = "g"
            elif metadata == "targets" and dict1["signed"].get("delegations"):
                for keyid in dict1["signed"]["delegations"]["keys"].keys():
                    dict1["signed"]["delegations"]["keys"][keyid]["d"] = "c"
                new_roles = []
                for role in dict1["signed"]["delegations"]["roles"]:
                    role["e"] = "g"
                    new_roles.append(role)
                dict1["signed"]["delegations"]["roles"] = new_roles
                dict1["signed"]["delegations"]["foo"] = "bar"

            temp_copy = copy.deepcopy(dict1)
            metadata_obj = Metadata.from_dict(temp_copy)

            self.assertEqual(dict1["signed"], metadata_obj.signed.to_dict())

            # Test that two instances of the same class could have different
            # unrecognized fields.
            dict2 = self.setup_dict_with_unrecognized_field(path, "f2", "b2")
            temp_copy2 = copy.deepcopy(dict2)
            metadata_obj2 = Metadata.from_dict(temp_copy2)
            self.assertNotEqual(
                metadata_obj.signed.to_dict(), metadata_obj2.signed.to_dict()
            )


# Run unit test.
if __name__ == '__main__':
    utils.configure_test_logging(sys.argv)
    unittest.main()
