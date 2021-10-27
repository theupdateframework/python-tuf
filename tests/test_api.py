#!/usr/bin/env python

# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
""" Unit tests for api/metadata.py

"""

import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

from dateutil.relativedelta import relativedelta
from securesystemslib import hash as sslib_hash
from securesystemslib.interface import (
    import_ed25519_privatekey_from_file,
    import_ed25519_publickey_from_file,
)
from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import Signature, SSlibSigner

from tests import utils
from tuf import exceptions
from tuf.api.metadata import (
    DelegatedRole,
    Key,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization import DeserializationError
from tuf.api.serialization.json import CanonicalJSONSerializer, JSONSerializer

logger = logging.getLogger(__name__)


class TestMetadata(unittest.TestCase):
    """Tests for public API of all classes in tuf/api/metadata.py"""

    @classmethod
    def setUpClass(cls):
        # Create a temporary directory to store the repository, metadata, and
        # target files.  'temporary_directory' must be deleted in
        # TearDownClass() so that temporary files are always removed, even when
        # exceptions occur.
        cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

        test_repo_data = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "repository_data"
        )

        cls.repo_dir = os.path.join(cls.temporary_directory, "repository")
        shutil.copytree(
            os.path.join(test_repo_data, "repository"), cls.repo_dir
        )

        cls.keystore_dir = os.path.join(cls.temporary_directory, "keystore")
        shutil.copytree(
            os.path.join(test_repo_data, "keystore"), cls.keystore_dir
        )

        # Load keys into memory
        cls.keystore = {}
        for role in ["delegation", "snapshot", "targets", "timestamp"]:
            cls.keystore[role] = import_ed25519_privatekey_from_file(
                os.path.join(cls.keystore_dir, role + "_key"),
                password="password",
            )

    @classmethod
    def tearDownClass(cls):
        # Remove the temporary repository directory, which should contain all
        # the metadata, targets, and key files generated for the test cases.
        shutil.rmtree(cls.temporary_directory)

    def test_generic_read(self):
        for metadata, inner_metadata_cls in [
            ("root", Root),
            ("snapshot", Snapshot),
            ("timestamp", Timestamp),
            ("targets", Targets),
        ]:

            # Load JSON-formatted metdata of each supported type from file
            # and from out-of-band read JSON string
            path = os.path.join(self.repo_dir, "metadata", metadata + ".json")
            md_obj = Metadata.from_file(path)
            with open(path, "rb") as f:
                md_obj2 = Metadata.from_bytes(f.read())

            # Assert that both methods instantiate the right inner class for
            # each metadata type and ...
            self.assertTrue(isinstance(md_obj.signed, inner_metadata_cls))
            self.assertTrue(isinstance(md_obj2.signed, inner_metadata_cls))

            # ... and return the same object (compared by dict representation)
            self.assertDictEqual(md_obj.to_dict(), md_obj2.to_dict())

        # Assert that it chokes correctly on an unknown metadata type
        bad_metadata_path = "bad-metadata.json"
        bad_metadata = {"signed": {"_type": "bad-metadata"}}
        bad_string = json.dumps(bad_metadata).encode("utf-8")
        with open(bad_metadata_path, "wb") as f:
            f.write(bad_string)

        with self.assertRaises(DeserializationError):
            Metadata.from_file(bad_metadata_path)
        with self.assertRaises(DeserializationError):
            Metadata.from_bytes(bad_string)

        os.remove(bad_metadata_path)

    def test_compact_json(self):
        path = os.path.join(self.repo_dir, "metadata", "targets.json")
        md_obj = Metadata.from_file(path)
        self.assertTrue(
            len(JSONSerializer(compact=True).serialize(md_obj))
            < len(JSONSerializer().serialize(md_obj))
        )

    def test_read_write_read_compare(self):
        for metadata in ["root", "snapshot", "timestamp", "targets"]:
            path = os.path.join(self.repo_dir, "metadata", metadata + ".json")
            md_obj = Metadata.from_file(path)

            path_2 = path + ".tmp"
            md_obj.to_file(path_2)
            md_obj_2 = Metadata.from_file(path_2)
            self.assertDictEqual(md_obj.to_dict(), md_obj_2.to_dict())

            os.remove(path_2)

    def test_to_from_bytes(self):
        for metadata in ["root", "snapshot", "timestamp", "targets"]:
            path = os.path.join(self.repo_dir, "metadata", metadata + ".json")
            with open(path, "rb") as f:
                metadata_bytes = f.read()
            md_obj = Metadata.from_bytes(metadata_bytes)
            # Comparate that from_bytes/to_bytes doesn't change the content
            # for two cases for the serializer: noncompact and compact.

            # Case 1: test noncompact by overriding the default serializer.
            self.assertEqual(md_obj.to_bytes(JSONSerializer()), metadata_bytes)

            # Case 2: test compact by using the default serializer.
            obj_bytes = md_obj.to_bytes()
            metadata_obj_2 = Metadata.from_bytes(obj_bytes)
            self.assertEqual(metadata_obj_2.to_bytes(), obj_bytes)

    def test_sign_verify(self):
        path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(path).signed

        # Locate the public keys we need from root
        targets_keyid = next(iter(root.roles["targets"].keyids))
        targets_key = root.keys[targets_keyid]
        snapshot_keyid = next(iter(root.roles["snapshot"].keyids))
        snapshot_key = root.keys[snapshot_keyid]
        timestamp_keyid = next(iter(root.roles["timestamp"].keyids))
        timestamp_key = root.keys[timestamp_keyid]

        # Load sample metadata (targets) and assert ...
        path = os.path.join(self.repo_dir, "metadata", "targets.json")
        md_obj = Metadata.from_file(path)

        # ... it has a single existing signature,
        self.assertEqual(len(md_obj.signatures), 1)
        # ... which is valid for the correct key.
        targets_key.verify_signature(md_obj)
        with self.assertRaises(exceptions.UnsignedMetadataError):
            snapshot_key.verify_signature(md_obj)

        # Test verifying with explicitly set serializer
        targets_key.verify_signature(md_obj, CanonicalJSONSerializer())
        with self.assertRaises(exceptions.UnsignedMetadataError):
            targets_key.verify_signature(md_obj, JSONSerializer())

        sslib_signer = SSlibSigner(self.keystore["snapshot"])
        # Append a new signature with the unrelated key and assert that ...
        sig = md_obj.sign(sslib_signer, append=True)
        # ... there are now two signatures, and
        self.assertEqual(len(md_obj.signatures), 2)
        # ... both are valid for the corresponding keys.
        targets_key.verify_signature(md_obj)
        snapshot_key.verify_signature(md_obj)
        # ... the returned (appended) signature is for snapshot key
        self.assertEqual(sig.keyid, snapshot_keyid)

        sslib_signer = SSlibSigner(self.keystore["timestamp"])
        # Create and assign (don't append) a new signature and assert that ...
        md_obj.sign(sslib_signer, append=False)
        # ... there now is only one signature,
        self.assertEqual(len(md_obj.signatures), 1)
        # ... valid for that key.
        timestamp_key.verify_signature(md_obj)
        with self.assertRaises(exceptions.UnsignedMetadataError):
            targets_key.verify_signature(md_obj)

        # Test failure on unknown scheme (securesystemslib
        # UnsupportedAlgorithmError)
        scheme = timestamp_key.scheme
        timestamp_key.scheme = "foo"
        with self.assertRaises(exceptions.UnsignedMetadataError):
            timestamp_key.verify_signature(md_obj)
        timestamp_key.scheme = scheme

        # Test failure on broken public key data (securesystemslib CryptoError)
        public = timestamp_key.keyval["public"]
        timestamp_key.keyval["public"] = "ffff"
        with self.assertRaises(exceptions.UnsignedMetadataError):
            timestamp_key.verify_signature(md_obj)
        timestamp_key.keyval["public"] = public

        # Test failure with invalid signature (securesystemslib FormatError)
        sig = md_obj.signatures[timestamp_keyid]
        correct_sig = sig.signature
        sig.signature = "foo"
        with self.assertRaises(exceptions.UnsignedMetadataError):
            timestamp_key.verify_signature(md_obj)

        # Test failure with valid but incorrect signature
        sig.signature = "ff" * 64
        with self.assertRaises(exceptions.UnsignedMetadataError):
            timestamp_key.verify_signature(md_obj)
        sig.signature = correct_sig

    def test_metadata_base(self):
        # Use of Snapshot is arbitrary, we're just testing the base class
        # features with real data
        snapshot_path = os.path.join(self.repo_dir, "metadata", "snapshot.json")
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

        # Test deserializing metadata with non-unique signatures:
        data = md.to_dict()
        data["signatures"].append(
            {"keyid": data["signatures"][0]["keyid"], "sig": "foo"}
        )
        with self.assertRaises(ValueError):
            Metadata.from_dict(data)

    def test_metadata_snapshot(self):
        snapshot_path = os.path.join(self.repo_dir, "metadata", "snapshot.json")
        snapshot = Metadata[Snapshot].from_file(snapshot_path)

        # Create a MetaFile instance representing what we expect
        # the updated data to be.
        hashes = {
            "sha256": "c2986576f5fdfd43944e2b19e775453b96748ec4fe2638a6d2f32f1310967095"  # pylint: disable=line-too-long
        }
        fileinfo = MetaFile(2, 123, hashes)

        self.assertNotEqual(
            snapshot.signed.meta["role1.json"].to_dict(), fileinfo.to_dict()
        )
        snapshot.signed.update("role1", fileinfo)
        self.assertEqual(
            snapshot.signed.meta["role1.json"].to_dict(), fileinfo.to_dict()
        )

    def test_metadata_timestamp(self):
        timestamp_path = os.path.join(
            self.repo_dir, "metadata", "timestamp.json"
        )
        timestamp = Metadata[Timestamp].from_file(timestamp_path)

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
        hashes = {
            "sha256": "0ae9664468150a9aa1e7f11feecb32341658eb84292851367fea2da88e8a58dc"  # pylint: disable=line-too-long
        }
        fileinfo = MetaFile(2, 520, hashes)

        self.assertNotEqual(
            timestamp.signed.snapshot_meta.to_dict(), fileinfo.to_dict()
        )
        timestamp.signed.update(fileinfo)
        self.assertEqual(
            timestamp.signed.snapshot_meta.to_dict(), fileinfo.to_dict()
        )

    def test_metadata_verify_delegate(self):
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path)
        snapshot_path = os.path.join(self.repo_dir, "metadata", "snapshot.json")
        snapshot = Metadata[Snapshot].from_file(snapshot_path)
        targets_path = os.path.join(self.repo_dir, "metadata", "targets.json")
        targets = Metadata[Targets].from_file(targets_path)
        role1_path = os.path.join(self.repo_dir, "metadata", "role1.json")
        role1 = Metadata[Targets].from_file(role1_path)
        role2_path = os.path.join(self.repo_dir, "metadata", "role2.json")
        role2 = Metadata[Targets].from_file(role2_path)

        # test the expected delegation tree
        root.verify_delegate("root", root)
        root.verify_delegate("snapshot", snapshot)
        root.verify_delegate("targets", targets)
        targets.verify_delegate("role1", role1)
        role1.verify_delegate("role2", role2)

        # only root and targets can verify delegates
        with self.assertRaises(TypeError):
            snapshot.verify_delegate("snapshot", snapshot)
        # verify fails for roles that are not delegated by delegator
        with self.assertRaises(ValueError):
            root.verify_delegate("role1", role1)
        with self.assertRaises(ValueError):
            targets.verify_delegate("targets", targets)
        # verify fails when delegator has no delegations
        with self.assertRaises(ValueError):
            role2.verify_delegate("role1", role1)

        # verify fails when delegate content is modified
        expires = snapshot.signed.expires
        snapshot.signed.bump_expiration()
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate("snapshot", snapshot)
        snapshot.signed.expires = expires

        # verify fails if roles keys do not sign the metadata
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate("timestamp", snapshot)

        # Add a key to snapshot role, make sure the new sig fails to verify
        ts_keyid = next(iter(root.signed.roles["timestamp"].keyids))
        root.signed.add_key("snapshot", root.signed.keys[ts_keyid])
        snapshot.signatures[ts_keyid] = Signature(ts_keyid, "ff" * 64)

        # verify succeeds if threshold is reached even if some signatures
        # fail to verify
        root.verify_delegate("snapshot", snapshot)

        # verify fails if threshold of signatures is not reached
        root.signed.roles["snapshot"].threshold = 2
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate("snapshot", snapshot)

        # verify succeeds when we correct the new signature and reach the
        # threshold of 2 keys
        snapshot.sign(SSlibSigner(self.keystore["timestamp"]), append=True)
        root.verify_delegate("snapshot", snapshot)

    def test_key_class(self):
        # Test if from_securesystemslib_key removes the private key from keyval
        # of a securesystemslib key dictionary.
        sslib_key = generate_ed25519_key()
        key = Key.from_securesystemslib_key(sslib_key)
        self.assertFalse("private" in key.keyval.keys())

    def test_root_add_key_and_remove_key(self):
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path)

        # Create a new key
        root_key2 = import_ed25519_publickey_from_file(
            os.path.join(self.keystore_dir, "root_key2.pub")
        )
        keyid = root_key2["keyid"]
        key_metadata = Key(
            keyid,
            root_key2["keytype"],
            root_key2["scheme"],
            root_key2["keyval"],
        )

        # Assert that root does not contain the new key
        self.assertNotIn(keyid, root.signed.roles["root"].keyids)
        self.assertNotIn(keyid, root.signed.keys)

        # Add new root key
        root.signed.add_key("root", key_metadata)

        # Assert that key is added
        self.assertIn(keyid, root.signed.roles["root"].keyids)
        self.assertIn(keyid, root.signed.keys)

        # Confirm that the newly added key does not break
        # the object serialization
        root.to_dict()

        # Try adding the same key again and assert its ignored.
        pre_add_keyid = root.signed.roles["root"].keyids.copy()
        root.signed.add_key("root", key_metadata)
        self.assertEqual(pre_add_keyid, root.signed.roles["root"].keyids)

        # Add the same key to targets role as well
        root.signed.add_key("targets", key_metadata)

        # Add the same key to a nonexistent role.
        with self.assertRaises(ValueError):
            root.signed.add_key("nosuchrole", key_metadata)

        # Remove the key from root role (targets role still uses it)
        root.signed.remove_key("root", keyid)
        self.assertNotIn(keyid, root.signed.roles["root"].keyids)
        self.assertIn(keyid, root.signed.keys)

        # Remove the key from targets as well
        root.signed.remove_key("targets", keyid)
        self.assertNotIn(keyid, root.signed.roles["targets"].keyids)
        self.assertNotIn(keyid, root.signed.keys)

        with self.assertRaises(ValueError):
            root.signed.remove_key("root", "nosuchkey")
        with self.assertRaises(ValueError):
            root.signed.remove_key("nosuchrole", keyid)

    def test_is_target_in_pathpattern(self):
        supported_use_cases = [
            ("foo.tgz", "foo.tgz"),
            ("foo.tgz", "*"),
            ("foo.tgz", "*.tgz"),
            ("foo-version-a.tgz", "foo-version-?.tgz"),
            ("targets/foo.tgz", "targets/*.tgz"),
            ("foo/bar/zoo/k.tgz", "foo/bar/zoo/*"),
            ("foo/bar/zoo/k.tgz", "foo/*/zoo/*"),
            ("foo/bar/zoo/k.tgz", "*/*/*/*"),
            ("foo/bar", "f?o/bar"),
            ("foo/bar", "*o/bar"),
        ]
        for targetpath, pathpattern in supported_use_cases:
            self.assertTrue(
                # pylint: disable-next=protected-access
                DelegatedRole._is_target_in_pathpattern(targetpath, pathpattern)
            )

        invalid_use_cases = [
            ("targets/foo.tgz", "*.tgz"),
            ("/foo.tgz", "*.tgz"),
            ("targets/foo.tgz", "*"),
            ("foo-version-alpha.tgz", "foo-version-?.tgz"),
            ("foo//bar", "*/bar"),
            ("foo/bar", "f?/bar"),
        ]
        for targetpath, pathpattern in invalid_use_cases:
            self.assertFalse(
                # pylint: disable-next=protected-access
                DelegatedRole._is_target_in_pathpattern(targetpath, pathpattern)
            )

    def test_metadata_targets(self):
        targets_path = os.path.join(self.repo_dir, "metadata", "targets.json")
        targets = Metadata[Targets].from_file(targets_path)

        # Create a fileinfo dict representing the expected updated data.
        filename = "file2.txt"
        hashes = {
            "sha256": "141f740f53781d1ca54b8a50af22cbf74e44c21a998fa2a8a05aaac2c002886b",  # pylint: disable=line-too-long
            "sha512": "ef5beafa16041bcdd2937140afebd485296cd54f7348ecd5a4d035c09759608de467a7ac0eb58753d0242df873c305e8bffad2454aa48f44480f15efae1cacd0",  # pylint: disable=line-too-long
        }

        fileinfo = TargetFile(length=28, hashes=hashes, path=filename)

        # Assert that data is not aleady equal
        self.assertNotEqual(
            targets.signed.targets[filename].to_dict(), fileinfo.to_dict()
        )
        # Update an already existing fileinfo
        targets.signed.update(fileinfo)
        # Verify that data is updated
        self.assertEqual(
            targets.signed.targets[filename].to_dict(), fileinfo.to_dict()
        )

    def test_targets_key_api(self):
        targets_path = os.path.join(self.repo_dir, "metadata", "targets.json")
        targets: Targets = Metadata[Targets].from_file(targets_path).signed

        # Add a new delegated role "role2" in targets
        delegated_role = DelegatedRole.from_dict(
            {
                "keyids": [],
                "name": "role2",
                "paths": ["fn3", "fn4"],
                "terminating": False,
                "threshold": 1,
            }
        )
        targets.delegations.roles["role2"] = delegated_role

        key_dict = {
            "keytype": "ed25519",
            "keyval": {
                "public": "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"  # pylint: disable=line-too-long
            },
            "scheme": "ed25519",
        }
        key = Key.from_dict("id2", key_dict)

        # Assert that delegated role "role1" does not contain the new key
        self.assertNotIn(key.keyid, targets.delegations.roles["role1"].keyids)
        targets.add_key("role1", key)

        # Assert that the new key is added to the delegated role "role1"
        self.assertIn(key.keyid, targets.delegations.roles["role1"].keyids)

        # Confirm that the newly added key does not break the obj serialization
        targets.to_dict()

        # Try adding the same key again and assert its ignored.
        past_keyid = targets.delegations.roles["role1"].keyids.copy()
        targets.add_key("role1", key)
        self.assertEqual(past_keyid, targets.delegations.roles["role1"].keyids)

        # Try adding a key to a delegated role that doesn't exists
        with self.assertRaises(ValueError):
            targets.add_key("nosuchrole", key)

        # Add the same key to "role2" as well
        targets.add_key("role2", key)

        # Remove the key from "role1" role ("role2" still uses it)
        targets.remove_key("role1", key.keyid)

        # Assert that delegated role "role1" doesn't contain the key.
        self.assertNotIn(key.keyid, targets.delegations.roles["role1"].keyids)
        self.assertIn(key.keyid, targets.delegations.roles["role2"].keyids)

        # Remove the key from "role2" as well
        targets.remove_key("role2", key.keyid)
        self.assertNotIn(key.keyid, targets.delegations.roles["role2"].keyids)

        # Try remove key not used by "role1"
        with self.assertRaises(ValueError):
            targets.remove_key("role1", key.keyid)

        # Try removing a key from delegated role that doesn't exists
        with self.assertRaises(ValueError):
            targets.remove_key("nosuchrole", key.keyid)

        # Remove delegations as a whole
        targets.delegations = None
        # Test that calling add_key and remove_key throws an error
        # and that delegations is still None after each of the api calls
        with self.assertRaises(ValueError):
            targets.add_key("role1", key)
        self.assertTrue(targets.delegations is None)
        with self.assertRaises(ValueError):
            targets.remove_key("role1", key.keyid)
        self.assertTrue(targets.delegations is None)

    def test_length_and_hash_validation(self):

        # Test metadata files' hash and length verification.
        # Use timestamp to get a MetaFile object and snapshot
        # for untrusted metadata file to verify.
        timestamp_path = os.path.join(
            self.repo_dir, "metadata", "timestamp.json"
        )
        timestamp = Metadata[Timestamp].from_file(timestamp_path)
        snapshot_metafile = timestamp.signed.snapshot_meta

        snapshot_path = os.path.join(self.repo_dir, "metadata", "snapshot.json")

        with open(snapshot_path, "rb") as file:
            # test with  data as a file object
            snapshot_metafile.verify_length_and_hashes(file)
            file.seek(0)
            data = file.read()
            # test with data as bytes
            snapshot_metafile.verify_length_and_hashes(data)

            # test exceptions
            expected_length = snapshot_metafile.length
            snapshot_metafile.length = 2345
            self.assertRaises(
                exceptions.LengthOrHashMismatchError,
                snapshot_metafile.verify_length_and_hashes,
                data,
            )

            snapshot_metafile.length = expected_length
            snapshot_metafile.hashes = {"sha256": "incorrecthash"}
            self.assertRaises(
                exceptions.LengthOrHashMismatchError,
                snapshot_metafile.verify_length_and_hashes,
                data,
            )

            snapshot_metafile.hashes = {
                "unsupported-alg": "8f88e2ba48b412c3843e9bb26e1b6f8fc9e98aceb0fbaa97ba37b4c98717d7ab"  # pylint: disable=line-too-long
            }
            self.assertRaises(
                exceptions.LengthOrHashMismatchError,
                snapshot_metafile.verify_length_and_hashes,
                data,
            )

            # Test wrong algorithm format (sslib.FormatError)
            snapshot_metafile.hashes = {
                256: "8f88e2ba48b412c3843e9bb26e1b6f8fc9e98aceb0fbaa97ba37b4c98717d7ab"  # pylint: disable=line-too-long
            }
            self.assertRaises(
                exceptions.LengthOrHashMismatchError,
                snapshot_metafile.verify_length_and_hashes,
                data,
            )

            # test optional length and hashes
            snapshot_metafile.length = None
            snapshot_metafile.hashes = None
            snapshot_metafile.verify_length_and_hashes(data)

        # Test target files' hash and length verification
        targets_path = os.path.join(self.repo_dir, "metadata", "targets.json")
        targets = Metadata[Targets].from_file(targets_path)
        file1_targetfile = targets.signed.targets["file1.txt"]
        filepath = os.path.join(self.repo_dir, "targets", "file1.txt")

        with open(filepath, "rb") as file1:
            file1_targetfile.verify_length_and_hashes(file1)

            # test exceptions
            expected_length = file1_targetfile.length
            file1_targetfile.length = 2345
            self.assertRaises(
                exceptions.LengthOrHashMismatchError,
                file1_targetfile.verify_length_and_hashes,
                file1,
            )

            file1_targetfile.length = expected_length
            file1_targetfile.hashes = {"sha256": "incorrecthash"}
            self.assertRaises(
                exceptions.LengthOrHashMismatchError,
                file1_targetfile.verify_length_and_hashes,
                file1,
            )

    def test_targetfile_from_file(self):
        # Test with an existing file and valid hash algorithm
        file_path = os.path.join(self.repo_dir, "targets", "file1.txt")
        targetfile_from_file = TargetFile.from_file(
            file_path, file_path, ["sha256"]
        )

        with open(file_path, "rb") as file:
            targetfile_from_file.verify_length_and_hashes(file)

        # Test with a non-existing file
        file_path = os.path.join(self.repo_dir, "targets", "file123.txt")
        self.assertRaises(
            FileNotFoundError,
            TargetFile.from_file,
            file_path,
            file_path,
            [sslib_hash.DEFAULT_HASH_ALGORITHM],
        )

        # Test with an unsupported algorithm
        file_path = os.path.join(self.repo_dir, "targets", "file1.txt")
        self.assertRaises(
            exceptions.UnsupportedAlgorithmError,
            TargetFile.from_file,
            file_path,
            file_path,
            ["123"],
        )

    def test_targetfile_from_data(self):
        data = b"Inline test content"
        target_file_path = os.path.join(self.repo_dir, "targets", "file1.txt")

        # Test with a valid hash algorithm
        targetfile_from_data = TargetFile.from_data(
            target_file_path, data, ["sha256"]
        )
        targetfile_from_data.verify_length_and_hashes(data)

        # Test with no algorithms specified
        targetfile_from_data = TargetFile.from_data(target_file_path, data)
        targetfile_from_data.verify_length_and_hashes(data)

    def test_is_delegated_role(self):
        # test path matches
        # see more extensive tests in test_is_target_in_pathpattern()
        for paths in [
            ["a/path"],
            ["otherpath", "a/path"],
            ["*/?ath"],
        ]:
            role = DelegatedRole("", [], 1, False, paths, None)
            self.assertFalse(role.is_delegated_path("a/non-matching path"))
            self.assertTrue(role.is_delegated_path("a/path"))

        # test path hash prefix matches: sha256 sum of "a/path" is 927b0ecf9...
        for hash_prefixes in [
            ["927b0ecf9"],
            ["other prefix", "927b0ecf9"],
            ["927b0"],
            ["92"],
        ]:
            role = DelegatedRole("", [], 1, False, None, hash_prefixes)
            self.assertFalse(role.is_delegated_path("a/non-matching path"))
            self.assertTrue(role.is_delegated_path("a/path"))


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
