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
from copy import copy
from datetime import datetime, timedelta
from typing import Any, ClassVar, Dict

from securesystemslib import hash as sslib_hash
from securesystemslib.interface import (
    import_ed25519_privatekey_from_file,
    import_ed25519_publickey_from_file,
)
from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import Signature, SSlibSigner

from tests import utils
from tuf.api import exceptions
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    Root,
    Snapshot,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization import DeserializationError, SerializationError
from tuf.api.serialization.json import CanonicalJSONSerializer, JSONSerializer

logger = logging.getLogger(__name__)


# pylint: disable=too-many-public-methods
class TestMetadata(unittest.TestCase):
    """Tests for public API of all classes in 'tuf/api/metadata.py'."""

    temporary_directory: ClassVar[str]
    repo_dir: ClassVar[str]
    keystore_dir: ClassVar[str]
    keystore: ClassVar[Dict[str, Dict[str, Any]]]

    @classmethod
    def setUpClass(cls) -> None:
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
        for role in ["delegation", Snapshot.type, Targets.type, Timestamp.type]:
            cls.keystore[role] = import_ed25519_privatekey_from_file(
                os.path.join(cls.keystore_dir, role + "_key"),
                password="password",
            )

    @classmethod
    def tearDownClass(cls) -> None:
        # Remove the temporary repository directory, which should contain all
        # the metadata, targets, and key files generated for the test cases.
        shutil.rmtree(cls.temporary_directory)

    def test_generic_read(self) -> None:
        for metadata, inner_metadata_cls in [
            (Root.type, Root),
            (Snapshot.type, Snapshot),
            (Timestamp.type, Timestamp),
            (Targets.type, Targets),
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

    def test_md_read_write_file_exceptions(self) -> None:
        # Test writing to a file with bad filename
        with self.assertRaises(exceptions.StorageError):
            Metadata.from_file("bad-metadata.json")

        # Test serializing to a file with bad filename
        with self.assertRaises(exceptions.StorageError):
            md = Metadata.from_file(
                os.path.join(self.repo_dir, "metadata", "root.json")
            )
            md.to_file("")

    def test_compact_json(self) -> None:
        path = os.path.join(self.repo_dir, "metadata", "targets.json")
        md_obj = Metadata.from_file(path)
        self.assertTrue(
            len(JSONSerializer(compact=True).serialize(md_obj))
            < len(JSONSerializer().serialize(md_obj))
        )

    def test_read_write_read_compare(self) -> None:
        for metadata in TOP_LEVEL_ROLE_NAMES:
            path = os.path.join(self.repo_dir, "metadata", metadata + ".json")
            md_obj = Metadata.from_file(path)

            path_2 = path + ".tmp"
            md_obj.to_file(path_2)
            md_obj_2 = Metadata.from_file(path_2)
            self.assertDictEqual(md_obj.to_dict(), md_obj_2.to_dict())

            os.remove(path_2)

    def test_serialize_with_validate(self) -> None:
        # Assert that by changing one required attribute validation will fail.
        root = Metadata.from_file(
            os.path.join(self.repo_dir, "metadata", "root.json")
        )
        root.signed.version = 0
        with self.assertRaises(SerializationError):
            root.to_bytes(JSONSerializer(validate=True))

    def test_to_from_bytes(self) -> None:
        for metadata in TOP_LEVEL_ROLE_NAMES:
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

    def test_sign_verify(self) -> None:
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path).signed

        # Locate the public keys we need from root
        targets_keyid = next(iter(root.roles[Targets.type].keyids))
        targets_key = root.keys[targets_keyid]
        snapshot_keyid = next(iter(root.roles[Snapshot.type].keyids))
        snapshot_key = root.keys[snapshot_keyid]
        timestamp_keyid = next(iter(root.roles[Timestamp.type].keyids))
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
            targets_key.verify_signature(md_obj, JSONSerializer())  # type: ignore[arg-type]

        sslib_signer = SSlibSigner(self.keystore[Snapshot.type])
        # Append a new signature with the unrelated key and assert that ...
        sig = md_obj.sign(sslib_signer, append=True)
        # ... there are now two signatures, and
        self.assertEqual(len(md_obj.signatures), 2)
        # ... both are valid for the corresponding keys.
        targets_key.verify_signature(md_obj)
        snapshot_key.verify_signature(md_obj)
        # ... the returned (appended) signature is for snapshot key
        self.assertEqual(sig.keyid, snapshot_keyid)

        sslib_signer = SSlibSigner(self.keystore[Timestamp.type])
        # Create and assign (don't append) a new signature and assert that ...
        md_obj.sign(sslib_signer, append=False)
        # ... there now is only one signature,
        self.assertEqual(len(md_obj.signatures), 1)
        # ... valid for that key.
        timestamp_key.verify_signature(md_obj)
        with self.assertRaises(exceptions.UnsignedMetadataError):
            targets_key.verify_signature(md_obj)

    def test_sign_failures(self) -> None:
        # Test throwing UnsignedMetadataError because of signing problems
        # related to bad information in the signer.
        md = Metadata.from_file(
            os.path.join(self.repo_dir, "metadata", "snapshot.json")
        )
        key_dict = copy(self.keystore[Snapshot.type])
        key_dict["keytype"] = "rsa"
        key_dict["scheme"] = "bad_scheme"
        sslib_signer = SSlibSigner(key_dict)
        with self.assertRaises(exceptions.UnsignedMetadataError):
            md.sign(sslib_signer)

    def test_verify_failures(self) -> None:
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path).signed

        # Locate the timestamp public key we need from root
        timestamp_keyid = next(iter(root.roles[Timestamp.type].keyids))
        timestamp_key = root.keys[timestamp_keyid]

        # Load sample metadata (timestamp)
        path = os.path.join(self.repo_dir, "metadata", "timestamp.json")
        md_obj = Metadata.from_file(path)

        # Test failure on unknown scheme (securesystemslib
        # UnsupportedAlgorithmError)
        scheme = timestamp_key.scheme
        timestamp_key.scheme = "foo"
        with self.assertRaises(exceptions.UnsignedMetadataError):
            timestamp_key.verify_signature(md_obj)
        timestamp_key.scheme = scheme

        # Test failure on broken public key data (securesystemslib
        # CryptoError)
        public = timestamp_key.keyval["public"]
        timestamp_key.keyval["public"] = "ffff"
        with self.assertRaises(exceptions.UnsignedMetadataError):
            timestamp_key.verify_signature(md_obj)
        timestamp_key.keyval["public"] = public

        # Test failure with invalid signature (securesystemslib
        # FormatError)
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

    def test_metadata_signed_is_expired(self) -> None:
        # Use of Snapshot is arbitrary, we're just testing the base class
        # features with real data
        snapshot_path = os.path.join(self.repo_dir, "metadata", "snapshot.json")
        md = Metadata.from_file(snapshot_path)

        self.assertEqual(md.signed.expires, datetime(2030, 1, 1, 0, 0))

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

    def test_metadata_verify_delegate(self) -> None:
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
        root.verify_delegate(Root.type, root)
        root.verify_delegate(Snapshot.type, snapshot)
        root.verify_delegate(Targets.type, targets)
        targets.verify_delegate("role1", role1)
        role1.verify_delegate("role2", role2)

        # only root and targets can verify delegates
        with self.assertRaises(TypeError):
            snapshot.verify_delegate(Snapshot.type, snapshot)
        # verify fails for roles that are not delegated by delegator
        with self.assertRaises(ValueError):
            root.verify_delegate("role1", role1)
        with self.assertRaises(ValueError):
            targets.verify_delegate(Targets.type, targets)
        # verify fails when delegator has no delegations
        with self.assertRaises(ValueError):
            role2.verify_delegate("role1", role1)

        # verify fails when delegate content is modified
        expires = snapshot.signed.expires
        snapshot.signed.expires = expires + timedelta(days=1)
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate(Snapshot.type, snapshot)
        snapshot.signed.expires = expires

        # verify fails if roles keys do not sign the metadata
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate(Timestamp.type, snapshot)

        # Add a key to snapshot role, make sure the new sig fails to verify
        ts_keyid = next(iter(root.signed.roles[Timestamp.type].keyids))
        root.signed.add_key(root.signed.keys[ts_keyid], Snapshot.type)
        snapshot.signatures[ts_keyid] = Signature(ts_keyid, "ff" * 64)

        # verify succeeds if threshold is reached even if some signatures
        # fail to verify
        root.verify_delegate(Snapshot.type, snapshot)

        # verify fails if threshold of signatures is not reached
        root.signed.roles[Snapshot.type].threshold = 2
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate(Snapshot.type, snapshot)

        # verify succeeds when we correct the new signature and reach the
        # threshold of 2 keys
        snapshot.sign(SSlibSigner(self.keystore[Timestamp.type]), append=True)
        root.verify_delegate(Snapshot.type, snapshot)

    def test_key_class(self) -> None:
        # Test if from_securesystemslib_key removes the private key from keyval
        # of a securesystemslib key dictionary.
        sslib_key = generate_ed25519_key()
        key = Key.from_securesystemslib_key(sslib_key)
        self.assertFalse("private" in key.keyval.keys())

        # Test raising ValueError with non-existent keytype
        sslib_key["keytype"] = "bad keytype"
        with self.assertRaises(ValueError):
            Key.from_securesystemslib_key(sslib_key)

    def test_root_add_key_and_revoke_key(self) -> None:
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
        self.assertNotIn(keyid, root.signed.roles[Root.type].keyids)
        self.assertNotIn(keyid, root.signed.keys)

        # Assert that add_key with old argument order will raise an error
        with self.assertRaises(ValueError):
            root.signed.add_key(Root.type, key_metadata)  # type: ignore

        # Add new root key
        root.signed.add_key(key_metadata, Root.type)

        # Assert that key is added
        self.assertIn(keyid, root.signed.roles[Root.type].keyids)
        self.assertIn(keyid, root.signed.keys)

        # Confirm that the newly added key does not break
        # the object serialization
        root.to_dict()

        # Try adding the same key again and assert its ignored.
        pre_add_keyid = root.signed.roles[Root.type].keyids.copy()
        root.signed.add_key(key_metadata, Root.type)
        self.assertEqual(pre_add_keyid, root.signed.roles[Root.type].keyids)

        # Add the same key to targets role as well
        root.signed.add_key(key_metadata, Targets.type)

        # Add the same key to a nonexistent role.
        with self.assertRaises(ValueError):
            root.signed.add_key(key_metadata, "nosuchrole")

        # Remove the key from root role (targets role still uses it)
        root.signed.revoke_key(keyid, Root.type)
        self.assertNotIn(keyid, root.signed.roles[Root.type].keyids)
        self.assertIn(keyid, root.signed.keys)

        # Remove the key from targets as well
        root.signed.revoke_key(keyid, Targets.type)
        self.assertNotIn(keyid, root.signed.roles[Targets.type].keyids)
        self.assertNotIn(keyid, root.signed.keys)

        with self.assertRaises(ValueError):
            root.signed.revoke_key("nosuchkey", Root.type)
        with self.assertRaises(ValueError):
            root.signed.revoke_key(keyid, "nosuchrole")

    def test_is_target_in_pathpattern(self) -> None:
        # pylint: disable=protected-access
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
                DelegatedRole._is_target_in_pathpattern(targetpath, pathpattern)
            )

    def test_targets_key_api(self) -> None:
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
        assert isinstance(targets.delegations, Delegations)
        assert isinstance(targets.delegations.roles, Dict)
        targets.delegations.roles["role2"] = delegated_role

        key_dict = {
            "keytype": "ed25519",
            "keyval": {
                "public": "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"
            },
            "scheme": "ed25519",
        }
        key = Key.from_dict("id2", key_dict)

        # Assert that add_key with old argument order will raise an error
        with self.assertRaises(ValueError):
            targets.add_key("role1", key)  # type: ignore

        # Assert that delegated role "role1" does not contain the new key
        self.assertNotIn(key.keyid, targets.delegations.roles["role1"].keyids)
        targets.add_key(key, "role1")

        # Assert that the new key is added to the delegated role "role1"
        self.assertIn(key.keyid, targets.delegations.roles["role1"].keyids)

        # Confirm that the newly added key does not break the obj serialization
        targets.to_dict()

        # Try adding the same key again and assert its ignored.
        past_keyid = targets.delegations.roles["role1"].keyids.copy()
        targets.add_key(key, "role1")
        self.assertEqual(past_keyid, targets.delegations.roles["role1"].keyids)

        # Try adding a key to a delegated role that doesn't exists
        with self.assertRaises(ValueError):
            targets.add_key(key, "nosuchrole")

        # Add the same key to "role2" as well
        targets.add_key(key, "role2")

        # Remove the key from "role1" role ("role2" still uses it)
        targets.revoke_key(key.keyid, "role1")

        # Assert that delegated role "role1" doesn't contain the key.
        self.assertNotIn(key.keyid, targets.delegations.roles["role1"].keyids)
        self.assertIn(key.keyid, targets.delegations.roles["role2"].keyids)

        # Remove the key from "role2" as well
        targets.revoke_key(key.keyid, "role2")
        self.assertNotIn(key.keyid, targets.delegations.roles["role2"].keyids)

        # Try remove key not used by "role1"
        with self.assertRaises(ValueError):
            targets.revoke_key(key.keyid, "role1")

        # Try removing a key from delegated role that doesn't exists
        with self.assertRaises(ValueError):
            targets.revoke_key(key.keyid, "nosuchrole")

        # Remove delegations as a whole
        targets.delegations = None
        # Test that calling add_key and revoke_key throws an error
        # and that delegations is still None after each of the api calls
        with self.assertRaises(ValueError):
            targets.add_key(key, "role1")
        self.assertTrue(targets.delegations is None)
        with self.assertRaises(ValueError):
            targets.revoke_key(key.keyid, "role1")
        self.assertTrue(targets.delegations is None)

    def test_targets_key_api_with_succinct_roles(self) -> None:
        targets_path = os.path.join(self.repo_dir, "metadata", "targets.json")
        targets: Targets = Metadata[Targets].from_file(targets_path).signed
        key_dict = {
            "keytype": "ed25519",
            "keyval": {
                "public": "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"
            },
            "scheme": "ed25519",
        }
        key = Key.from_dict("id2", key_dict)

        # Remove delegated roles.
        assert targets.delegations is not None
        assert targets.delegations.roles is not None
        targets.delegations.roles = None
        targets.delegations.keys = {}

        # Add succinct_roles information.
        targets.delegations.succinct_roles = SuccinctRoles([], 1, 8, "foo")
        self.assertEqual(len(targets.delegations.keys), 0)
        self.assertEqual(len(targets.delegations.succinct_roles.keyids), 0)

        # Add a key to succinct_roles and verify it's saved.
        targets.add_key(key)
        self.assertIn(key.keyid, targets.delegations.keys)
        self.assertIn(key.keyid, targets.delegations.succinct_roles.keyids)
        self.assertEqual(len(targets.delegations.keys), 1)

        # Try adding the same key again and verify that noting is added.
        targets.add_key(key)
        self.assertEqual(len(targets.delegations.keys), 1)

        # Remove the key and verify it's not stored anymore.
        targets.revoke_key(key.keyid)
        self.assertNotIn(key.keyid, targets.delegations.keys)
        self.assertNotIn(key.keyid, targets.delegations.succinct_roles.keyids)
        self.assertEqual(len(targets.delegations.keys), 0)

        # Try removing it again.
        with self.assertRaises(ValueError):
            targets.revoke_key(key.keyid)

    def test_length_and_hash_validation(self) -> None:

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
            with self.assertRaises(exceptions.LengthOrHashMismatchError):
                snapshot_metafile.verify_length_and_hashes(data)

            snapshot_metafile.length = expected_length
            snapshot_metafile.hashes = {"sha256": "incorrecthash"}
            with self.assertRaises(exceptions.LengthOrHashMismatchError):
                snapshot_metafile.verify_length_and_hashes(data)

            snapshot_metafile.hashes = {
                "unsupported-alg": "8f88e2ba48b412c3843e9bb26e1b6f8fc9e98aceb0fbaa97ba37b4c98717d7ab"
            }
            with self.assertRaises(exceptions.LengthOrHashMismatchError):
                snapshot_metafile.verify_length_and_hashes(data)

            # Test wrong algorithm format (sslib.FormatError)
            snapshot_metafile.hashes = {
                256: "8f88e2ba48b412c3843e9bb26e1b6f8fc9e98aceb0fbaa97ba37b4c98717d7ab"  # type: ignore[dict-item]
            }
            with self.assertRaises(exceptions.LengthOrHashMismatchError):
                snapshot_metafile.verify_length_and_hashes(data)

            # test optional length and hashes
            snapshot_metafile.length = None
            snapshot_metafile.hashes = None
            snapshot_metafile.verify_length_and_hashes(data)

        # Test target files' hash and length verification
        targets_path = os.path.join(self.repo_dir, "metadata", "targets.json")
        targets = Metadata[Targets].from_file(targets_path)
        file1_targetfile = targets.signed.targets["file1.txt"]
        filepath = os.path.join(self.repo_dir, Targets.type, "file1.txt")

        with open(filepath, "rb") as file1:
            file1_targetfile.verify_length_and_hashes(file1)

            # test exceptions
            expected_length = file1_targetfile.length
            file1_targetfile.length = 2345
            with self.assertRaises(exceptions.LengthOrHashMismatchError):
                file1_targetfile.verify_length_and_hashes(file1)

            file1_targetfile.length = expected_length
            file1_targetfile.hashes = {"sha256": "incorrecthash"}
            with self.assertRaises(exceptions.LengthOrHashMismatchError):
                file1_targetfile.verify_length_and_hashes(file1)

    def test_targetfile_from_file(self) -> None:
        # Test with an existing file and valid hash algorithm
        file_path = os.path.join(self.repo_dir, Targets.type, "file1.txt")
        targetfile_from_file = TargetFile.from_file(
            file_path, file_path, ["sha256"]
        )

        with open(file_path, "rb") as file:
            targetfile_from_file.verify_length_and_hashes(file)

        # Test with a non-existing file
        file_path = os.path.join(self.repo_dir, Targets.type, "file123.txt")
        with self.assertRaises(FileNotFoundError):
            TargetFile.from_file(
                file_path, file_path, [sslib_hash.DEFAULT_HASH_ALGORITHM]
            )

        # Test with an unsupported algorithm
        file_path = os.path.join(self.repo_dir, Targets.type, "file1.txt")
        with self.assertRaises(ValueError):
            TargetFile.from_file(file_path, file_path, ["123"])

    def test_targetfile_custom(self) -> None:
        # Test creating TargetFile and accessing custom.
        targetfile = TargetFile(
            100, {"sha256": "abc"}, "file.txt", {"custom": "foo"}
        )
        self.assertEqual(targetfile.custom, "foo")

    def test_targetfile_from_data(self) -> None:
        data = b"Inline test content"
        target_file_path = os.path.join(
            self.repo_dir, Targets.type, "file1.txt"
        )

        # Test with a valid hash algorithm
        targetfile_from_data = TargetFile.from_data(
            target_file_path, data, ["sha256"]
        )
        targetfile_from_data.verify_length_and_hashes(data)

        # Test with no algorithms specified
        targetfile_from_data = TargetFile.from_data(target_file_path, data)
        targetfile_from_data.verify_length_and_hashes(data)

    def test_is_delegated_role(self) -> None:
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

    def test_is_delegated_role_in_succinct_roles(self) -> None:
        succinct_roles = SuccinctRoles([], 1, 5, "bin")
        false_role_name_examples = [
            "foo",
            "bin-",
            "bin-s",
            "bin-0t",
            "bin-20",
            "bin-100",
        ]
        for role_name in false_role_name_examples:
            msg = f"Error for {role_name}"
            self.assertFalse(succinct_roles.is_delegated_role(role_name), msg)

        # delegated role name suffixes are in hex format.
        true_name_examples = ["bin-00", "bin-0f", "bin-1f"]
        for role_name in true_name_examples:
            msg = f"Error for {role_name}"
            self.assertTrue(succinct_roles.is_delegated_role(role_name), msg)

    def test_get_roles_in_succinct_roles(self) -> None:
        succinct_roles = SuccinctRoles([], 1, 16, "bin")
        # bin names are in hex format and 4 hex digits are enough to represent
        # all bins between 0 and 2^16 - 1 meaning suffix_len must be 4
        expected_suffix_length = 4
        self.assertEqual(succinct_roles.suffix_len, expected_suffix_length)
        for bin_numer, role_name in enumerate(succinct_roles.get_roles()):
            # This adds zero-padding if the bin_numer is represented by a hex
            # number with a length less than expected_suffix_length.
            expected_bin_suffix = f"{bin_numer:0{expected_suffix_length}x}"
            self.assertEqual(role_name, f"bin-{expected_bin_suffix}")


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
