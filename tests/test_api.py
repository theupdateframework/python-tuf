# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests for api/metadata.py"""

import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
from copy import copy, deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar, Dict, Optional

from securesystemslib import exceptions as sslib_exceptions
from securesystemslib import hash as sslib_hash
from securesystemslib.signer import (
    CryptoSigner,
    Key,
    SecretsHandler,
    Signer,
)

from tests import utils
from tuf.api import exceptions
from tuf.api.dsse import SimpleEnvelope
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    RootVerificationResult,
    Signature,
    Snapshot,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
    VerificationResult,
)
from tuf.api.serialization import DeserializationError, SerializationError
from tuf.api.serialization.json import JSONSerializer

logger = logging.getLogger(__name__)


class TestMetadata(unittest.TestCase):
    """Tests for public API of all classes in 'tuf/api/metadata.py'."""

    temporary_directory: ClassVar[str]
    repo_dir: ClassVar[str]
    keystore_dir: ClassVar[str]
    signers: ClassVar[Dict[str, Signer]]

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

        path = os.path.join(cls.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(path).signed

        # Load signers

        cls.signers = {}
        for role in [Snapshot.type, Targets.type, Timestamp.type]:
            uri = f"file2:{os.path.join(cls.keystore_dir, role + '_key')}"
            role_obj = root.get_delegated_role(role)
            key = root.get_key(role_obj.keyids[0])
            cls.signers[role] = CryptoSigner.from_priv_key_uri(uri, key)

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
        path = os.path.join(self.repo_dir, "metadata")
        root = Metadata[Root].from_file(os.path.join(path, "root.json")).signed

        # Locate the public keys we need from root
        targets_keyid = next(iter(root.roles[Targets.type].keyids))
        targets_key = root.keys[targets_keyid]
        snapshot_keyid = next(iter(root.roles[Snapshot.type].keyids))
        snapshot_key = root.keys[snapshot_keyid]
        timestamp_keyid = next(iter(root.roles[Timestamp.type].keyids))
        timestamp_key = root.keys[timestamp_keyid]

        # Load sample metadata (targets) and assert ...
        md_obj = Metadata.from_file(os.path.join(path, "targets.json"))
        sig = md_obj.signatures[targets_keyid]
        data = md_obj.signed_bytes

        # ... it has a single existing signature,
        self.assertEqual(len(md_obj.signatures), 1)
        # ... which is valid for the correct key.
        targets_key.verify_signature(sig, data)
        with self.assertRaises(sslib_exceptions.VerificationError):
            snapshot_key.verify_signature(sig, data)

        # Append a new signature with the unrelated key and assert that ...
        snapshot_sig = md_obj.sign(self.signers[Snapshot.type], append=True)
        # ... there are now two signatures, and
        self.assertEqual(len(md_obj.signatures), 2)
        # ... both are valid for the corresponding keys.
        targets_key.verify_signature(sig, data)
        snapshot_key.verify_signature(snapshot_sig, data)
        # ... the returned (appended) signature is for snapshot key
        self.assertEqual(snapshot_sig.keyid, snapshot_keyid)

        # Create and assign (don't append) a new signature and assert that ...
        ts_sig = md_obj.sign(self.signers[Timestamp.type], append=False)
        # ... there now is only one signature,
        self.assertEqual(len(md_obj.signatures), 1)
        # ... valid for that key.
        timestamp_key.verify_signature(ts_sig, data)
        with self.assertRaises(sslib_exceptions.VerificationError):
            targets_key.verify_signature(ts_sig, data)

    def test_sign_failures(self) -> None:
        # Test throwing UnsignedMetadataError because of signing problems
        md = Metadata.from_file(
            os.path.join(self.repo_dir, "metadata", "snapshot.json")
        )

        class FailingSigner(Signer):
            @classmethod
            def from_priv_key_uri(
                cls,
                priv_key_uri: str,
                public_key: Key,
                secrets_handler: Optional[SecretsHandler] = None,
            ) -> "Signer":
                pass

            @property
            def public_key(self) -> Key:
                raise RuntimeError("Not a real signer")

            def sign(self, _payload: bytes) -> Signature:
                raise RuntimeError("signing failed")

        failing_signer = FailingSigner()

        with self.assertRaises(exceptions.UnsignedMetadataError):
            md.sign(failing_signer)

    def test_key_verify_failures(self) -> None:
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path).signed

        # Locate the timestamp public key we need from root
        timestamp_keyid = next(iter(root.roles[Timestamp.type].keyids))
        timestamp_key = root.keys[timestamp_keyid]

        # Load sample metadata (timestamp)
        path = os.path.join(self.repo_dir, "metadata", "timestamp.json")
        md_obj = Metadata.from_file(path)
        sig = md_obj.signatures[timestamp_keyid]
        data = md_obj.signed_bytes

        # Test failure on unknown scheme (securesystemslib
        # UnsupportedAlgorithmError)
        scheme = timestamp_key.scheme
        timestamp_key.scheme = "foo"
        with self.assertRaises(sslib_exceptions.VerificationError):
            timestamp_key.verify_signature(sig, data)
        timestamp_key.scheme = scheme

        # Test failure on broken public key data (securesystemslib
        # CryptoError)
        public = timestamp_key.keyval["public"]
        timestamp_key.keyval["public"] = "ffff"
        with self.assertRaises(sslib_exceptions.VerificationError):
            timestamp_key.verify_signature(sig, data)
        timestamp_key.keyval["public"] = public

        # Test failure with invalid signature (securesystemslib
        # FormatError)
        incorrect_sig = copy(sig)
        incorrect_sig.signature = "foo"
        with self.assertRaises(sslib_exceptions.VerificationError):
            timestamp_key.verify_signature(incorrect_sig, data)

        # Test failure with valid but incorrect signature
        incorrect_sig.signature = "ff" * 64
        with self.assertRaises(sslib_exceptions.UnverifiedSignatureError):
            timestamp_key.verify_signature(incorrect_sig, data)

    def test_metadata_signed_is_expired(self) -> None:
        # Use of Snapshot is arbitrary, we're just testing the base class
        # features with real data
        snapshot_path = os.path.join(self.repo_dir, "metadata", "snapshot.json")
        md = Metadata.from_file(snapshot_path)

        expected_expiry = datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(md.signed.expires, expected_expiry)

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
        md.signed.expires = datetime.now(timezone.utc)
        is_expired = md.signed.is_expired()
        self.assertTrue(is_expired)
        md.signed.expires = datetime.now(timezone.utc) + timedelta(days=1)
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

    def test_signed_verify_delegate(self) -> None:
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root_md = Metadata[Root].from_file(root_path)
        root = root_md.signed
        snapshot_path = os.path.join(self.repo_dir, "metadata", "snapshot.json")
        snapshot_md = Metadata[Snapshot].from_file(snapshot_path)
        snapshot = snapshot_md.signed
        targets_path = os.path.join(self.repo_dir, "metadata", "targets.json")
        targets_md = Metadata[Targets].from_file(targets_path)
        targets = targets_md.signed
        role1_path = os.path.join(self.repo_dir, "metadata", "role1.json")
        role1_md = Metadata[Targets].from_file(role1_path)
        role1 = role1_md.signed
        role2_path = os.path.join(self.repo_dir, "metadata", "role2.json")
        role2_md = Metadata[Targets].from_file(role2_path)
        role2 = role2_md.signed

        # test the expected delegation tree
        root.verify_delegate(
            Root.type, root_md.signed_bytes, root_md.signatures
        )
        root.verify_delegate(
            Snapshot.type, snapshot_md.signed_bytes, snapshot_md.signatures
        )
        root.verify_delegate(
            Targets.type, targets_md.signed_bytes, targets_md.signatures
        )
        targets.verify_delegate(
            "role1", role1_md.signed_bytes, role1_md.signatures
        )
        role1.verify_delegate(
            "role2", role2_md.signed_bytes, role2_md.signatures
        )

        # only root and targets can verify delegates
        with self.assertRaises(AttributeError):
            snapshot.verify_delegate(
                Snapshot.type, snapshot_md.signed_bytes, snapshot_md.signatures
            )
        # verify fails for roles that are not delegated by delegator
        with self.assertRaises(ValueError):
            root.verify_delegate(
                "role1", role1_md.signed_bytes, role1_md.signatures
            )
        with self.assertRaises(ValueError):
            targets.verify_delegate(
                Targets.type, targets_md.signed_bytes, targets_md.signatures
            )
        # verify fails when delegator has no delegations
        with self.assertRaises(ValueError):
            role2.verify_delegate(
                "role1", role1_md.signed_bytes, role1_md.signatures
            )

        # verify fails when delegate content is modified
        expires = snapshot.expires
        snapshot.expires = expires + timedelta(days=1)
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate(
                Snapshot.type, snapshot_md.signed_bytes, snapshot_md.signatures
            )
        snapshot.expires = expires

        # verify fails if sslib verify fails with VerificationError
        # (in this case signature is malformed)
        keyid = next(iter(root.roles[Snapshot.type].keyids))
        good_sig = snapshot_md.signatures[keyid].signature
        snapshot_md.signatures[keyid].signature = "foo"
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate(
                Snapshot.type, snapshot_md.signed_bytes, snapshot_md.signatures
            )
        snapshot_md.signatures[keyid].signature = good_sig

        # verify fails if roles keys do not sign the metadata
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate(
                Timestamp.type, snapshot_md.signed_bytes, snapshot_md.signatures
            )

        # Add a key to snapshot role, make sure the new sig fails to verify
        ts_keyid = next(iter(root.roles[Timestamp.type].keyids))
        root.add_key(root.keys[ts_keyid], Snapshot.type)
        snapshot_md.signatures[ts_keyid] = Signature(ts_keyid, "ff" * 64)

        # verify succeeds if threshold is reached even if some signatures
        # fail to verify
        root.verify_delegate(
            Snapshot.type, snapshot_md.signed_bytes, snapshot_md.signatures
        )

        # verify fails if threshold of signatures is not reached
        root.roles[Snapshot.type].threshold = 2
        with self.assertRaises(exceptions.UnsignedMetadataError):
            root.verify_delegate(
                Snapshot.type, snapshot_md.signed_bytes, snapshot_md.signatures
            )

        # verify succeeds when we correct the new signature and reach the
        # threshold of 2 keys
        snapshot_md.sign(self.signers[Timestamp.type], append=True)
        root.verify_delegate(
            Snapshot.type, snapshot_md.signed_bytes, snapshot_md.signatures
        )

    def test_verification_result(self) -> None:
        vr = VerificationResult(3, {"a": None}, {"b": None})
        self.assertEqual(vr.missing, 2)
        self.assertFalse(vr.verified)
        self.assertFalse(vr)

        # Add a signature
        vr.signed["c"] = None
        self.assertEqual(vr.missing, 1)
        self.assertFalse(vr.verified)
        self.assertFalse(vr)

        # Add last missing signature
        vr.signed["d"] = None
        self.assertEqual(vr.missing, 0)
        self.assertTrue(vr.verified)
        self.assertTrue(vr)

        # Add one more signature
        vr.signed["e"] = None
        self.assertEqual(vr.missing, 0)
        self.assertTrue(vr.verified)
        self.assertTrue(vr)

    def test_root_verification_result(self) -> None:
        vr1 = VerificationResult(3, {"a": None}, {"b": None})
        vr2 = VerificationResult(1, {"c": None}, {"b": None})

        vr = RootVerificationResult(vr1, vr2)
        self.assertEqual(vr.signed, {"a": None, "c": None})
        self.assertEqual(vr.unsigned, {"b": None})
        self.assertFalse(vr.verified)
        self.assertFalse(vr)

        vr1.signed["c"] = None
        vr1.signed["f"] = None
        self.assertEqual(vr.signed, {"a": None, "c": None, "f": None})
        self.assertEqual(vr.unsigned, {"b": None})
        self.assertTrue(vr.verified)
        self.assertTrue(vr)

    def test_signed_get_verification_result(self) -> None:
        # Setup: Load test metadata and keys
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path)

        key1_id = root.signed.roles[Root.type].keyids[0]
        key1 = root.signed.get_key(key1_id)

        key2_id = root.signed.roles[Timestamp.type].keyids[0]
        key2 = root.signed.get_key(key2_id)

        key3_id = "123456789abcdefg"

        key4_id = self.signers[Snapshot.type].public_key.keyid

        # Test: 1 authorized key, 1 valid signature
        result = root.signed.get_verification_result(
            Root.type, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key1_id: key1})
        self.assertEqual(result.unsigned, {})

        # Test: 2 authorized keys, 1 invalid signature
        # Adding a key, i.e. metadata change, invalidates existing signature
        root.signed.add_key(key2, Root.type)
        result = root.signed.get_verification_result(
            Root.type, root.signed_bytes, root.signatures
        )
        self.assertFalse(result)
        self.assertEqual(result.signed, {})
        self.assertEqual(result.unsigned, {key1_id: key1, key2_id: key2})

        # Test: 3 authorized keys, 1 invalid signature, 1 key missing key data
        # Adding a keyid w/o key, fails verification but this key is not listed
        # in unsigned
        root.signed.roles[Root.type].keyids.append(key3_id)
        result = root.signed.get_verification_result(
            Root.type, root.signed_bytes, root.signatures
        )
        self.assertFalse(result)
        self.assertEqual(result.signed, {})
        self.assertEqual(result.unsigned, {key1_id: key1, key2_id: key2})

        # Test: 3 authorized keys, 1 valid signature, 1 invalid signature, 1
        # key missing key data
        root.sign(self.signers[Timestamp.type], append=True)
        result = root.signed.get_verification_result(
            Root.type, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key2_id: key2})
        self.assertEqual(result.unsigned, {key1_id: key1})

        # Test: 3 authorized keys, 1 valid signature, 1 invalid signature, 1
        # key missing key data, 1 ignored unrelated signature
        root.sign(self.signers[Snapshot.type], append=True)
        self.assertEqual(
            set(root.signatures.keys()), {key1_id, key2_id, key4_id}
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key2_id: key2})
        self.assertEqual(result.unsigned, {key1_id: key1})

        # See test_signed_verify_delegate for more related tests ...

    def test_root_get_root_verification_result(self) -> None:
        # Setup: Load test metadata and keys
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path)

        key1_id = root.signed.roles[Root.type].keyids[0]
        key1 = root.signed.get_key(key1_id)

        key2_id = root.signed.roles[Timestamp.type].keyids[0]
        key2 = root.signed.get_key(key2_id)

        # Test: Verify with no previous root version
        result = root.signed.get_root_verification_result(
            None, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key1_id: key1})
        self.assertEqual(result.unsigned, {})

        # Test: Verify with other root that is not version N-1
        prev_root: Metadata[Root] = deepcopy(root)
        with self.assertRaises(ValueError):
            result = root.signed.get_root_verification_result(
                prev_root.signed, root.signed_bytes, root.signatures
            )

        # Test: Verify with previous root
        prev_root.signed.version -= 1
        result = root.signed.get_root_verification_result(
            prev_root.signed, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key1_id: key1})
        self.assertEqual(result.unsigned, {})

        # Test: Add a signer to previous root (threshold still 1)
        prev_root.signed.add_key(key2, Root.type)
        result = root.signed.get_root_verification_result(
            prev_root.signed, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key1_id: key1})
        self.assertEqual(result.unsigned, {key2_id: key2})

        # Test: Increase threshold in previous root
        prev_root.signed.roles[Root.type].threshold += 1
        result = root.signed.get_root_verification_result(
            prev_root.signed, root.signed_bytes, root.signatures
        )
        self.assertFalse(result)
        self.assertEqual(result.signed, {key1_id: key1})
        self.assertEqual(result.unsigned, {key2_id: key2})

        # Test: Sign root with both keys
        root.sign(self.signers[Timestamp.type], append=True)
        result = root.signed.get_root_verification_result(
            prev_root.signed, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key1_id: key1, key2_id: key2})
        self.assertEqual(result.unsigned, {})

        # Test: Sign root with an unrelated key
        root.sign(self.signers[Snapshot.type], append=True)
        result = root.signed.get_root_verification_result(
            prev_root.signed, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key1_id: key1, key2_id: key2})
        self.assertEqual(result.unsigned, {})

        # Test: Remove key1 from previous root
        prev_root.signed.revoke_key(key1_id, Root.type)
        result = root.signed.get_root_verification_result(
            prev_root.signed, root.signed_bytes, root.signatures
        )
        self.assertFalse(result)
        self.assertEqual(result.signed, {key1_id: key1, key2_id: key2})
        self.assertEqual(result.unsigned, {})

        # Test: Lower threshold in previous root
        prev_root.signed.roles[Root.type].threshold -= 1
        result = root.signed.get_root_verification_result(
            prev_root.signed, root.signed_bytes, root.signatures
        )
        self.assertTrue(result)
        self.assertEqual(result.signed, {key1_id: key1, key2_id: key2})
        self.assertEqual(result.unsigned, {})

    def test_root_add_key_and_revoke_key(self) -> None:
        root_path = os.path.join(self.repo_dir, "metadata", "root.json")
        root = Metadata[Root].from_file(root_path)

        # Create a new key
        signer = CryptoSigner.generate_ecdsa()
        key = signer.public_key

        # Assert that root does not contain the new key
        self.assertNotIn(key.keyid, root.signed.roles[Root.type].keyids)
        self.assertNotIn(key.keyid, root.signed.keys)

        # Assert that add_key with old argument order will raise an error
        with self.assertRaises(ValueError):
            root.signed.add_key(Root.type, key)

        # Add new root key
        root.signed.add_key(key, Root.type)

        # Assert that key is added
        self.assertIn(key.keyid, root.signed.roles[Root.type].keyids)
        self.assertIn(key.keyid, root.signed.keys)

        # Confirm that the newly added key does not break
        # the object serialization
        root.to_dict()

        # Try adding the same key again and assert its ignored.
        pre_add_keyid = root.signed.roles[Root.type].keyids.copy()
        root.signed.add_key(key, Root.type)
        self.assertEqual(pre_add_keyid, root.signed.roles[Root.type].keyids)

        # Add the same key to targets role as well
        root.signed.add_key(key, Targets.type)

        # Add the same key to a nonexistent role.
        with self.assertRaises(ValueError):
            root.signed.add_key(key, "nosuchrole")

        # Remove the key from root role (targets role still uses it)
        root.signed.revoke_key(key.keyid, Root.type)
        self.assertNotIn(key.keyid, root.signed.roles[Root.type].keyids)
        self.assertIn(key.keyid, root.signed.keys)

        # Remove the key from targets as well
        root.signed.revoke_key(key.keyid, Targets.type)
        self.assertNotIn(key.keyid, root.signed.roles[Targets.type].keyids)
        self.assertNotIn(key.keyid, root.signed.keys)

        with self.assertRaises(ValueError):
            root.signed.revoke_key("nosuchkey", Root.type)
        with self.assertRaises(ValueError):
            root.signed.revoke_key(key.keyid, "nosuchrole")

    def test_is_target_in_pathpattern(self) -> None:
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
            targets.add_key("role1", key)

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

    def test_metafile_from_data(self) -> None:
        data = b"Inline test content"

        # Test with a valid hash algorithm
        metafile = MetaFile.from_data(1, data, ["sha256"])
        metafile.verify_length_and_hashes(data)

        # Test with an invalid hash algorithm
        with self.assertRaises(ValueError):
            metafile = MetaFile.from_data(1, data, ["invalid_algorithm"])
            metafile.verify_length_and_hashes(data)

        self.assertEqual(
            metafile,
            MetaFile(
                1,
                19,
                {
                    "sha256": "fcee2e6d56ab08eab279016f7db7e4e1d172ccea78e15f4cf8bd939991a418fa"
                },
            ),
        )

    def test_targetfile_get_prefixed_paths(self) -> None:
        target = TargetFile(100, {"sha256": "abc", "md5": "def"}, "a/b/f.ext")
        self.assertEqual(
            target.get_prefixed_paths(), ["a/b/abc.f.ext", "a/b/def.f.ext"]
        )

        target = TargetFile(100, {"sha256": "abc", "md5": "def"}, "")
        self.assertEqual(target.get_prefixed_paths(), ["abc.", "def."])

        target = TargetFile(100, {"sha256": "abc", "md5": "def"}, "a/b/")
        self.assertEqual(target.get_prefixed_paths(), ["a/b/abc.", "a/b/def."])

        target = TargetFile(100, {"sha256": "abc", "md5": "def"}, "f.ext")
        self.assertEqual(
            target.get_prefixed_paths(), ["abc.f.ext", "def.f.ext"]
        )

        target = TargetFile(100, {"sha256": "abc", "md5": "def"}, "a/b/.ext")
        self.assertEqual(
            target.get_prefixed_paths(), ["a/b/abc..ext", "a/b/def..ext"]
        )

        target = TargetFile(100, {"sha256": "abc"}, "/root/file.ext")
        self.assertEqual(target.get_prefixed_paths(), ["/root/abc.file.ext"])

        target = TargetFile(100, {"sha256": "abc"}, "/")
        self.assertEqual(target.get_prefixed_paths(), ["/abc."])

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

    def test_delegations_get_delegated_role(self) -> None:
        delegations = Delegations({}, {})
        targets = Targets(delegations=delegations)

        with self.assertRaises(ValueError):
            targets.get_delegated_role("abc")

        # test "normal" delegated role (path or path_hash_prefix)
        role = DelegatedRole("delegated", [], 1, False, [])
        delegations.roles = {"delegated": role}
        with self.assertRaises(ValueError):
            targets.get_delegated_role("not-delegated")
        self.assertEqual(targets.get_delegated_role("delegated"), role)
        delegations.roles = None

        # test succinct delegation
        bit_len = 3
        role2 = SuccinctRoles([], 1, bit_len, "prefix")
        delegations.succinct_roles = role2
        for name in ["prefix-", "prefix--1", f"prefix-{2**bit_len:0x}"]:
            with self.assertRaises(ValueError, msg=f"role name '{name}'"):
                targets.get_delegated_role(name)
        for i in range(2**bit_len):
            self.assertEqual(
                targets.get_delegated_role(f"prefix-{i:0x}"), role2
            )


class TestSimpleEnvelope(unittest.TestCase):
    """Tests for public API in 'tuf/api/dsse.py'."""

    @classmethod
    def setUpClass(cls) -> None:
        repo_data_dir = Path(utils.TESTS_DIR) / "repository_data"
        cls.metadata_dir = repo_data_dir / "repository" / "metadata"
        cls.keystore_dir = repo_data_dir / "keystore"
        cls.signers = {}
        root_path = os.path.join(cls.metadata_dir, "root.json")
        root: Root = Metadata.from_file(root_path).signed

        for role in [Snapshot, Targets, Timestamp]:
            uri = f"file2:{os.path.join(cls.keystore_dir, role.type + '_key')}"
            role_obj = root.get_delegated_role(role.type)
            key = root.get_key(role_obj.keyids[0])
            cls.signers[role.type] = CryptoSigner.from_priv_key_uri(uri, key)

    def test_serialization(self) -> None:
        """Basic de/serialization test.

        1. Load test metadata for each role
        2. Wrap metadata payloads in envelope serializing the payload
        3. Serialize envelope
        4. De-serialize envelope
        5. De-serialize payload

        """
        for role in [Root, Timestamp, Snapshot, Targets]:
            metadata_path = self.metadata_dir / f"{role.type}.json"
            metadata = Metadata.from_file(str(metadata_path))
            self.assertIsInstance(metadata.signed, role)

            envelope = SimpleEnvelope.from_signed(metadata.signed)
            envelope_bytes = envelope.to_bytes()

            envelope2 = SimpleEnvelope.from_bytes(envelope_bytes)
            payload = envelope2.get_signed()
            self.assertEqual(metadata.signed, payload)

    def test_fail_envelope_serialization(self) -> None:
        envelope = SimpleEnvelope(b"foo", "bar", ["baz"])
        with self.assertRaises(SerializationError):
            envelope.to_bytes()

    def test_fail_envelope_deserialization(self) -> None:
        with self.assertRaises(DeserializationError):
            SimpleEnvelope.from_bytes(b"[")

    def test_fail_payload_serialization(self) -> None:
        with self.assertRaises(SerializationError):
            SimpleEnvelope.from_signed("foo")  # type: ignore[type-var]

    def test_fail_payload_deserialization(self) -> None:
        payloads = [b"[", b'{"_type": "foo"}']
        for payload in payloads:
            envelope = SimpleEnvelope(payload, "bar", [])
            with self.assertRaises(DeserializationError):
                envelope.get_signed()

    def test_verify_delegate(self) -> None:
        """Basic verification test.

        1. Load test metadata for each role
        2. Wrap non-root payloads in envelope serializing the payload
        3. Sign with correct delegated key
        4. Verify delegate with root

        """
        root_path = self.metadata_dir / "root.json"
        root = Metadata[Root].from_file(str(root_path)).signed

        for role in [Timestamp, Snapshot, Targets]:
            metadata_path = self.metadata_dir / f"{role.type}.json"
            metadata = Metadata.from_file(str(metadata_path))
            self.assertIsInstance(metadata.signed, role)

            signer = self.signers[role.type]
            self.assertIn(signer.public_key.keyid, root.roles[role.type].keyids)

            envelope = SimpleEnvelope.from_signed(metadata.signed)
            envelope.sign(signer)
            self.assertTrue(len(envelope.signatures) == 1)

            root.verify_delegate(role.type, envelope.pae(), envelope.signatures)


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
