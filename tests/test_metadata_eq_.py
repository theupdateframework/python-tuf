#!/usr/bin/env python

# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test __eq__ implementations of classes inside tuf/api/metadata.py."""


import copy
import os
import sys
import unittest
from typing import Any, ClassVar, Dict

from securesystemslib.signer import Signature

from tests import utils
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)


class TestMetadataComparisions(unittest.TestCase):
    """Test __eq__ for all classes inside tuf/api/metadata.py."""

    metadata: ClassVar[Dict[str, bytes]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_dir = os.path.join(
            utils.TESTS_DIR, "repository_data", "repository", "metadata"
        )
        cls.metadata = {}
        for md in TOP_LEVEL_ROLE_NAMES:
            with open(os.path.join(cls.repo_dir, f"{md}.json"), "rb") as f:
                cls.metadata[md] = f.read()

    def copy_and_simple_assert(self, obj: Any) -> Any:
        # Assert that obj is not equal to an object from another type
        self.assertNotEqual(obj, "")
        result_obj = copy.deepcopy(obj)
        # Assert that __eq__ works for equal objects.
        self.assertEqual(obj, result_obj)
        return result_obj

    def test_metadata_eq_(self) -> None:
        md = Metadata.from_bytes(self.metadata["snapshot"])
        md_2: Metadata = self.copy_and_simple_assert(md)

        for attr, value in [("signed", None), ("signatures", None)]:
            setattr(md_2, attr, value)
            self.assertNotEqual(md, md_2, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(md_2, attr, getattr(md, attr))

    def test_md_eq_signatures_reversed_order(self) -> None:
        # Test comparing objects with same signatures but different order.

        # Remove all signatures and create new ones.
        md = Metadata.from_bytes(self.metadata["snapshot"])
        md.signatures = {"a": Signature("a", "a"), "b": Signature("b", "b")}
        md_2 = copy.deepcopy(md)
        # Reverse signatures order in md_2.
        # In python3.7 we need to cast to a list and then reverse.
        md_2.signatures = dict(reversed(list(md_2.signatures.items())))
        # Assert that both objects are not the same because of signatures order.
        self.assertNotEqual(md, md_2)

        # but if we fix the signatures order they will be equal
        md_2.signatures = {"a": Signature("a", "a"), "b": Signature("b", "b")}
        self.assertEqual(md, md_2)

    def test_md_eq_special_signatures_tests(self) -> None:
        # Test that metadata objects with different signatures are not equal.
        md = Metadata.from_bytes(self.metadata["snapshot"])
        md_2 = copy.deepcopy(md)
        md_2.signatures = {}
        self.assertNotEqual(md, md_2)

        # Test that metadata objects with empty signatures are equal
        md.signatures = {}
        self.assertEqual(md, md_2)

        # Metadata objects with different signatures types are not equal.
        md_2.signatures = ""  # type: ignore
        self.assertNotEqual(md, md_2)

    def test_signed_eq_(self) -> None:
        md = Metadata.from_bytes(self.metadata["snapshot"])
        md_2: Metadata = self.copy_and_simple_assert(md)

        # We don't need to make "signed" = None as that was done when testing
        # metadata attribute modifications.
        for attr, value in [("version", -1), ("spec_version", "0.0.0")]:
            setattr(md_2.signed, attr, value)
            self.assertNotEqual(md.signed, md_2.signed, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(md_2.signed, attr, getattr(md.signed, attr))

    def test_key_eq_(self) -> None:
        key_dict = {
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyval": {"public": "foo"},
        }
        key = Key.from_dict("12sa12", key_dict)
        key_2: Key = self.copy_and_simple_assert(key)
        for attr, value in [
            ("keyid", "a"),
            ("keytype", "foo"),
            ("scheme", "b"),
            ("keytype", "b"),
        ]:
            setattr(key_2, attr, value)
            self.assertNotEqual(key, key_2, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(key_2, attr, getattr(key, attr))

    def test_role_eq_(self) -> None:
        role_dict = {
            "keyids": ["keyid1", "keyid2"],
            "threshold": 3,
        }
        role = Role.from_dict(role_dict)
        role_2: Role = self.copy_and_simple_assert(role)

        for attr, value in [("keyids", []), ("threshold", 10)]:
            setattr(role_2, attr, value)
            self.assertNotEqual(role, role_2, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(role_2, attr, getattr(role, attr))

    def test_root_eq_(self) -> None:
        md = Metadata.from_bytes(self.metadata["root"])
        signed_copy: Root = self.copy_and_simple_assert(md.signed)

        # Common attributes between Signed and Root doesn't need testing.
        # Ignore mypy request for type annotations on attr and value
        for attr, value in [  # type: ignore
            ("consistent_snapshot", None),
            ("keys", {}),
            ("roles", {}),
        ]:

            setattr(signed_copy, attr, value)
            self.assertNotEqual(md.signed, signed_copy, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(signed_copy, attr, getattr(md.signed, attr))

    def test_metafile_eq_(self) -> None:
        metafile_dict = {
            "version": 1,
            "length": 12,
            "hashes": {"sha256": "abc"},
        }
        metafile = MetaFile.from_dict(metafile_dict)
        metafile_2: MetaFile = self.copy_and_simple_assert(metafile)

        # Ignore mypy request for type annotations on attr and value
        for attr, value in [  # type: ignore
            ("version", None),
            ("length", None),
            ("hashes", {}),
        ]:
            setattr(metafile_2, attr, value)
            self.assertNotEqual(metafile, metafile_2, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(metafile_2, attr, getattr(metafile, attr))

    def test_timestamp_eq_(self) -> None:
        md = Metadata.from_bytes(self.metadata["timestamp"])
        signed_copy: Timestamp = self.copy_and_simple_assert(md.signed)

        # Common attributes between Signed and Timestamp doesn't need testing.
        setattr(signed_copy, "snapshot_meta", None)
        self.assertNotEqual(md.signed, signed_copy)

    def test_snapshot_eq_(self) -> None:
        md = Metadata.from_bytes(self.metadata["snapshot"])
        signed_copy: Snapshot = self.copy_and_simple_assert(md.signed)

        # Common attributes between Signed and Snapshot doesn't need testing.
        setattr(signed_copy, "meta", None)
        self.assertNotEqual(md.signed, signed_copy)

    def test_delegated_role_eq_(self) -> None:
        delegated_role_dict = {
            "keyids": ["keyid"],
            "name": "a",
            "terminating": False,
            "threshold": 1,
            "paths": ["fn1", "fn2"],
        }
        delegated_role = DelegatedRole.from_dict(delegated_role_dict)
        delegated_role_2: DelegatedRole = self.copy_and_simple_assert(
            delegated_role
        )

        # Common attributes between DelegatedRole and Role doesn't need testing.
        for attr, value in [
            ("name", ""),
            ("terminating", None),
            ("paths", [""]),
            ("path_hash_prefixes", [""]),
        ]:
            setattr(delegated_role_2, attr, value)
            msg = f"Failed case: {attr}"
            self.assertNotEqual(delegated_role, delegated_role_2, msg)
            # Restore the old value of the attribute.
            setattr(delegated_role_2, attr, getattr(delegated_role, attr))

    def test_delegations_eq_(self) -> None:
        delegations_dict = {
            "keys": {
                "keyid2": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": "bar"},
                }
            },
            "roles": [
                {
                    "keyids": ["keyid2"],
                    "name": "b",
                    "terminating": True,
                    "paths": ["fn2"],
                    "threshold": 4,
                }
            ],
        }
        delegations = Delegations.from_dict(delegations_dict)
        delegations_2: Delegations = self.copy_and_simple_assert(delegations)
        # Ignore mypy request for type annotations on attr and value
        for attr, value in [("keys", {}), ("roles", {})]:  # type: ignore
            setattr(delegations_2, attr, value)
            msg = f"Failed case: {attr}"
            self.assertNotEqual(delegations, delegations_2, msg)
            # Restore the old value of the attribute.
            setattr(delegations_2, attr, getattr(delegations, attr))

    def test_targetfile_eq_(self) -> None:
        targetfile_dict = {
            "length": 12,
            "hashes": {"sha256": "abc"},
        }
        targetfile = TargetFile.from_dict(targetfile_dict, "file1.txt")
        targetfile_2: TargetFile = self.copy_and_simple_assert(targetfile)

        # Common attr between TargetFile and MetaFile doesn't need testing.
        setattr(targetfile_2, "path", "")
        self.assertNotEqual(targetfile, targetfile_2)

    def test_delegations_eq_roles_reversed_order(self) -> None:
        # Test comparing objects with same delegated roles but different order.
        role_one_dict = {
            "keyids": ["keyid1"],
            "name": "a",
            "terminating": False,
            "paths": ["fn1"],
            "threshold": 1,
        }
        role_two_dict = {
            "keyids": ["keyid2"],
            "name": "b",
            "terminating": True,
            "paths": ["fn2"],
            "threshold": 4,
        }

        delegations_dict = {
            "keys": {
                "keyid2": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": "bar"},
                }
            },
            "roles": [role_one_dict, role_two_dict],
        }
        delegations = Delegations.from_dict(copy.deepcopy(delegations_dict))

        # Create a second delegations obj with reversed roles order
        delegations_2 = copy.deepcopy(delegations)
        # In python3.7 we need to cast to a list and then reverse.
        delegations_2.roles = dict(reversed(list(delegations.roles.items())))

        # Both objects are not the equal because of delegated roles order.
        self.assertNotEqual(delegations, delegations_2)

        # but if we fix the delegated roles order they will be equal
        delegations_2.roles = delegations.roles

        self.assertEqual(delegations, delegations_2)

    def test_targets_eq_(self) -> None:
        md = Metadata.from_bytes(self.metadata["targets"])
        signed_copy: Targets = self.copy_and_simple_assert(md.signed)

        # Common attributes between Targets and Signed doesn't need testing.
        # Ignore mypy request for type annotations on attr and value
        for attr, value in [("targets", {}), ("delegations", [])]:  # type: ignore
            setattr(signed_copy, attr, value)
            self.assertNotEqual(md.signed, signed_copy, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(signed_copy, attr, getattr(md.signed, attr))


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
