# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test __eq__ implementations of classes inside tuf/api/metadata.py."""

import copy
import os
import sys
import unittest
from typing import Any, ClassVar, Dict

from securesystemslib.signer import SSlibKey

from tests import utils
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Role,
    Signature,
    SuccinctRoles,
    TargetFile,
)


class TestMetadataComparisions(unittest.TestCase):
    """Test __eq__ for all classes inside tuf/api/metadata.py."""

    metadata: ClassVar[Dict[str, bytes]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_dir = os.path.join(
            utils.TESTS_DIR, "repository_data", "repository", "metadata"
        )

        # Store class instances in this dict instead of creating them inside the
        # test function in order to escape the need for reinitialization of the
        # instances on each run of the test function.
        cls.objects = {}
        for md in TOP_LEVEL_ROLE_NAMES:
            with open(os.path.join(cls.repo_dir, f"{md}.json"), "rb") as f:
                data = f.read()
                cls.objects[md.capitalize()] = Metadata.from_bytes(data).signed

        cls.objects["Metadata"] = Metadata(cls.objects["Timestamp"], {})
        cls.objects["Signed"] = cls.objects["Timestamp"]
        cls.objects["Key"] = SSlibKey(
            "id", "rsa", "rsassa-pss-sha256", {"public": "foo"}
        )
        cls.objects["Role"] = Role(["keyid1", "keyid2"], 3)
        cls.objects["MetaFile"] = MetaFile(1, 12, {"sha256": "abc"})
        cls.objects["DelegatedRole"] = DelegatedRole("a", [], 1, False, ["d"])
        cls.objects["SuccinctRoles"] = SuccinctRoles(["keyid"], 1, 8, "foo")
        cls.objects["Delegations"] = Delegations(
            {"keyid": cls.objects["Key"]}, {"a": cls.objects["DelegatedRole"]}
        )
        cls.objects["TargetFile"] = TargetFile(
            1, {"sha256": "abc"}, "file1.txt"
        )

    # Keys are class names.
    # Values are dictionaries containing attribute names and their new values.
    classes_attributes_modifications: utils.DataSet = {
        "Metadata": {"signed": None, "signatures": None},
        "Signed": {"version": -1, "spec_version": "0.0.0"},
        "Key": {"keyid": "a", "keytype": "foo", "scheme": "b", "keyval": "b"},
        "Role": {"keyids": [], "threshold": 10},
        "Root": {"consistent_snapshot": None, "keys": {}},
        "MetaFile": {"version": None, "length": None, "hashes": {}},
        "Timestamp": {"snapshot_meta": None},
        "Snapshot": {"meta": None},
        "DelegatedRole": {
            "name": "",
            "terminating": None,
            "paths": [""],
            "path_hash_prefixes": [""],
        },
        "SuccinctRoles": {"bit_length": 0, "name_prefix": ""},
        "Delegations": {"keys": {}, "roles": {}},
        "TargetFile": {"length": 0, "hashes": {}, "path": ""},
        "Targets": {"targets": {}, "delegations": []},
    }

    @utils.run_sub_tests_with_dataset(classes_attributes_modifications)
    def test_classes_eq_(self, test_case_data: Dict[str, Any]) -> None:
        obj = self.objects[self.case_name]

        # Assert that obj is not equal to an object from another type
        self.assertNotEqual(obj, "")
        obj_2 = copy.deepcopy(obj)
        # Assert that __eq__ works for equal objects.
        self.assertEqual(obj, obj_2)

        for attr, value in test_case_data.items():
            original_value = getattr(obj_2, attr)
            setattr(obj_2, attr, value)
            # Assert that the original object != modified one.
            self.assertNotEqual(obj, obj_2, f"Failed case: {attr}")
            # Restore the old value of the attribute.
            setattr(obj_2, attr, original_value)

    def test_md_eq_signatures_reversed_order(self) -> None:
        # Test comparing objects with same signatures but different order.

        # Remove all signatures and create new ones.
        md: Metadata = self.objects["Metadata"]
        md.signatures = {"a": Signature("a", "a"), "b": Signature("b", "b")}
        md_2 = copy.deepcopy(md)
        # Reverse signatures order in md_2.
        md_2.signatures = dict(reversed(md_2.signatures.items()))
        # Assert that both objects are not the same because of signatures order.
        self.assertNotEqual(md, md_2)

        # but if we fix the signatures order they will be equal
        md_2.signatures = {"a": Signature("a", "a"), "b": Signature("b", "b")}
        self.assertEqual(md, md_2)

    def test_md_eq_special_signatures_tests(self) -> None:
        # Test that metadata objects with different signatures are not equal.
        md: Metadata = self.objects["Metadata"]
        md_2 = copy.deepcopy(md)
        md_2.signatures = {}
        self.assertNotEqual(md, md_2)

        # Test that metadata objects with empty signatures are equal
        md.signatures = {}
        self.assertEqual(md, md_2)

        # Metadata objects with different signatures types are not equal.
        md_2.signatures = ""  # type: ignore[assignment]
        self.assertNotEqual(md, md_2)

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
        assert isinstance(delegations.roles, dict)
        delegations_2.roles = dict(reversed(delegations.roles.items()))

        # Both objects are not the equal because of delegated roles order.
        self.assertNotEqual(delegations, delegations_2)

        # but if we fix the delegated roles order they will be equal
        delegations_2.roles = delegations.roles

        self.assertEqual(delegations, delegations_2)


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
