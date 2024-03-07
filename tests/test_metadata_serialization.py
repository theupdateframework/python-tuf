# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests testing tuf/api/metadata.py classes
serialization and deserialization.

"""

import copy
import json
import logging
import sys
import unittest

from securesystemslib.signer import Signature

from tests import utils
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization import DeserializationError

logger = logging.getLogger(__name__)


class TestSerialization(unittest.TestCase):
    """Test serialization for all classes in 'tuf/api/metadata.py'."""

    invalid_metadata: utils.DataSet = {
        "no signatures field": b'{"signed": \
            { "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}} \
        }',
        "non unique duplicating signatures": b'{"signed": \
                { "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
                "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}}, \
            "signatures": [{"keyid": "id", "sig": "b"}, {"keyid": "id", "sig": "b"}] \
        }',
    }

    @utils.run_sub_tests_with_dataset(invalid_metadata)
    def test_invalid_metadata_serialization(self, test_data: bytes) -> None:
        # We expect a DeserializationError reraised from ValueError or KeyError.
        with self.assertRaises(DeserializationError):
            Metadata.from_bytes(test_data)

    valid_metadata: utils.DataSet = {
        "multiple signatures": b'{ \
            "signed": \
                { "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
                "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}}, \
            "signatures": [{ "keyid": "id", "sig": "b"}, {"keyid": "id2", "sig": "d" }] \
        }',
        "no signatures": b'{ \
            "signed": \
                { "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
                "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}}, \
            "signatures": [] \
        }',
        "unrecognized fields": b'{ \
            "signed": \
                { "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
                "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}}, \
            "signatures": [{"keyid": "id", "sig": "b"}], \
            "foo": "bar" \
        }',
    }

    @utils.run_sub_tests_with_dataset(valid_metadata)
    def test_valid_metadata_serialization(self, test_case_data: bytes) -> None:
        md = Metadata.from_bytes(test_case_data)

        # Convert to a JSON and sort the keys the way we do in JSONSerializer.
        separators = (",", ":")
        test_json = json.loads(test_case_data)
        test_bytes = json.dumps(
            test_json, separators=separators, sort_keys=True
        ).encode("utf-8")

        self.assertEqual(test_bytes, md.to_bytes())

    invalid_signatures: utils.DataSet = {
        "missing keyid attribute in a signature": '{ "sig": "abc" }',
        "missing sig attribute in a signature": '{ "keyid": "id" }',
    }

    @utils.run_sub_tests_with_dataset(invalid_signatures)
    def test_invalid_signature_serialization(self, test_data: str) -> None:
        case_dict = json.loads(test_data)
        with self.assertRaises(KeyError):
            Signature.from_dict(case_dict)

    valid_signatures: utils.DataSet = {
        "all": '{ "keyid": "id", "sig": "b"}',
        "unrecognized fields": '{ "keyid": "id", "sig": "b", "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_signatures)
    def test_signature_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        signature = Signature.from_dict(copy.copy(case_dict))
        self.assertEqual(case_dict, signature.to_dict())

    # Snapshot instances with meta = {} are valid, but for a full valid
    # repository it's required that meta has at least one element inside it.
    invalid_signed: utils.DataSet = {
        "no _type": '{"spec_version": "1.0.0", "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "no spec_version": '{"_type": "snapshot", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "no version": '{"_type": "snapshot", "spec_version": "1.0.0", "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "no expires": '{"_type": "snapshot", "spec_version": "1.0.0", "version": 1, "meta": {}}',
        "empty str _type": '{"_type": "", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "empty str spec_version": '{"_type": "snapshot", "spec_version": "", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "_type wrong type": '{"_type": "foo", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "version wrong type": '{"_type": "snapshot", "spec_version": "1.0.0", "version": "a", "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "invalid spec_version str": '{"_type": "snapshot", "spec_version": "abc", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "non-number spec_version": '{"_type": "snapshot", "spec_version": "1.2.a", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "one part spec_version": '{"_type": "snapshot", "spec_version": "1", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "different major spec_version": '{"_type": "snapshot", "spec_version": "0.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "version 0": '{"_type": "snapshot", "spec_version": "1.0.0", "version": 0, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "version below 0": '{"_type": "snapshot", "spec_version": "1.0.0", "version": -1, "expires": "2030-01-01T00:00:00Z", "meta": {}}',
        "wrong datetime string": '{"_type": "snapshot", "spec_version": "1.0.0", "version": 1, "expires": "abc", "meta": {}}',
    }

    @utils.run_sub_tests_with_dataset(invalid_signed)
    def test_invalid_signed_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises((KeyError, ValueError, TypeError)):
            Snapshot.from_dict(case_dict)

    valid_keys: utils.DataSet = {
        "all": '{"keytype": "rsa", "scheme": "rsassa-pss-sha256", \
            "keyval": {"public": "foo"}}',
        "unrecognized field": '{"keytype": "rsa", "scheme": "rsassa-pss-sha256", \
            "keyval": {"public": "foo"}, "foo": "bar"}',
        "unrecognized field in keyval": '{"keytype": "rsa", "scheme": "rsassa-pss-sha256", \
            "keyval": {"public": "foo", "foo": "bar"}}',
    }

    @utils.run_sub_tests_with_dataset(valid_keys)
    def test_valid_key_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        key = Key.from_dict("id", copy.copy(case_dict))
        self.assertDictEqual(case_dict, key.to_dict())

    invalid_keys: utils.DataSet = {
        "no keyid": '{"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "abc"}}',
        "no keytype": '{"keyid": "id", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}',
        "no scheme": '{"keyid": "id", "keytype": "rsa", "keyval": {"public": "foo"}}',
        "no keyval": '{"keyid": "id", "keytype": "rsa", "scheme": "rsassa-pss-sha256"}',
        "keyid wrong type": '{"keyid": 1, "keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "abc"}}',
        "keytype wrong type": '{"keyid": "id", "keytype": 1, "scheme": "rsassa-pss-sha256", "keyval": {"public": "abc"}}',
        "scheme wrong type": '{"keyid": "id", "keytype": "rsa", "scheme": 1, "keyval": {"public": "abc"}}',
        "keyval wrong type": '{"keyid": "id", "keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": 1}',
    }

    @utils.run_sub_tests_with_dataset(invalid_keys)
    def test_invalid_key_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises((TypeError, KeyError, ValueError)):
            keyid = case_dict.pop("keyid")
            Key.from_dict(keyid, case_dict)

    invalid_roles: utils.DataSet = {
        "no threshold": '{"keyids": ["keyid"]}',
        "no keyids": '{"threshold": 3}',
        "wrong threshold type": '{"keyids": ["keyid"], "threshold": "a"}',
        "wrong keyids type": '{"keyids": 1, "threshold": 3}',
        "threshold below 1": '{"keyids": ["keyid"], "threshold": 0}',
        "duplicate keyids": '{"keyids": ["keyid", "keyid"], "threshold": 3}',
    }

    @utils.run_sub_tests_with_dataset(invalid_roles)
    def test_invalid_role_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises((KeyError, TypeError, ValueError)):
            Role.from_dict(case_dict)

    valid_roles: utils.DataSet = {
        "all": '{"keyids": ["keyid"], "threshold": 3}',
        "many keyids": '{"keyids": ["a", "b", "c", "d", "e"], "threshold": 1}',
        "ordered keyids": '{"keyids": ["c", "b", "a"], "threshold": 1}',
        "empty keyids": '{"keyids": [], "threshold": 1}',
        "unrecognized field": '{"keyids": ["keyid"], "threshold": 3, "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_roles)
    def test_role_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        role = Role.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, role.to_dict())

    valid_roots: utils.DataSet = {
        "all": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": false, \
            "keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "roles": { \
                "root": {"keyids": ["keyid1"], "threshold": 1}, \
                "timestamp": {"keyids": ["keyid2"], "threshold": 1}, \
                "targets": {"keyids": ["keyid1"], "threshold": 1}, \
                "snapshot": {"keyids": ["keyid2"], "threshold": 1}} \
            }',
        "no consistent_snapshot": '{ "_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", \
            "keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"} }}, \
            "roles": { \
                "root": {"keyids": ["keyid"], "threshold": 1}, \
                "timestamp": {"keyids": ["keyid"], "threshold": 1}, \
                "targets": {"keyids": ["keyid"], "threshold": 1}, \
                "snapshot": {"keyids": ["keyid"], "threshold": 1}} \
            }',
        "empty keys": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": false, \
            "keys": {}, \
            "roles": { \
                "root": {"keyids": [], "threshold": 1}, \
                "timestamp": {"keyids": [], "threshold": 1}, \
                "targets": {"keyids": [], "threshold": 1}, \
                "snapshot": {"keyids": [], "threshold": 1}} \
            }',
        "unrecognized field": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": false, \
            "keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": { \
                "root": {"keyids": ["keyid"], "threshold": 1}, \
                "timestamp": {"keyids": ["keyid"], "threshold": 1}, \
                "targets": {"keyids": ["keyid"], "threshold": 1}, \
                "snapshot": {"keyids": ["keyid"], "threshold": 1} \
            }, \
            "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_roots)
    def test_root_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        root = Root.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, root.to_dict())

    invalid_roots: utils.DataSet = {
        "invalid role name": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": false, \
            "keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "roles": { \
                "bar": {"keyids": ["keyid1"], "threshold": 1}, \
                "timestamp": {"keyids": ["keyid2"], "threshold": 1}, \
                "targets": {"keyids": ["keyid1"], "threshold": 1}, \
                "snapshot": {"keyids": ["keyid2"], "threshold": 1}} \
            }',
        "missing root role": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": false, \
            "keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "roles": { \
                "timestamp": {"keyids": ["keyid2"], "threshold": 1}, \
                "targets": {"keyids": ["keyid1"], "threshold": 1}, \
                "snapshot": {"keyids": ["keyid2"], "threshold": 1}} \
            }',
        "one additional role": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": false, \
            "keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "roles": { \
                "root": {"keyids": ["keyid1"], "threshold": 1}, \
                "timestamp": {"keyids": ["keyid2"], "threshold": 1}, \
                "targets": {"keyids": ["keyid1"], "threshold": 1}, \
                "snapshot": {"keyids": ["keyid2"], "threshold": 1}, \
                "foo": {"keyids": ["keyid2"], "threshold": 1}} \
            }',
        "invalid expiry with microseconds": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T12:00:00.123456Z", "consistent_snapshot": false, \
            "keys": {}, "roles": {"root": {}, "timestamp": {}, "targets": {}, "snapshot": {}}}',
    }

    @utils.run_sub_tests_with_dataset(invalid_roots)
    def test_invalid_root_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises(ValueError):
            Root.from_dict(case_dict)

    invalid_metafiles: utils.DataSet = {
        "wrong length type": '{"version": 1, "length": "a", "hashes": {"sha256" : "abc"}}',
        "version 0": '{"version": 0, "length": 1, "hashes": {"sha256" : "abc"}}',
        "length below 0": '{"version": 1, "length": -1, "hashes": {"sha256" : "abc"}}',
        "empty hashes dict": '{"version": 1, "length": 1, "hashes": {}}',
        "hashes wrong type": '{"version": 1, "length": 1, "hashes": 1}',
        "hashes values wrong type": '{"version": 1, "length": 1, "hashes": {"sha256": 1}}',
    }

    @utils.run_sub_tests_with_dataset(invalid_metafiles)
    def test_invalid_metafile_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises((TypeError, ValueError, AttributeError)):
            MetaFile.from_dict(case_dict)

    valid_metafiles: utils.DataSet = {
        "all": '{"hashes": {"sha256" : "abc"}, "length": 12, "version": 1}',
        "no length": '{"hashes": {"sha256" : "abc"}, "version": 1 }',
        "length 0": '{"version": 1, "length": 0, "hashes": {"sha256" : "abc"}}',
        "no hashes": '{"length": 12, "version": 1}',
        "unrecognized field": '{"hashes": {"sha256" : "abc"}, "length": 12, "version": 1, "foo": "bar"}',
        "many hashes": '{"hashes": {"sha256" : "abc", "sha512": "cde"}, "length": 12, "version": 1}',
    }

    @utils.run_sub_tests_with_dataset(valid_metafiles)
    def test_metafile_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        metafile = MetaFile.from_dict(copy.copy(case_dict))
        self.assertDictEqual(case_dict, metafile.to_dict())

    invalid_timestamps: utils.DataSet = {
        "no metafile": '{ "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
    }

    @utils.run_sub_tests_with_dataset(invalid_timestamps)
    def test_invalid_timestamp_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises((ValueError, KeyError)):
            Timestamp.from_dict(case_dict)

    valid_timestamps: utils.DataSet = {
        "all": '{ "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}}',
        "legacy spec_version": '{ "_type": "timestamp", "spec_version": "1.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}}',
        "unrecognized field": '{ "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}, "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_timestamps)
    def test_timestamp_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        timestamp = Timestamp.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, timestamp.to_dict())

    valid_snapshots: utils.DataSet = {
        "all": '{ "_type": "snapshot", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": { \
                "file1.txt": {"hashes": {"sha256" : "abc"}, "version": 1}, \
                "file2.txt": {"hashes": {"sha256" : "cde"}, "version": 1} \
            }}',
        "empty meta": '{ "_type": "snapshot", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": {} \
            }',
        "unrecognized field": '{ "_type": "snapshot", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": { "file.txt": { "hashes": {"sha256" : "abc"}, "version": 1 }}, "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_snapshots)
    def test_snapshot_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        snapshot = Snapshot.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, snapshot.to_dict())

    valid_delegated_roles: utils.DataSet = {
        # DelegatedRole inherits Role and some use cases can be found in the valid_roles.
        "no hash prefix attribute": '{"keyids": ["keyid"], "name": "a", "paths": ["fn1", "fn2"], \
            "terminating": false, "threshold": 1}',
        "no path attribute": '{"keyids": ["keyid"], "name": "a", "terminating": false, \
            "path_hash_prefixes": ["h1", "h2"], "threshold": 99}',
        "empty paths": '{"keyids": ["keyid"], "name": "a", "paths": [], \
            "terminating": false, "threshold": 1}',
        "empty path_hash_prefixes": '{"keyids": ["keyid"], "name": "a", "terminating": false, \
            "path_hash_prefixes": [], "threshold": 99}',
        "unrecognized field": '{"keyids": ["keyid"], "name": "a", "terminating": true, "paths": ["fn1"], "threshold": 3, "foo": "bar"}',
        "many keyids": '{"keyids": ["keyid1", "keyid2"], "name": "a", "paths": ["fn1", "fn2"], \
            "terminating": false, "threshold": 1}',
        "ordered keyids": '{"keyids": ["keyid2", "keyid1"], "name": "a", "paths": ["fn1", "fn2"], \
            "terminating": false, "threshold": 1}',
    }

    @utils.run_sub_tests_with_dataset(valid_delegated_roles)
    def test_delegated_role_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        deserialized_role = DelegatedRole.from_dict(copy.copy(case_dict))
        self.assertDictEqual(case_dict, deserialized_role.to_dict())

    invalid_delegated_roles: utils.DataSet = {
        # DelegatedRole inherits Role and some use cases can be found in the invalid_roles.
        "missing hash prefixes and paths": '{"name": "a", "keyids": ["keyid"], "threshold": 1, "terminating": false}',
        "both hash prefixes and paths": '{"name": "a", "keyids": ["keyid"], "threshold": 1, "terminating": false, \
            "paths": ["fn1", "fn2"], "path_hash_prefixes": ["h1", "h2"]}',
        "invalid path type": '{"keyids": ["keyid"], "name": "a", "paths": [1,2,3], \
            "terminating": false, "threshold": 1}',
        "invalid path_hash_prefixes type": '{"keyids": ["keyid"], "name": "a", "path_hash_prefixes": [1,2,3], \
            "terminating": false, "threshold": 1}',
    }

    @utils.run_sub_tests_with_dataset(invalid_delegated_roles)
    def test_invalid_delegated_role_serialization(
        self, test_case_data: str
    ) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises(ValueError):
            DelegatedRole.from_dict(case_dict)

    valid_succinct_roles: utils.DataSet = {
        # SuccinctRoles inherits Role and some use cases can be found in the valid_roles.
        "standard succinct_roles information": '{"keyids": ["keyid"], "threshold": 1, \
            "bit_length": 8, "name_prefix": "foo"}',
        "succinct_roles with unrecognized fields": '{"keyids": ["keyid"], "threshold": 1, \
            "bit_length": 8, "name_prefix": "foo", "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_succinct_roles)
    def test_succinct_roles_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        succinct_roles = SuccinctRoles.from_dict(copy.copy(case_dict))
        self.assertDictEqual(case_dict, succinct_roles.to_dict())

    invalid_succinct_roles: utils.DataSet = {
        # SuccinctRoles inherits Role and some use cases can be found in the invalid_roles.
        "missing bit_length from succinct_roles": '{"keyids": ["keyid"], "threshold": 1, "name_prefix": "foo"}',
        "missing name_prefix from succinct_roles": '{"keyids": ["keyid"], "threshold": 1, "bit_length": 8}',
        "succinct_roles with invalid bit_length type": '{"keyids": ["keyid"], "threshold": 1, "bit_length": "a", "name_prefix": "foo"}',
        "succinct_roles with invalid name_prefix type": '{"keyids": ["keyid"], "threshold": 1, "bit_length": 8, "name_prefix": 1}',
        "succinct_roles with high bit_length value": '{"keyids": ["keyid"], "threshold": 1, "bit_length": 50, "name_prefix": "foo"}',
        "succinct_roles with low bit_length value": '{"keyids": ["keyid"], "threshold": 1, "bit_length": 0, "name_prefix": "foo"}',
    }

    @utils.run_sub_tests_with_dataset(invalid_succinct_roles)
    def test_invalid_succinct_roles_serialization(self, test_data: str) -> None:
        case_dict = json.loads(test_data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            SuccinctRoles.from_dict(case_dict)

    invalid_delegations: utils.DataSet = {
        "empty delegations": "{}",
        "missing keys": '{ "roles": [ \
                {"keyids": ["keyid"], "name": "a", "terminating": true, "paths": ["fn1"], "threshold": 3}, \
                {"keyids": ["keyid2"], "name": "b", "terminating": true, "paths": ["fn2"], "threshold": 4} ] \
            }',
        "missing roles": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}}',
        "bad keys": '{"keys": "foo", \
            "roles": [{"keyids": ["keyid"], "name": "a", "paths": ["fn1", "fn2"], "terminating": false, "threshold": 3}]}',
        "bad roles": '{"keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": ["foo"]}',
        "duplicate role names": '{"keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ \
                {"keyids": ["keyid"], "name": "a", "paths": ["fn1", "fn2"], "terminating": false, "threshold": 3}, \
                {"keyids": ["keyid2"], "name": "a", "paths": ["fn3"], "terminating": false, "threshold": 2}    \
                ] \
            }',
        "using empty string role name": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ \
                {"keyids": ["keyid1"], "name": "", "terminating": true, "paths": ["fn1"], "threshold": 3}] \
            }',
        "using root as delegate role name": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ \
                {"keyids": ["keyid1"], "name": "root", "terminating": true, "paths": ["fn1"], "threshold": 3}] \
            }',
        "using snapshot as delegate role name": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ \
                {"keyids": ["keyid1"], "name": "snapshot", "terminating": true, "paths": ["fn1"], "threshold": 3}] \
            }',
        "using targets as delegate role name": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ \
                {"keyids": ["keyid1"], "name": "targets", "terminating": true, "paths": ["fn1"], "threshold": 3}] \
            }',
        "using timestamp as delegate role name": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ \
                {"keyids": ["keyid1"], "name": "timestamp", "terminating": true, "paths": ["fn1"], "threshold": 3}] \
            }',
        "using valid and top-level role name": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "roles": [ \
                {"keyids": ["keyid1"], "name": "b", "terminating": true, "paths": ["fn1"], "threshold": 3}, \
                {"keyids": ["keyid2"], "name": "root", "terminating": true, "paths": ["fn2"], "threshold": 4} ] \
            }',
        "roles and succinct_roles set": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "roles": [ \
                {"keyids": ["keyid"], "name": "a", "terminating": true, "paths": ["fn1"], "threshold": 3}, \
                {"keyids": ["keyid2"], "name": "b", "terminating": true, "paths": ["fn2"], "threshold": 4} ], \
            "succinct_roles": {"keyids": ["keyid"], "threshold": 1, "bit_length": 8, "name_prefix": "foo"}}',
    }

    @utils.run_sub_tests_with_dataset(invalid_delegations)
    def test_invalid_delegation_serialization(
        self, test_case_data: str
    ) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises((ValueError, KeyError, AttributeError)):
            Delegations.from_dict(case_dict)

    valid_delegations: utils.DataSet = {
        "with roles": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "roles": [ \
                {"keyids": ["keyid"], "name": "a", "terminating": true, "paths": ["fn1"], "threshold": 3}, \
                {"keyids": ["keyid2"], "name": "b", "terminating": true, "paths": ["fn2"], "threshold": 4} ] \
            }',
        "with succinct_roles": '{"keys": { \
                "keyid1" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                "keyid2" : {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
            "succinct_roles": {"keyids": ["keyid"], "threshold": 1, "bit_length": 8, "name_prefix": "foo"}}',
        "unrecognized field": '{"keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ {"keyids": ["keyid"], "name": "a", "paths": ["fn1", "fn2"], "terminating": true, "threshold": 3} ], \
            "foo": "bar"}',
        "empty keys and roles": '{"keys": {}, \
            "roles": [] \
            }',
    }

    @utils.run_sub_tests_with_dataset(valid_delegations)
    def test_delegation_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        delegation = Delegations.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, delegation.to_dict())

    invalid_targetfiles: utils.DataSet = {
        "no hashes": '{"length": 1}',
        "no length": '{"hashes": {"sha256": "abc"}}',
        # The remaining cases are the same as for invalid_hashes and
        # invalid_length datasets.
    }

    @utils.run_sub_tests_with_dataset(invalid_targetfiles)
    def test_invalid_targetfile_serialization(
        self, test_case_data: str
    ) -> None:
        case_dict = json.loads(test_case_data)
        with self.assertRaises(KeyError):
            TargetFile.from_dict(case_dict, "file1.txt")

    valid_targetfiles: utils.DataSet = {
        "all": '{"length": 12, "hashes": {"sha256" : "abc"}, \
            "custom" : {"foo": "bar"} }',
        "no custom": '{"length": 12, "hashes": {"sha256" : "abc"}}',
        "unrecognized field": '{"length": 12, "hashes": {"sha256" : "abc"}, \
            "custom" : {"foo": "bar"}, "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_targetfiles)
    def test_targetfile_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        target_file = TargetFile.from_dict(copy.copy(case_dict), "file1.txt")
        self.assertDictEqual(case_dict, target_file.to_dict())

    valid_targets: utils.DataSet = {
        "all attributes": '{"_type": "targets", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "targets": { \
                "file.txt": {"length": 12, "hashes": {"sha256" : "abc"} }, \
                "file2.txt": {"length": 50, "hashes": {"sha256" : "cde"} } }, \
            "delegations": { \
                "keys": { \
                    "keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}, \
                    "keyid2": {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "bar"}}}, \
                "roles": [ \
                    {"keyids": ["keyid"], "name": "a", "terminating": true, "paths": ["fn1"], "threshold": 3}, \
                    {"keyids": ["keyid2"], "name": "b", "terminating": true, "paths": ["fn2"], "threshold": 4} ] \
            }}',
        "empty targets": '{"_type": "targets", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "targets": {}, \
            "delegations": {"keys": {"keyid" : {"keytype": "rsa", \
                    "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"} }}, \
                "roles": [ {"keyids": ["keyid"], "name": "a", "paths": ["fn1", "fn2"], "terminating": true, "threshold": 3} ]} \
            }',
        "no delegations": '{"_type": "targets", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "targets":  { "file.txt": {"length": 12, "hashes": {"sha256" : "abc"} } } \
            }',
        "unrecognized_field": '{"_type": "targets", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "targets":  {}, "foo": "bar"}',
    }

    @utils.run_sub_tests_with_dataset(valid_targets)
    def test_targets_serialization(self, test_case_data: str) -> None:
        case_dict = json.loads(test_case_data)
        targets = Targets.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, targets.to_dict())


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
