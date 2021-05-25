# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

""" Unit tests testing tuf/api/metadata.py classes
serialization and deserialization.

"""

import json
import sys
import logging
import unittest
import copy

from typing import Dict, Callable

from tests import utils

from tuf.api.metadata import (
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

logger = logging.getLogger(__name__)

# DataSet is only here so type hints can be used:
# It is a dict of name to test dict
DataSet = Dict[str, str]

# Test runner decorator: Runs the test as a set of N SubTests,
# (where N is number of items in dataset), feeding the actual test
# function one test case at a time
def run_sub_tests_with_dataset(dataset: DataSet):
    def real_decorator(function: Callable[["TestSerialization", str], None]):
        def wrapper(test_cls: "TestSerialization"):
            for case, data in dataset.items():
                with test_cls.subTest(case=case):
                    function(test_cls, data)
        return wrapper
    return real_decorator


class TestSerialization(unittest.TestCase):

    valid_keys: DataSet = {
        "all": '{"keytype": "rsa", "scheme": "rsassa-pss-sha256", \
            "keyval": {"public": "foo"}}',
    }

    @run_sub_tests_with_dataset(valid_keys)
    def test_key_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        key = Key.from_dict("id", copy.copy(case_dict))
        self.assertDictEqual(case_dict, key.to_dict())


    valid_roles: DataSet = {
        "all": '{"keyids": ["keyid"], "threshold": 3}'
    }

    @run_sub_tests_with_dataset(valid_roles)
    def test_role_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        role = Role.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, role.to_dict())


    valid_roots: DataSet = {
        "all": '{"_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": false, \
            "keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": { "targets": {"keyids": ["keyid"], "threshold": 3}} \
            }',
        "no consistent_snapshot": '{ "_type": "root", "spec_version": "1.0.0", "version": 1, \
            "expires": "2030-01-01T00:00:00Z", \
            "keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"} }}, \
            "roles": { "targets": {"keyids": ["keyid"], "threshold": 3} } \
            }',
    }

    @run_sub_tests_with_dataset(valid_roots)
    def test_root_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        root = Root.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, root.to_dict())

    valid_metafiles: DataSet = {
        "all": '{"hashes": {"sha256" : "abc"}, "length": 12, "version": 1}',
        "no length": '{"hashes": {"sha256" : "abc"}, "version": 1 }',
        "no hashes": '{"length": 12, "version": 1}'
    }

    @run_sub_tests_with_dataset(valid_metafiles)
    def test_metafile_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        metafile = MetaFile.from_dict(copy.copy(case_dict))
        self.assertDictEqual(case_dict, metafile.to_dict())


    valid_timestamps: DataSet = {
        "all": '{ "_type": "timestamp", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": {"snapshot.json": {"hashes": {"sha256" : "abc"}, "version": 1}}}'
    }

    @run_sub_tests_with_dataset(valid_timestamps)
    def test_timestamp_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        timestamp = Timestamp.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, timestamp.to_dict())


    valid_snapshots: DataSet = {
        "all": '{ "_type": "snapshot", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "meta": { "file.txt": { "hashes": {"sha256" : "abc"}, "version": 1 }}}'
    }

    @run_sub_tests_with_dataset(valid_snapshots)
    def test_snapshot_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        snapshot = Snapshot.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, snapshot.to_dict())


    valid_delegated_roles: DataSet = {
        "no hash prefix attribute":
            '{"keyids": ["keyid"], "name": "a", "paths": ["fn1", "fn2"], \
            "terminating": false, "threshold": 1}',
        "no path attribute":
            '{"keyids": ["keyid"], "name": "a", "terminating": false, \
            "path_hash_prefixes": ["h1", "h2"], "threshold": 99}',
        "no hash or path prefix":
            '{"keyids": ["keyid"], "name": "a", "terminating": true, "threshold": 3}',
    }

    @run_sub_tests_with_dataset(valid_delegated_roles)
    def test_delegated_role_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        deserialized_role = DelegatedRole.from_dict(copy.copy(case_dict))
        self.assertDictEqual(case_dict, deserialized_role.to_dict())


    valid_delegations: DataSet = {
        "all": '{"keys": {"keyid" : {"keytype": "rsa", "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"}}}, \
            "roles": [ {"keyids": ["keyid"], "name": "a", "terminating": true, "threshold": 3} ]}'
    }

    @run_sub_tests_with_dataset(valid_delegations)
    def test_delegation_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        delegation = Delegations.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, delegation.to_dict())


    valid_targetfiles: DataSet = {
        "all": '{"length": 12, "hashes": {"sha256" : "abc"}, \
            "custom" : {"foo": "bar"} }',
        "no custom": '{"length": 12, "hashes": {"sha256" : "abc"}}'
    }

    @run_sub_tests_with_dataset(valid_targetfiles)
    def test_targetfile_serialization(self, test_case_data: str):
        case_dict = json.loads(test_case_data)
        target_file = TargetFile.from_dict(copy.copy(case_dict))
        self.assertDictEqual(case_dict, target_file.to_dict())


    valid_targets: DataSet = {
        "all attributes": '{"_type": "targets", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "targets": { "file.txt": {"length": 12, "hashes": {"sha256" : "abc"} } }, \
            "delegations": {"keys": {"keyid" : {"keytype": "rsa", \
                    "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"} }}, \
                "roles": [ {"keyids": ["keyid"], "name": "a", "terminating": true, "threshold": 3} ]} \
            }',
        "empty targets": '{"_type": "targets", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "targets": {}, \
            "delegations": {"keys": {"keyid" : {"keytype": "rsa", \
                    "scheme": "rsassa-pss-sha256", "keyval": {"public": "foo"} }}, \
                "roles": [ {"keyids": ["keyid"], "name": "a", "terminating": true, "threshold": 3} ]} \
            }',
        "no delegations": '{"_type": "targets", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z", \
            "targets":  { "file.txt": {"length": 12, "hashes": {"sha256" : "abc"} } } \
            }'
    }

    @run_sub_tests_with_dataset(valid_targets)
    def test_targets_serialization(self, test_case_data):
        case_dict = json.loads(test_case_data)
        targets = Targets.from_dict(copy.deepcopy(case_dict))
        self.assertDictEqual(case_dict, targets.to_dict())


# Run unit test.
if __name__ == '__main__':
    utils.configure_test_logging(sys.argv)
    unittest.main()
