import json
import logging
import os
import shutil
import sys
import tempfile
import unittest

from tuf import exceptions
from tuf.api.metadata import Metadata
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet

from tests import utils

logger = logging.getLogger(__name__)

class TestTrustedMetadataSet(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo_dir = os.path.join(
            os.getcwd(), 'repository_data', 'repository', 'metadata'
        )
        cls.metadata = {}
        for md in ["root", "timestamp", "snapshot", "targets", "role1", "role2"]:
            with open(os.path.join(cls.repo_dir, f"{md}.json"), "rb") as f:
                cls.metadata[md] = f.read()


    def test_update(self):
        trusted_set = TrustedMetadataSet(self.metadata["root"])
        trusted_set.root_update_finished()

        trusted_set.update_timestamp(self.metadata["timestamp"])
        trusted_set.update_snapshot(self.metadata["snapshot"])
        trusted_set.update_targets(self.metadata["targets"])
        trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )
        trusted_set.update_delegated_targets(
            self.metadata["role2"], "role2", "role1"
        )

    def test_out_of_order_ops(self):
        trusted_set = TrustedMetadataSet(self.metadata["root"])

        # Update timestamp before root is finished
        with self.assertRaises(RuntimeError):
            trusted_set.update_timestamp(self.metadata["timestamp"])

        trusted_set.root_update_finished()
        with self.assertRaises(RuntimeError):
            trusted_set.root_update_finished()

        # Update snapshot before timestamp
        with self.assertRaises(RuntimeError):
            trusted_set.update_snapshot(self.metadata["snapshot"])

        trusted_set.update_timestamp(self.metadata["timestamp"])

        # Update targets before snapshot
        with self.assertRaises(RuntimeError):
            trusted_set.update_targets(self.metadata["targets"])

        trusted_set.update_snapshot(self.metadata["snapshot"])

        # update timestamp after snapshot
        with self.assertRaises(RuntimeError):
            trusted_set.update_timestamp(self.metadata["timestamp"])

        # Update delegated targets before targets
        with self.assertRaises(RuntimeError):
            trusted_set.update_delegated_targets(
                self.metadata["role1"], "role1", "targets"
            )

        trusted_set.update_targets(self.metadata["targets"])
        trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )

        trusted_set.update_targets(self.metadata["targets"])
        trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )

    def test_update_with_invalid_json(self):
        # root.json not a json file at all
        with self.assertRaises(exceptions.RepositoryError):
            TrustedMetadataSet(b"")
        # root.json is invalid
        root = Metadata.from_bytes(self.metadata["root"])
        root.signed.version += 1
        with self.assertRaises(exceptions.RepositoryError):
            TrustedMetadataSet(json.dumps(root.to_dict()).encode())

        trusted_set = TrustedMetadataSet(self.metadata["root"])
        trusted_set.root_update_finished()

        top_level_md = [
            (self.metadata["timestamp"], trusted_set.update_timestamp),
            (self.metadata["snapshot"], trusted_set.update_snapshot),
            (self.metadata["targets"], trusted_set.update_targets),
        ]
        for metadata, update_func in top_level_md:
            # metadata is not json
            with self.assertRaises(exceptions.RepositoryError):
                update_func(b"")
            # metadata is invalid
            md = Metadata.from_bytes(metadata)
            md.signed.version += 1
            with self.assertRaises(exceptions.RepositoryError):
                update_func(json.dumps(md.to_dict()).encode())

            # metadata is of wrong type
            with self.assertRaises(exceptions.RepositoryError):
                update_func(self.metadata["root"])

            update_func(metadata)


    # TODO test updating over initial metadata (new keys, newer timestamp, etc)
    # TODO test the actual specification checks


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
