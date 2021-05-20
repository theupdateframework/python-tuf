import json
import logging
import os
import shutil
import sys
import tempfile
import unittest

from tuf import exceptions
from tuf.api.metadata import Metadata
from tuf.ngclient._internal.metadata_bundle import MetadataBundle

from tests import utils

logger = logging.getLogger(__name__)

class TestMetadataBundle(unittest.TestCase):

    def test_update(self):
        repo_dir = os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata')

        with open(os.path.join(repo_dir, "root.json"), "rb") as f:
            bundle = MetadataBundle(f.read())
        bundle.root_update_finished()

        with open(os.path.join(repo_dir, "timestamp.json"), "rb") as f:
            bundle.update_timestamp(f.read())
        with open(os.path.join(repo_dir, "snapshot.json"), "rb") as f:
            bundle.update_snapshot(f.read())
        with open(os.path.join(repo_dir, "targets.json"), "rb") as f:
            bundle.update_targets(f.read())
        with open(os.path.join(repo_dir, "role1.json"), "rb") as f:
            bundle.update_delegated_targets(f.read(), "role1", "targets")
        with open(os.path.join(repo_dir, "role2.json"), "rb") as f:
            bundle.update_delegated_targets(f.read(), "role2", "role1")

    def test_out_of_order_ops(self):
        repo_dir = os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata')
        data={}
        for md in ["root", "timestamp", "snapshot", "targets", "role1"]:
            with open(os.path.join(repo_dir, f"{md}.json"), "rb") as f:
                data[md] = f.read()

        bundle = MetadataBundle(data["root"])

        # Update timestamp before root is finished
        with self.assertRaises(RuntimeError):
            bundle.update_timestamp(data["timestamp"])

        bundle.root_update_finished()
        with self.assertRaises(RuntimeError):
            bundle.root_update_finished()

        # Update snapshot before timestamp
        with self.assertRaises(RuntimeError):
            bundle.update_snapshot(data["snapshot"])

        bundle.update_timestamp(data["timestamp"])

        # Update targets before snapshot
        with self.assertRaises(RuntimeError):
            bundle.update_targets(data["targets"])

        bundle.update_snapshot(data["snapshot"])

        #update timestamp after snapshot
        with self.assertRaises(RuntimeError):
            bundle.update_timestamp(data["timestamp"])

        # Update delegated targets before targets
        with self.assertRaises(RuntimeError):
            bundle.update_delegated_targets(data["role1"], "role1", "targets")

        bundle.update_targets(data["targets"])
        bundle.update_delegated_targets(data["role1"], "role1", "targets")

    def test_update_with_invalid_json(self):
        repo_dir = os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata')
        data={}
        for md in ["root", "timestamp", "snapshot", "targets", "role1"]:
            with open(os.path.join(repo_dir, f"{md}.json"), "rb") as f:
                data[md] = f.read()

        # root.json not a json file at all
        with self.assertRaises(exceptions.RepositoryError):
            MetadataBundle(b"")
        # root.json is invalid
        root = Metadata.from_bytes(data["root"])
        root.signed.version += 1
        with self.assertRaises(exceptions.RepositoryError):
            MetadataBundle(json.dumps(root.to_dict()).encode())

        bundle = MetadataBundle(data["root"])
        bundle.root_update_finished()

        top_level_md = [
            (data["timestamp"], bundle.update_timestamp),
            (data["snapshot"], bundle.update_snapshot),
            (data["targets"], bundle.update_targets),
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
                update_func(data["root"])

            update_func(metadata)


    # TODO test updating over initial metadata (new keys, newer timestamp, etc)
    # TODO test the actual specification checks


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
