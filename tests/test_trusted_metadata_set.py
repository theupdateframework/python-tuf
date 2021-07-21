import logging
from typing import Optional, Union, Callable
import os
import sys
import unittest
from datetime import datetime

from tuf import exceptions
from tuf.api.metadata import Metadata, Signed, Timestamp, Snapshot, MetaFile
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet

from securesystemslib.signer import SSlibSigner
from securesystemslib.interface import(
    import_ed25519_privatekey_from_file,
    import_rsa_privatekey_from_file
)

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

        keystore_dir = os.path.join(os.getcwd(), 'repository_data', 'keystore')
        cls.keystore = {}
        root_key_dict = import_rsa_privatekey_from_file(
            os.path.join(keystore_dir, "root" + '_key'),
            password="password"
        )
        cls.keystore["root"] = SSlibSigner(root_key_dict)
        for role in ["delegation", "snapshot", "targets", "timestamp"]:
            key_dict = import_ed25519_privatekey_from_file(
                os.path.join(keystore_dir, role + '_key'),
                password="password"
            )
            cls.keystore[role] = SSlibSigner(key_dict)

    def setUp(self) -> None:
        self.trusted_set = TrustedMetadataSet(self.metadata["root"])

    def _root_updated_and_update_timestamp(
        self, timestamp_bytes: Optional[bytes] = None
    ):
        """Finsh root update and update timestamp with passed timestamp_bytes.

        Args:
            timestamp_bytes:
                Bytes used when calling trusted_set.update_timestamp().
                Default self.metadata["timestamp"].

        """
        timestamp_bytes = timestamp_bytes or self.metadata["timestamp"]
        self.trusted_set.root_update_finished()
        self.trusted_set.update_timestamp(timestamp_bytes)


    def _update_all_besides_targets(
        self,
        timestamp_bytes: Optional[bytes] = None,
        snapshot_bytes: Optional[bytes] = None,
    ):
        """Update all metadata roles besides targets.

        Args:
            timestamp_bytes:
                Bytes used when calling trusted_set.update_timestamp().
                Default self.metadata["timestamp"].
            snapshot_bytes:
                Bytes used when calling trusted_set.update_snapshot().
                Default self.metadata["snapshot"].

        """
        self._root_updated_and_update_timestamp(timestamp_bytes)
        snapshot_bytes = snapshot_bytes or self.metadata["snapshot"]
        self.trusted_set.update_snapshot(snapshot_bytes)

    def modify_metadata(
        self, rolename: str, modification_func: Callable[["Signed"], None]
    ):
        """Instantiate metadata from rolename type, call modification_func and
        sign it again with self.keystore[rolename] signer."""
        metadata = Metadata.from_bytes(self.metadata[rolename])
        modification_func(metadata.signed)
        metadata.sign(self.keystore[rolename])
        return metadata.to_bytes()

    def test_update(self):
        self.trusted_set.root_update_finished()
        self.trusted_set.update_timestamp(self.metadata["timestamp"])
        self.trusted_set.update_snapshot(self.metadata["snapshot"])
        self.trusted_set.update_targets(self.metadata["targets"])
        self.trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )
        self.trusted_set.update_delegated_targets(
            self.metadata["role2"], "role2", "role1"
        )
        # the 4 top level metadata objects + 2 additional delegated targets
        self.assertTrue(len(self.trusted_set), 6)

    def test_out_of_order_ops(self):
        # Update timestamp before root is finished
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

        self.trusted_set.root_update_finished()
        with self.assertRaises(RuntimeError):
            self.trusted_set.root_update_finished()

        # Update root after a previous successful root update
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_root(self.metadata["root"])

        # Update snapshot before timestamp
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

        self.trusted_set.update_timestamp(self.metadata["timestamp"])

        # Update targets before snapshot
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_targets(self.metadata["targets"])

        self.trusted_set.update_snapshot(self.metadata["snapshot"])

        # update timestamp after snapshot
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

        # Update delegated targets before targets
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_delegated_targets(
                self.metadata["role1"], "role1", "targets"
            )

        self.trusted_set.update_targets(self.metadata["targets"])

        # Update snapshot after sucessful targets update
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

        self.trusted_set.update_delegated_targets(
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
            TrustedMetadataSet(root.to_bytes())

        # update_root called with the wrong metadata type
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_root(self.metadata["snapshot"])

        self.trusted_set.root_update_finished()

        top_level_md = [
            (self.metadata["timestamp"], self.trusted_set.update_timestamp),
            (self.metadata["snapshot"], self.trusted_set.update_snapshot),
            (self.metadata["targets"], self.trusted_set.update_targets),
        ]
        for metadata, update_func in top_level_md:
            md = Metadata.from_bytes(metadata)
            if md.signed.type == "snapshot":
                # timestamp hashes and length intervene when testing snapshot
                self.trusted_set.timestamp.signed.meta["snapshot.json"].hashes = None
                self.trusted_set.timestamp.signed.meta["snapshot.json"].length = None
            # metadata is not json
            with self.assertRaises(exceptions.RepositoryError):
                update_func(b"")
            # metadata is invalid
            md.signed.version += 1
            with self.assertRaises(exceptions.RepositoryError):
                update_func(md.to_bytes())

            # metadata is of wrong type
            with self.assertRaises(exceptions.RepositoryError):
                update_func(self.metadata["root"])

            update_func(metadata)


    def test_update_root_new_root_cannot_be_verified_with_threshold(self):
        # new_root data with threshold which cannot be verified.
        root = Metadata.from_bytes(self.metadata["root"])
        # remove root role keyids representing root signatures
        root.signed.roles["root"].keyids = []
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_root(root.to_bytes())

    def test_update_root_new_root_ver_same_as_trusted_root_ver(self):
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_root(self.metadata["root"])


    def test_root_update_finished_expired(self):
        root = Metadata.from_bytes(self.metadata["root"])
        root.signed.expires = datetime(1970, 1, 1)
        root.sign(self.keystore["root"])
        tmp_trusted_set = TrustedMetadataSet(root.to_bytes())
        # call root_update_finished when trusted root has expired
        with self.assertRaises(exceptions.ExpiredMetadataError):
            tmp_trusted_set.root_update_finished()


    def test_update_timestamp_new_timestamp_ver_below_trusted_ver(self):
        # new_timestamp.version < trusted_timestamp.version
        timestamp = Metadata.from_bytes(self.metadata["timestamp"])
        timestamp.signed.version = 3
        timestamp.sign(self.keystore["timestamp"])
        self._root_updated_and_update_timestamp(timestamp.to_bytes())
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def test_update_timestamp_snapshot_ver_below_trusted_snapshot_ver(self):
        def version_modifier(timestamp: Timestamp):
            timestamp.version = 3

        modified_timestamp = self.modify_metadata("timestamp", version_modifier)
        self._root_updated_and_update_timestamp(modified_timestamp)
        # new_timestamp.snapshot.version < trusted_timestamp.snapshot.version
        with self.assertRaises(exceptions.ReplayedMetadataError):
            self.trusted_set.update_timestamp(self.metadata["timestamp"])

    def test_update_timestamp_expired(self):
        self.trusted_set.root_update_finished()
        # new_timestamp has expired
        timestamp = Metadata.from_bytes(self.metadata["timestamp"])
        timestamp.signed.expires = datetime(1970, 1, 1)
        timestamp.sign(self.keystore["timestamp"])
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_timestamp(timestamp.to_bytes())


    def test_update_snapshot_cannot_verify_snapshot_with_threshold(self):
        def hashes_length_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None

        timestamp = self.modify_metadata("timestamp", hashes_length_modifier)
        self._root_updated_and_update_timestamp(timestamp)
        snapshot = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot.signatures.clear()
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_snapshot(snapshot.to_bytes())

    def test_update_snapshot_version_different_timestamp_snapshot_version(self):
        def hashes_length_version_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None
            timestamp.meta["snapshot.json"].version = 2

        timestamp = self.modify_metadata(
            "timestamp", hashes_length_version_modifier
        )
        self._root_updated_and_update_timestamp(timestamp)
        # new_snapshot.version != trusted timestamp.meta["snapshot"].version
        snapshot = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot.signed.version = 3
        snapshot.sign(self.keystore["snapshot"])
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(snapshot.to_bytes())

    def test_update_snapshot_after_successful_update_new_snapshot_no_meta(self):
        def hashes_length_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None

        timestamp = self.modify_metadata("timestamp", hashes_length_modifier)
        self._update_all_besides_targets(timestamp)
        # Test removing a meta_file in new_snapshot compared to the old snapshot
        snapshot = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot.signed.meta = {}
        snapshot.sign(self.keystore["snapshot"])
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_snapshot(snapshot.to_bytes())

    def test_update_snapshot_after_succesfull_update_new_snapshot_meta_version_different(self):
        def hashes_length_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None

        timestamp = self.modify_metadata("timestamp", hashes_length_modifier)
        self._root_updated_and_update_timestamp(timestamp)
        # snapshot.meta["project1"].version != new_snapshot.meta["project1"].version
        snapshot = Metadata.from_bytes(self.metadata["snapshot"])
        for metafile_path in snapshot.signed.meta.keys():
            snapshot.signed.meta[metafile_path].version += 1
        snapshot.sign(self.keystore["snapshot"])
        self.trusted_set.update_snapshot(snapshot.to_bytes())
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata["snapshot"])

    def test_update_snapshot_expired_new_snapshot(self):
        def hashes_length_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None

        timestamp = self.modify_metadata("timestamp", hashes_length_modifier)
        self._root_updated_and_update_timestamp(timestamp)
        # new_snapshot has expired
        snapshot = Metadata.from_bytes(self.metadata["snapshot"])
        snapshot.signed.expires = datetime(1970, 1, 1)
        snapshot.sign(self.keystore["snapshot"])
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_snapshot(snapshot.to_bytes())


    def test_update_targets_no_meta_in_snapshot(self):
        def hashes_length_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None

        timestamp = self.modify_metadata("timestamp", hashes_length_modifier)
        def no_meta_modifier(snapshot: Snapshot):
            snapshot.meta = {}

        snapshot = self.modify_metadata("snapshot", no_meta_modifier)
        self._update_all_besides_targets(timestamp, snapshot)
        # remove meta information with information about targets from snapshot
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_hash_different_than_snapshot_meta_hash(self):
        def hashes_length_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None

        timestamp = self.modify_metadata("timestamp", hashes_length_modifier)
        def meta_length_modifier(snapshot: Snapshot):
            for metafile_path in snapshot.meta:
                snapshot.meta[metafile_path] = MetaFile(version=1, length=1)

        snapshot = self.modify_metadata("snapshot", meta_length_modifier)
        self._update_all_besides_targets(timestamp, snapshot)
        # observed_hash != stored hash in snapshot meta for targets
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_version_different_snapshot_meta_version(self):
        def hashes_length_modifier(timestamp: Timestamp):
            timestamp.meta["snapshot.json"].hashes = None
            timestamp.meta["snapshot.json"].length = None

        timestamp = self.modify_metadata("timestamp", hashes_length_modifier)
        def meta_modifier(snapshot: Snapshot):
            for metafile_path in snapshot.meta:
                snapshot.meta[metafile_path] = MetaFile(version=2)

        snapshot = self.modify_metadata("snapshot", meta_modifier)
        self._update_all_besides_targets(timestamp, snapshot)
        # new_delegate.signed.version != meta.version stored in snapshot
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_targets(self.metadata["targets"])

    def test_update_targets_expired_new_target(self):
        self._update_all_besides_targets()
        # new_delegated_target has expired
        targets = Metadata.from_bytes(self.metadata["targets"])
        targets.signed.expires = datetime(1970, 1, 1)
        targets.sign(self.keystore["targets"])
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_targets(targets.to_bytes())

    # TODO test updating over initial metadata (new keys, newer timestamp, etc)


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
