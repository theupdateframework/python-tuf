"""Unit tests for 'tuf/ngclient/_internal/trusted_metadata_set.py'."""

import logging
import os
import sys
import unittest
from datetime import datetime, timezone
from typing import Callable, ClassVar, Dict, List, Optional, Tuple

from securesystemslib.signer import Signer

from tests import utils
from tuf.api import exceptions
from tuf.api.dsse import SimpleEnvelope
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Signed,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient._internal.trusted_metadata_set import (
    TrustedMetadataSet,
    _load_from_simple_envelope,
)
from tuf.ngclient.config import EnvelopeType

logger = logging.getLogger(__name__)


class TestTrustedMetadataSet(unittest.TestCase):
    """Tests for all public API of the TrustedMetadataSet class."""

    keystore: ClassVar[Dict[str, Signer]]
    metadata: ClassVar[Dict[str, bytes]]
    repo_dir: ClassVar[str]

    @classmethod
    def modify_metadata(
        cls, rolename: str, modification_func: Callable
    ) -> bytes:
        """Instantiate metadata from rolename type, call modification_func and
        sign it again with self.keystore[rolename] signer.

        Attributes:
            rolename: Denoting the name of the metadata which will be modified.
            modification_func: Function that will be called to modify the signed
                portion of metadata bytes.
        """
        metadata = Metadata.from_bytes(cls.metadata[rolename])
        modification_func(metadata.signed)
        metadata.sign(cls.keystore[rolename])
        return metadata.to_bytes(JSONSerializer(validate=True))

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_dir = os.path.join(
            utils.TESTS_DIR, "repository_data", "repository", "metadata"
        )
        cls.metadata = {}
        for md in [
            Root.type,
            Timestamp.type,
            Snapshot.type,
            Targets.type,
            "role1",
            "role2",
        ]:
            with open(os.path.join(cls.repo_dir, f"{md}.json"), "rb") as f:
                cls.metadata[md] = f.read()

        keystore_dir = os.path.join(
            utils.TESTS_DIR, "repository_data", "keystore"
        )
        root = Metadata[Root].from_bytes(cls.metadata[Root.type]).signed

        cls.keystore = {}
        for role in [
            Root.type,
            Snapshot.type,
            Targets.type,
            Timestamp.type,
        ]:
            uri = f"file2:{os.path.join(keystore_dir, role + '_key')}"
            role_obj = root.get_delegated_role(role)
            key = root.get_key(role_obj.keyids[0])
            cls.keystore[role] = Signer.from_priv_key_uri(uri, key)

        def hashes_length_modifier(timestamp: Timestamp) -> None:
            timestamp.snapshot_meta.hashes = None
            timestamp.snapshot_meta.length = None

        cls.metadata[Timestamp.type] = cls.modify_metadata(
            Timestamp.type, hashes_length_modifier
        )

    def setUp(self) -> None:
        self.trusted_set = TrustedMetadataSet(
            self.metadata[Root.type], EnvelopeType.METADATA
        )

    def _update_all_besides_targets(
        self,
        timestamp_bytes: Optional[bytes] = None,
        snapshot_bytes: Optional[bytes] = None,
    ) -> None:
        """Update all metadata roles besides targets.

        Args:
            timestamp_bytes:
                Bytes used when calling trusted_set.update_timestamp().
                Default self.metadata[Timestamp.type].
            snapshot_bytes:
                Bytes used when calling trusted_set.update_snapshot().
                Default self.metadata[Snapshot.type].

        """

        timestamp_bytes = timestamp_bytes or self.metadata[Timestamp.type]
        self.trusted_set.update_timestamp(timestamp_bytes)
        snapshot_bytes = snapshot_bytes or self.metadata[Snapshot.type]
        self.trusted_set.update_snapshot(snapshot_bytes)

    def test_update(self) -> None:
        self.trusted_set.update_timestamp(self.metadata[Timestamp.type])
        self.trusted_set.update_snapshot(self.metadata[Snapshot.type])
        self.trusted_set.update_targets(self.metadata[Targets.type])
        self.trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", Targets.type
        )
        self.trusted_set.update_delegated_targets(
            self.metadata["role2"], "role2", "role1"
        )
        # the 4 top level metadata objects + 2 additional delegated targets
        self.assertTrue(len(self.trusted_set), 6)

        count = 0
        for md in self.trusted_set:
            self.assertIsInstance(md, Signed)
            count += 1

        self.assertTrue(count, 6)

    def test_update_metadata_output(self) -> None:
        timestamp = self.trusted_set.update_timestamp(
            self.metadata["timestamp"]
        )
        snapshot = self.trusted_set.update_snapshot(self.metadata["snapshot"])
        targets = self.trusted_set.update_targets(self.metadata["targets"])
        delegeted_targets_1 = self.trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", "targets"
        )
        delegeted_targets_2 = self.trusted_set.update_delegated_targets(
            self.metadata["role2"], "role2", "role1"
        )
        self.assertIsInstance(timestamp, Timestamp)
        self.assertIsInstance(snapshot, Snapshot)
        self.assertIsInstance(targets, Targets)
        self.assertIsInstance(delegeted_targets_1, Targets)
        self.assertIsInstance(delegeted_targets_2, Targets)

    def test_out_of_order_ops(self) -> None:
        # Update snapshot before timestamp
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata[Snapshot.type])

        self.trusted_set.update_timestamp(self.metadata[Timestamp.type])

        # Update root after timestamp
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_root(self.metadata[Root.type])

        # Update targets before snapshot
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_targets(self.metadata[Targets.type])

        self.trusted_set.update_snapshot(self.metadata[Snapshot.type])

        # update timestamp after snapshot
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_timestamp(self.metadata[Timestamp.type])

        # Update delegated targets before targets
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_delegated_targets(
                self.metadata["role1"], "role1", Targets.type
            )

        self.trusted_set.update_targets(self.metadata[Targets.type])

        # Update snapshot after sucessful targets update
        with self.assertRaises(RuntimeError):
            self.trusted_set.update_snapshot(self.metadata[Snapshot.type])

        self.trusted_set.update_delegated_targets(
            self.metadata["role1"], "role1", Targets.type
        )

    def test_bad_initial_root(self) -> None:
        # root is not json
        with self.assertRaises(exceptions.RepositoryError):
            TrustedMetadataSet(b"", EnvelopeType.METADATA)

        # root is invalid
        root = Metadata.from_bytes(self.metadata[Root.type])
        root.signed.version += 1
        with self.assertRaises(exceptions.UnsignedMetadataError):
            TrustedMetadataSet(root.to_bytes(), EnvelopeType.METADATA)

        # metadata is of wrong type
        with self.assertRaises(exceptions.RepositoryError):
            TrustedMetadataSet(
                self.metadata[Snapshot.type], EnvelopeType.METADATA
            )

    def test_bad_root_update(self) -> None:
        # root is not json
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_root(b"")

        # root is invalid
        root = Metadata.from_bytes(self.metadata[Root.type])
        root.signed.version += 1
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_root(root.to_bytes())

        # metadata is of wrong type
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_root(self.metadata[Snapshot.type])

    def test_top_level_md_with_invalid_json(self) -> None:
        top_level_md: List[Tuple[bytes, Callable[[bytes], Signed]]] = [
            (self.metadata[Timestamp.type], self.trusted_set.update_timestamp),
            (self.metadata[Snapshot.type], self.trusted_set.update_snapshot),
            (self.metadata[Targets.type], self.trusted_set.update_targets),
        ]
        for metadata, update_func in top_level_md:
            md = Metadata.from_bytes(metadata)
            # metadata is not json
            with self.assertRaises(exceptions.RepositoryError):
                update_func(b"")

            # metadata is invalid
            md.signed.version += 1
            with self.assertRaises(exceptions.UnsignedMetadataError):
                update_func(md.to_bytes())

            # metadata is of wrong type
            with self.assertRaises(exceptions.RepositoryError):
                update_func(self.metadata[Root.type])

            update_func(metadata)

    def test_update_root_new_root(self) -> None:
        # test that root can be updated with a new valid version
        def root_new_version_modifier(root: Root) -> None:
            root.version += 1

        root = self.modify_metadata(Root.type, root_new_version_modifier)
        self.trusted_set.update_root(root)

    def test_update_root_new_root_fail_threshold_verification(self) -> None:
        # Increase threshold in new root, do not add enough keys
        def root_threshold_bump(root: Root) -> None:
            root.version += 1
            root.roles[Root.type].threshold += 1

        root = self.modify_metadata(Root.type, root_threshold_bump)
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_root(root)

    def test_update_root_new_root_ver_same_as_trusted_root_ver(self) -> None:
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_root(self.metadata[Root.type])

    def test_root_expired_final_root(self) -> None:
        def root_expired_modifier(root: Root) -> None:
            root.expires = datetime(1970, 1, 1, tzinfo=timezone.utc)

        # intermediate root can be expired
        root = self.modify_metadata(Root.type, root_expired_modifier)
        tmp_trusted_set = TrustedMetadataSet(root, EnvelopeType.METADATA)
        # update timestamp to trigger final root expiry check
        with self.assertRaises(exceptions.ExpiredMetadataError):
            tmp_trusted_set.update_timestamp(self.metadata[Timestamp.type])

    def test_update_timestamp_new_timestamp_ver_below_trusted_ver(self) -> None:
        # new_timestamp.version < trusted_timestamp.version
        def version_modifier(timestamp: Timestamp) -> None:
            timestamp.version = 3

        timestamp = self.modify_metadata(Timestamp.type, version_modifier)
        self.trusted_set.update_timestamp(timestamp)
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_timestamp(self.metadata[Timestamp.type])

    def test_update_timestamp_with_same_timestamp(self) -> None:
        # Test that timestamp is NOT updated if:
        # new_timestamp.version == trusted_timestamp.version
        self.trusted_set.update_timestamp(self.metadata[Timestamp.type])
        initial_timestamp = self.trusted_set.timestamp

        # Update timestamp with the same version.
        with self.assertRaises(exceptions.EqualVersionNumberError):
            self.trusted_set.update_timestamp(self.metadata[Timestamp.type])

        # Every object has a unique id() if they are equal, this means timestamp
        # was not updated.
        self.assertEqual(id(initial_timestamp), id(self.trusted_set.timestamp))

    def test_update_timestamp_snapshot_ver_below_current(self) -> None:
        def bump_snapshot_version(timestamp: Timestamp) -> None:
            timestamp.snapshot_meta.version = 2
            # The timestamp version must be increased to initiate a update.
            timestamp.version += 1

        # set current known snapshot.json version to 2
        timestamp = self.modify_metadata(Timestamp.type, bump_snapshot_version)
        self.trusted_set.update_timestamp(timestamp)

        # newtimestamp.meta.version < trusted_timestamp.meta.version
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_timestamp(self.metadata[Timestamp.type])

    def test_update_timestamp_expired(self) -> None:
        # new_timestamp has expired
        def timestamp_expired_modifier(timestamp: Timestamp) -> None:
            timestamp.expires = datetime(1970, 1, 1, tzinfo=timezone.utc)

        # expired intermediate timestamp is loaded but raises
        timestamp = self.modify_metadata(
            Timestamp.type, timestamp_expired_modifier
        )
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_timestamp(timestamp)

        # snapshot update does start but fails because timestamp is expired
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_snapshot(self.metadata[Snapshot.type])

    def test_update_snapshot_length_or_hash_mismatch(self) -> None:
        def modify_snapshot_length(timestamp: Timestamp) -> None:
            timestamp.snapshot_meta.length = 1

        # set known snapshot.json length to 1
        timestamp = self.modify_metadata(Timestamp.type, modify_snapshot_length)
        self.trusted_set.update_timestamp(timestamp)

        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_snapshot(self.metadata[Snapshot.type])

    def test_update_snapshot_fail_threshold_verification(self) -> None:
        self.trusted_set.update_timestamp(self.metadata[Timestamp.type])
        snapshot = Metadata.from_bytes(self.metadata[Snapshot.type])
        snapshot.signatures.clear()
        with self.assertRaises(exceptions.UnsignedMetadataError):
            self.trusted_set.update_snapshot(snapshot.to_bytes())

    def test_update_snapshot_version_diverge_timestamp_snapshot_version(
        self,
    ) -> None:
        def timestamp_version_modifier(timestamp: Timestamp) -> None:
            timestamp.snapshot_meta.version = 2

        timestamp = self.modify_metadata(
            Timestamp.type, timestamp_version_modifier
        )
        self.trusted_set.update_timestamp(timestamp)

        # if intermediate snapshot version is incorrect, load it but also raise
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata[Snapshot.type])

        # targets update starts but fails if snapshot version does not match
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_targets(self.metadata[Targets.type])

    def test_update_snapshot_file_removed_from_meta(self) -> None:
        self._update_all_besides_targets(self.metadata[Timestamp.type])

        def remove_file_from_meta(snapshot: Snapshot) -> None:
            del snapshot.meta["targets.json"]

        # Test removing a meta_file in new_snapshot compared to the old snapshot
        snapshot = self.modify_metadata(Snapshot.type, remove_file_from_meta)
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_snapshot(snapshot)

    def test_update_snapshot_meta_version_decreases(self) -> None:
        self.trusted_set.update_timestamp(self.metadata[Timestamp.type])

        def version_meta_modifier(snapshot: Snapshot) -> None:
            snapshot.meta["targets.json"].version += 1

        snapshot = self.modify_metadata(Snapshot.type, version_meta_modifier)
        self.trusted_set.update_snapshot(snapshot)

        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata[Snapshot.type])

    def test_update_snapshot_expired_new_snapshot(self) -> None:
        self.trusted_set.update_timestamp(self.metadata[Timestamp.type])

        def snapshot_expired_modifier(snapshot: Snapshot) -> None:
            snapshot.expires = datetime(1970, 1, 1, tzinfo=timezone.utc)

        # expired intermediate snapshot is loaded but will raise
        snapshot = self.modify_metadata(
            Snapshot.type, snapshot_expired_modifier
        )
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_snapshot(snapshot)

        # targets update does start but fails because snapshot is expired
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_targets(self.metadata[Targets.type])

    def test_update_snapshot_successful_rollback_checks(self) -> None:
        def meta_version_bump(timestamp: Timestamp) -> None:
            timestamp.snapshot_meta.version += 1
            # The timestamp version must be increased to initiate a update.
            timestamp.version += 1

        def version_bump(snapshot: Snapshot) -> None:
            snapshot.version += 1

        # load a "local" timestamp, then update to newer one:
        self.trusted_set.update_timestamp(self.metadata[Timestamp.type])
        new_timestamp = self.modify_metadata(Timestamp.type, meta_version_bump)
        self.trusted_set.update_timestamp(new_timestamp)

        # load a "local" snapshot with mismatching version (loading happens but
        # BadVersionNumberError is raised), then update to newer one:
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_snapshot(self.metadata[Snapshot.type])
        new_snapshot = self.modify_metadata(Snapshot.type, version_bump)
        self.trusted_set.update_snapshot(new_snapshot)

        # update targets to trigger final snapshot meta version check
        self.trusted_set.update_targets(self.metadata[Targets.type])

    def test_update_targets_no_meta_in_snapshot(self) -> None:
        def no_meta_modifier(snapshot: Snapshot) -> None:
            snapshot.meta = {}

        snapshot = self.modify_metadata(Snapshot.type, no_meta_modifier)
        self._update_all_besides_targets(
            self.metadata[Timestamp.type], snapshot
        )
        # remove meta information with information about targets from snapshot
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata[Targets.type])

    def test_update_targets_hash_diverge_from_snapshot_meta_hash(self) -> None:
        def meta_length_modifier(snapshot: Snapshot) -> None:
            for metafile_path in snapshot.meta:
                snapshot.meta[metafile_path] = MetaFile(version=1, length=1)

        snapshot = self.modify_metadata(Snapshot.type, meta_length_modifier)
        self._update_all_besides_targets(
            self.metadata[Timestamp.type], snapshot
        )
        # observed_hash != stored hash in snapshot meta for targets
        with self.assertRaises(exceptions.RepositoryError):
            self.trusted_set.update_targets(self.metadata[Targets.type])

    def test_update_targets_version_diverge_snapshot_meta_version(self) -> None:
        def meta_modifier(snapshot: Snapshot) -> None:
            for metafile_path in snapshot.meta:
                snapshot.meta[metafile_path] = MetaFile(version=2)

        snapshot = self.modify_metadata(Snapshot.type, meta_modifier)
        self._update_all_besides_targets(
            self.metadata[Timestamp.type], snapshot
        )
        # new_delegate.signed.version != meta.version stored in snapshot
        with self.assertRaises(exceptions.BadVersionNumberError):
            self.trusted_set.update_targets(self.metadata[Targets.type])

    def test_update_targets_expired_new_target(self) -> None:
        self._update_all_besides_targets()

        # new_delegated_target has expired
        def target_expired_modifier(target: Targets) -> None:
            target.expires = datetime(1970, 1, 1, tzinfo=timezone.utc)

        targets = self.modify_metadata(Targets.type, target_expired_modifier)
        with self.assertRaises(exceptions.ExpiredMetadataError):
            self.trusted_set.update_targets(targets)

    # TODO test updating over initial metadata (new keys, newer timestamp, etc)

    def test_load_from_simple_envelope(self) -> None:
        """Basic unit test for ``_load_from_simple_envelope`` helper.

        TODO: Test via trusted metadata set tests like for traditional metadata
        """
        metadata = Metadata.from_bytes(self.metadata[Root.type])
        root = metadata.signed
        envelope = SimpleEnvelope.from_signed(root)

        # Unwrap unsigned envelope without verification
        envelope_bytes = envelope.to_bytes()
        payload_obj, signed_bytes, signatures = _load_from_simple_envelope(
            Root, envelope_bytes
        )

        self.assertEqual(payload_obj, root)
        self.assertEqual(signed_bytes, envelope.pae())
        self.assertDictEqual(signatures, {})

        # Unwrap correctly signed envelope (use default role name)
        sig = envelope.sign(self.keystore[Root.type])
        envelope_bytes = envelope.to_bytes()
        _, _, signatures = _load_from_simple_envelope(
            Root, envelope_bytes, root
        )
        self.assertDictEqual(signatures, {sig.keyid: sig})

        # Load correctly signed envelope (with explicit role name)
        _, _, signatures = _load_from_simple_envelope(
            Root, envelope.to_bytes(), root, Root.type
        )
        self.assertDictEqual(signatures, {sig.keyid: sig})

        # Fail load envelope with unexpected 'payload_type'
        envelope_bad_type = SimpleEnvelope.from_signed(root)
        envelope_bad_type.payload_type = "foo"
        envelope_bad_type_bytes = envelope_bad_type.to_bytes()
        with self.assertRaises(exceptions.RepositoryError):
            _load_from_simple_envelope(Root, envelope_bad_type_bytes)

        # Fail load envelope with unexpected payload type
        envelope_bad_signed = SimpleEnvelope.from_signed(root)
        envelope_bad_signed_bytes = envelope_bad_signed.to_bytes()
        with self.assertRaises(exceptions.RepositoryError):
            _load_from_simple_envelope(Targets, envelope_bad_signed_bytes)


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
