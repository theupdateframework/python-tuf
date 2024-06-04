# Copyright 2024 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for tuf.repository module"""

import copy
import logging
import sys
import unittest
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from securesystemslib.signer import CryptoSigner, Signer

from tests import utils
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.repository import Repository

logger = logging.getLogger(__name__)

_signed_init = {
    Root.type: Root,
    Snapshot.type: Snapshot,
    Targets.type: Targets,
    Timestamp.type: Timestamp,
}


class TestingRepository(Repository):
    """Very simple in-memory repository implementation

    This repository keeps the metadata for all versions of all roles in memory.
    It also keeps all target content in memory.

    Mostly copied from examples/repository.

    Attributes:
        role_cache: Every historical metadata version of every role in this
            repository. Keys are role names and values are lists of Metadata
        signer_cache: All signers available to the repository. Keys are role
            names, values are lists of signers
    """

    expiry_period = timedelta(days=1)

    def __init__(self) -> None:
        # all versions of all metadata
        self.role_cache: Dict[str, List[Metadata]] = defaultdict(list)
        # all current keys
        self.signer_cache: Dict[str, List[Signer]] = defaultdict(list)
        # version cache for snapshot and all targets, updated in close().
        # The 'defaultdict(lambda: ...)' trick allows close() to easily modify
        # the version without always creating a new MetaFile
        self._snapshot_info = MetaFile(1)
        self._targets_infos: Dict[str, MetaFile] = defaultdict(
            lambda: MetaFile(1)
        )

        # setup a basic repository, generate signing key per top-level role
        with self.edit_root() as root:
            for role in ["root", "timestamp", "snapshot", "targets"]:
                signer = CryptoSigner.generate_ecdsa()
                self.signer_cache[role].append(signer)
                root.add_key(signer.public_key, role)

        for role in ["timestamp", "snapshot", "targets"]:
            with self.edit(role):
                pass

    @property
    def targets_infos(self) -> Dict[str, MetaFile]:
        return self._targets_infos

    @property
    def snapshot_info(self) -> MetaFile:
        return self._snapshot_info

    def open(self, role: str) -> Metadata:
        """Return current Metadata for role from 'storage'
        (or create a new one)
        """

        if role not in self.role_cache:
            signed_init = _signed_init.get(role, Targets)
            md = Metadata(signed_init())

            # this makes version bumping in close() simpler
            md.signed.version = 0
            return md

        # return a _copy_ of latest metadata from storage
        return copy.deepcopy(self.role_cache[role][-1])

    def close(self, role: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        md.signed.version += 1
        md.signed.expires = datetime.now(timezone.utc) + self.expiry_period

        md.signatures.clear()
        for signer in self.signer_cache[role]:
            md.sign(signer, append=True)

        # store new metadata version, update version caches
        self.role_cache[role].append(md)
        if role == "snapshot":
            self._snapshot_info.version = md.signed.version
        elif role not in ["root", "timestamp"]:
            self._targets_infos[f"{role}.json"].version = md.signed.version


class TestRepository(unittest.TestCase):
    """Tests for tuf.repository module."""

    def setUp(self) -> None:
        self.repo = TestingRepository()

    def test_initial_repo_setup(self) -> None:
        # check that we have metadata for top level roles
        self.assertEqual(4, len(self.repo.role_cache))
        for role in TOP_LEVEL_ROLE_NAMES:
            # There should be a single version for each role
            role_versions = self.repo.role_cache[role]
            self.assertEqual(1, len(role_versions))
            self.assertEqual(1, role_versions[-1].signed.version)

        # test the Repository helpers:
        self.assertIsInstance(self.repo.root(), Root)
        self.assertIsInstance(self.repo.timestamp(), Timestamp)
        self.assertIsInstance(self.repo.snapshot(), Snapshot)
        self.assertIsInstance(self.repo.targets(), Targets)

    def test_do_snapshot(self) -> None:
        # Expect no-op because targets have not changed and snapshot is still valid
        created, _ = self.repo.do_snapshot()

        self.assertFalse(created)
        snapshot_versions = self.repo.role_cache["snapshot"]
        self.assertEqual(1, len(snapshot_versions))
        self.assertEqual(1, snapshot_versions[-1].signed.version)

    def test_do_snapshot_after_targets_change(self) -> None:
        # do a targets change, expect do_snapshot to create a new snapshot
        with self.repo.edit_targets() as targets:
            targets.targets["path"] = TargetFile.from_data("path", b"data")

        created, _ = self.repo.do_snapshot()

        self.assertTrue(created)
        snapshot_versions = self.repo.role_cache["snapshot"]
        self.assertEqual(2, len(snapshot_versions))
        self.assertEqual(2, snapshot_versions[-1].signed.version)

    def test_do_snapshot_after_new_targets_delegation(self) -> None:
        # Add new delegated target, expect do_snapshot to create a new snapshot

        signer = CryptoSigner.generate_ecdsa()
        self.repo.signer_cache["delegated"].append(signer)

        # Add a new delegation to targets
        with self.repo.edit_targets() as targets:
            role = DelegatedRole("delegated", [], 1, True, [])
            targets.delegations = Delegations({}, {"delegated": role})

            targets.add_key(signer.public_key, "delegated")

        # create a version of the delegated metadata
        with self.repo.edit("delegated") as _:
            pass

        created, _ = self.repo.do_snapshot()

        self.assertTrue(created)
        snapshot_versions = self.repo.role_cache["snapshot"]
        self.assertEqual(2, len(snapshot_versions))
        self.assertEqual(2, snapshot_versions[-1].signed.version)

    def test_do_snapshot_after_snapshot_key_change(self) -> None:
        # change snapshot signing keys
        with self.repo.edit_root() as root:
            # remove key
            keyid = root.roles["snapshot"].keyids[0]
            root.revoke_key(keyid, "snapshot")
            self.repo.signer_cache["snapshot"].clear()

            # add new key
            signer = CryptoSigner.generate_ecdsa()
            self.repo.signer_cache["snapshot"].append(signer)
            root.add_key(signer.public_key, "snapshot")

        # snapshot is no longer signed correctly, expect do_snapshot to create a new snapshot
        created, _ = self.repo.do_snapshot()

        self.assertTrue(created)
        snapshot_versions = self.repo.role_cache["snapshot"]
        self.assertEqual(2, len(snapshot_versions))
        self.assertEqual(2, snapshot_versions[-1].signed.version)

    def test_do_timestamp(self) -> None:
        # Expect no-op because snpashot has not changed and timestamp is still valid
        created, _ = self.repo.do_timestamp()

        self.assertFalse(created)
        timestamp_versions = self.repo.role_cache["timestamp"]
        self.assertEqual(1, len(timestamp_versions))
        self.assertEqual(1, timestamp_versions[-1].signed.version)

    def test_do_timestamp_after_snapshot_change(self) -> None:
        # do a snapshot change, expect do_timestamp to create a new timestamp
        self.repo.do_snapshot(force=True)

        created, _ = self.repo.do_timestamp()

        self.assertTrue(created)
        timestamp_versions = self.repo.role_cache["timestamp"]
        self.assertEqual(2, len(timestamp_versions))
        self.assertEqual(2, timestamp_versions[-1].signed.version)

    def test_do_timestamp_after_timestamp_key_change(self) -> None:
        # change timestamp signing keys
        with self.repo.edit_root() as root:
            # remove key
            keyid = root.roles["timestamp"].keyids[0]
            root.revoke_key(keyid, "timestamp")
            self.repo.signer_cache["timestamp"].clear()

            # add new key
            signer = CryptoSigner.generate_ecdsa()
            self.repo.signer_cache["timestamp"].append(signer)
            root.add_key(signer.public_key, "timestamp")

        # timestamp is no longer signed correctly, expect do_timestamp to create a new timestamp
        created, _ = self.repo.do_timestamp()

        self.assertTrue(created)
        timestamp_versions = self.repo.role_cache["timestamp"]
        self.assertEqual(2, len(timestamp_versions))
        self.assertEqual(2, timestamp_versions[-1].signed.version)


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
