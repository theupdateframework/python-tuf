# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Simple example of using the repository library to build a repository"""

import copy
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from securesystemslib import keys
from securesystemslib.signer import Signer, SSlibSigner

from tuf.api.metadata import (
    Key,
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


class SimpleRepository(Repository):
    """Very simple in-memory repository implementation

    This repository keeps the metadata for all versions of all roles in memory.
    It also keeps all target content in memory.


    Attributes:
        role_cache: Every historical metadata version of every role in this
            repository. Keys are role names and values are lists of Metadata
        signer_cache: All signers available to the repository. Keys are role
            names, values are lists of signers
        target_cache: All target files served by the repository. Keys are
            target paths and values are file contents as bytes.
    """

    expiry_period = timedelta(days=1)

    def __init__(self) -> None:
        # all versions of all metadata
        self.role_cache: Dict[str, List[Metadata]] = defaultdict(list)
        # all current keys
        self.signer_cache: Dict[str, List[Signer]] = defaultdict(list)
        # all target content
        self.target_cache: Dict[str, bytes] = {}
        # version cache for snapshot and all targets, updated in close().
        # The 'defaultdict(lambda: ...)' trick allows close() to easily modify
        # the version without always creating a new MetaFile
        self._snapshot_info = MetaFile(1)
        self._targets_infos: Dict[str, MetaFile] = defaultdict(
            lambda: MetaFile(1)
        )

        # setup a basic repository, generate signing key per top-level role
        with self.edit("root") as root:
            for role in ["root", "timestamp", "snapshot", "targets"]:
                key = keys.generate_ed25519_key()
                self.signer_cache[role].append(SSlibSigner(key))
                root.add_key(Key.from_securesystemslib_key(key), role)

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
        """Return current Metadata for role from 'storage' (or create a new one)"""

        if role not in self.role_cache:
            signed_init = _signed_init.get(role, Targets)
            md = Metadata(signed_init())

            # this makes version bumping in close() simpler
            md.signed.version = 0
            return md

        # return latest metadata from storage (but don't return a reference)
        return copy.deepcopy(self.role_cache[role][-1])

    def close(self, role: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        md.signed.version += 1
        md.signed.expires = datetime.utcnow() + self.expiry_period

        md.signatures.clear()
        for signer in self.signer_cache[role]:
            md.sign(signer, append=True)

        # store new metadata version, update version caches
        self.role_cache[role].append(md)
        if role == "snapshot":
            self._snapshot_info.version = md.signed.version
        elif role not in ["root", "timestamp"]:
            self._targets_infos[f"{role}.json"].version = md.signed.version

    def add_target(self, path: str, content: str) -> None:
        """Add a target to repository"""
        data = bytes(content, "utf-8")

        # add content to cache for serving to clients
        self.target_cache[path] = data

        # add a target in the targets metadata
        with self.edit("targets") as targets:
            targets.targets[path] = TargetFile.from_data(path, data)

        logger.debug("Targets v%d", targets.version)

        # update snapshot, timestamp
        self.snapshot()
        self.timestamp()
