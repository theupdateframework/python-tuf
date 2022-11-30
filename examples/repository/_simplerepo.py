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
        role_cache: Contains every historical metadata version of every role in
            this repositorys. Keys are rolenames and values are lists of
            Metadata
        signer_cache: Contains all signers available to the repository. Keys
            are rolenames, values are lists of signers
        target_cache:
    """

    expiry_period = timedelta(days=1)

    def __init__(self) -> None:
        # all versions of all metadata
        self.role_cache: Dict[str, List[Metadata]] = defaultdict(list)
        # all current keys
        self.signer_cache: Dict[str, List[Signer]] = defaultdict(list)
        # all target content
        self.target_cache: Dict[str, bytes] = {}

        # setup a basic repository, generate signing key per top-level role
        with self.edit("root", init=True) as root:
            for role in ["root", "timestamp", "snapshot", "targets"]:
                key = keys.generate_ed25519_key()
                self.signer_cache[role].append(SSlibSigner(key))
                root.add_key(Key.from_securesystemslib_key(key), role)

        for role in ["timestamp", "snapshot", "targets"]:
            with self.edit(role, init=True):
                pass

    @property
    def targets_infos(self) -> Dict[str, MetaFile]:
        # TODO should track changes to snapshot meta and not recreate it here
        targets: Targets = self.role_cache["targets"][-1].signed
        return {"targets.json": MetaFile(targets.version)}

    @property
    def snapshot_info(self) -> MetaFile:
        snapshot = self.role_cache["snapshot"][-1].signed
        return MetaFile(snapshot.version)

    def open(self, role: str, init: bool = False) -> Metadata:
        """Return current Metadata for role from 'storage' (or create a new one)"""

        if init:
            signed_init = _signed_init.get(role, Targets)
            md = Metadata(signed_init())

            # this makes version bumping in close() simpler
            md.signed.version = 0
            return md

        # return latest metadata from storage (but don't return a reference)
        return copy.deepcopy(self.role_cache[role][-1])

    def close(self, role: str, md: Metadata, sign_only: bool = False) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        if sign_only:
            for signer in self.signer_cache[role]:
                md.sign(signer, append=True)
            self.role_cache[role][-1] = md
        else:
            md.signed.version += 1
            md.signed.expires = datetime.utcnow() + self.expiry_period

            md.signatures.clear()
            for signer in self.signer_cache[role]:
                md.sign(signer, append=True)

            self.role_cache[role].append(md)

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
