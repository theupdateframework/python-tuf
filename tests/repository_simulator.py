#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

""""Test utility to simulate a repository

RepositorySimulator provides methods to modify repository metadata so that it's
easy to "publish" new repository versions with modified metadata, while serving
the versions to client test code.

RepositorySimulator implements FetcherInterface so Updaters in tests can use it
as a way to "download" new metadata from remote: in practice no downloading,
network connections or even file access happens as RepositorySimulator serves
everything from memory.
"""

import logging
from collections import OrderedDict
from datetime import datetime, timedelta
from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibSigner
from tuf.exceptions import FetcherHTTPError
from typing import Dict, Iterator, List, Optional, Tuple
from urllib import parse

from tuf.api.metadata import(
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    SPECIFICATION_VERSION,
    Snapshot,
    Targets,
    Timestamp
)
from tuf.ngclient.fetcher import FetcherInterface

logger = logging.getLogger(__name__)

SPEC_VER = ".".join(SPECIFICATION_VERSION)

class RepositorySimulator(FetcherInterface):
    def __init__(self):
        # all root versions are stored
        self.md_roots: Dict[int, Metadata[Root]] = {}
        self.md_timestamp: Metadata[Timestamp] = None
        self.md_snapshot: Metadata[Snapshot] = None
        self.md_targets: Metadata[Targets] = None
        # all targets in one dict
        self.md_delegates: Dict[str, Metadata[Targets]] = {}

        self.signers: Dict[str, List[SSlibSigner]] = {}

        self._initialize()

    @property
    def root(self) -> Root:
        raise NotImplementedError

    @property
    def timestamp(self) -> Timestamp:
        return self.md_timestamp.signed

    @property
    def snapshot(self) -> Snapshot:
        return self.md_snapshot.signed

    @property
    def targets(self) -> Targets:
        return self.md_targets.signed

    def delegates(self) -> Iterator[Tuple[str, Targets]]:
        for role, md in self.md_delegates.items():
            yield role, md.signed

    def _create_key(self, role:str) -> Key:
        sslib_key = generate_ed25519_key()
        if role not in self.signers:
            self.signers[role] = []
        self.signers[role].append(SSlibSigner(sslib_key))

        key = Key.from_securesystemslib_key(sslib_key)
        return key

    def _initialize(self):
        """Setup a minimal valid repository"""
        expiry = datetime.utcnow().replace(microsecond=0) + timedelta(days=30)

        targets = Targets(1, SPEC_VER, expiry, {}, None)
        self.md_targets = Metadata(targets, OrderedDict())

        meta = {"targets.json": MetaFile(targets.version)}
        snapshot = Snapshot(1, SPEC_VER, expiry, meta)
        self.md_snapshot = Metadata(snapshot, OrderedDict())

        meta = {"snapshot.json": MetaFile(snapshot.version)}
        timestamp = Timestamp(1, SPEC_VER, expiry, meta)
        self.md_timestamp = Metadata(timestamp, OrderedDict())

        keys = {}
        roles = {}
        for role in ["root", "timestamp", "snapshot", "targets"]:
            key = self._create_key(role)
            keys[key.keyid] = key
            roles[role] = Role([key.keyid], 1)
        root = Root(1, SPEC_VER, expiry, keys, roles, True)
        self.md_roots[1] = Metadata(root, OrderedDict())

    def fetch(self, url: str) -> Iterator[bytes]:
        spliturl = parse.urlparse(url)
        if spliturl.path.startswith("/metadata/"):
            parts = spliturl.path[len("/metadata/"):].split(".")
            if len(parts) == 3:
                version = int(parts[0])
                role = parts[1]
            else:
                version = None
                role = parts[0]
            yield self._fetch_metadata (role, version)
        else:
            raise FetcherHTTPError(f"Unknown path '{spliturl.path}'", 404)

    def _fetch_metadata(self, role: str, version: Optional[int] = None) -> bytes:
        if role == "root":
            md = self.md_roots.get(version)
        elif role == "timestamp":
            md = self.md_timestamp
        elif role == "snapshot":
            md = self.md_snapshot
        elif role == "targets":
            md = self.md_targets
        else:
            md = self.md_delegates.get(role)

        if md is None:
            raise FetcherHTTPError(f"Unknown role {role}", 404)

        md.signatures.clear()
        for signer in self.signers[role]:
            md.sign(signer)

        logger.debug("fetched metadata %s version %d", role, md.signed.version)
        return md.to_bytes()

    def update_timestamp(self):
        self.timestamp.meta["snapshot.json"].version = self.snapshot.version

        self.timestamp.version += 1

    def update_snapshot(self):
        self.snapshot.meta["targets.json"].version = self.targets.version
        for role, delegate in self.delegates():
            self.snapshot.meta[f"{role}.json"].version = delegate.version

        self.snapshot.version += 1
        self.update_timestamp()

    def write(self, directory:str):
        """Write current repository metadata to a directory"""
        raise NotImplementedError

