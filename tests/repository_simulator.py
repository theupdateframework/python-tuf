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

from collections import OrderedDict
from datetime import datetime, timedelta
import logging
import os
import tempfile
from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibSigner
from typing import Dict, Iterator, List, Optional, Tuple
from urllib import parse

from tuf.api.serialization.json import JSONSerializer
from tuf.exceptions import FetcherHTTPError
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
        self.md_root: Metadata[Root] = None
        self.md_timestamp: Metadata[Timestamp] = None
        self.md_snapshot: Metadata[Snapshot] = None
        self.md_targets: Metadata[Targets] = None
        self.md_delegates: Dict[str, Metadata[Targets]] = {}

        # other metadata is signed on-demand (when fetched) but roots must be
        # explicitly published with publish_root() which maintains this list
        self.signed_roots: List[bytes] = []

        # signers are used on-demand at fetch time to sign metadata
        self.signers: Dict[str, List[SSlibSigner]] = {}

        self.dump_dir = None
        self.dump_version = 0

        self._initialize()

    @property
    def root(self) -> Root:
        return self.md_root.signed

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

    def create_key(self) -> Tuple[Key, SSlibSigner]:
        sslib_key = generate_ed25519_key()
        return Key.from_securesystemslib_key(sslib_key), SSlibSigner(sslib_key)

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

        root = Root(1, SPEC_VER, expiry, {}, {}, True)
        for role in ["root", "timestamp", "snapshot", "targets"]:
            key, signer = self.create_key()
            root.roles[role] = Role([], 1)
            root.add_key(role, key)
            # store the private key
            if role not in self.signers:
                self.signers[role] = []
            self.signers[role].append(signer)
        self.md_root = Metadata(root, OrderedDict())
        self.publish_root()

    def publish_root(self):
        """Sign and store a new serialized version of root"""
        self.md_root.signatures.clear()
        for signer in self.signers["root"]:
            self.md_root.sign(signer)

        self.signed_roots.append(self.md_root.to_bytes(JSONSerializer()))
        logger.debug("Published root v%d", self.root.version)

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
            # return a version previously serialized in publish_root()
            if version > len(self.signed_roots):
                raise FetcherHTTPError(f"Unknown root version {version}", 404)
            logger.debug("fetched root version %d", role, version)
            return self.signed_roots[version - 1]
        else:
            # sign and serialize the requested metadata
            if role == "timestamp":
                md = self.md_timestamp
            elif role == "snapshot":
                md = self.md_snapshot
            elif role == "targets":
                md = self.md_targets
            else:
                md = self.md_delegates.get(role)

            if md is None:
                raise FetcherHTTPError(f"Unknown role {role}", 404)
            if version is not None and version != md.signed.version:
                raise FetcherHTTPError(f"Unknown {role} version {version}", 404)

            md.signatures.clear()
            for signer in self.signers[role]:
                md.sign(signer,append=True)

            logger.debug(
                "fetched %s v%d with %d sigs",
                role,
                md.signed.version,
                len(self.signers[role]))
            return md.to_bytes(JSONSerializer())

    def update_timestamp(self):
        self.timestamp.meta["snapshot.json"].version = self.snapshot.version

        self.timestamp.version += 1

    def update_snapshot(self):
        self.snapshot.meta["targets.json"].version = self.targets.version
        for role, delegate in self.delegates():
            self.snapshot.meta[f"{role}.json"].version = delegate.version

        self.snapshot.version += 1
        self.update_timestamp()

    def write(self):
        """Dump current repository metadata to self.dump_dir

        This is a debugging tool: dumping repository state before running
        Updater refresh may be useful while debugging a test.
        """
        if self.dump_dir is None:
            self.dump_dir = tempfile.mkdtemp()
            print(f"Repository Simulator dumps in {self.dump_dir}")

        self.dump_version += 1
        dir = os.path.join(self.dump_dir, str(self.dump_version))
        os.makedirs(dir)

        for ver in range(1, len(self.signed_roots) + 1):
            with open(os.path.join(dir, f"{ver}.root.json"), "wb") as f:
                f.write(self._fetch_metadata("root", ver))

        for role in ["timestamp", "snapshot", "targets"]:
            with open(os.path.join(dir, f"{role}.json"), "wb") as f:
                f.write(self._fetch_metadata(role))

        for role in self.md_delegates.keys():
            with open(os.path.join(dir, f"{role}.json"), "wb") as f:
                f.write(self._fetch_metadata(role))
