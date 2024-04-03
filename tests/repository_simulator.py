# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test utility to simulate a repository

RepositorySimulator provides methods to modify repository metadata so that it's
easy to "publish" new repository versions with modified metadata, while serving
the versions to client test code.

RepositorySimulator implements FetcherInterface so Updaters in tests can use it
as a way to "download" new metadata from remote: in practice no downloading,
network connections or even file access happens as RepositorySimulator serves
everything from memory.

Metadata and targets "hosted" by the simulator are made available in URL paths
"/metadata/..." and "/targets/..." respectively.

Example::

    # constructor creates repository with top-level metadata
    sim = RepositorySimulator()

    # metadata can be modified directly: it is immediately available to clients
    sim.snapshot.version += 1

    # As an exception, new root versions require explicit publishing
    sim.root.version += 1
    sim.publish_root()

    # there are helper functions
    sim.add_target("targets", b"content", "targetpath")
    sim.targets.version += 1
    sim.update_snapshot()

    # Use the simulated repository from an Updater:
    updater = Updater(
        dir,
        "https://example.com/metadata/",
        "https://example.com/targets/",
        sim
    )
    updater.refresh()
"""

import datetime
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple
from urllib import parse

import securesystemslib.hash as sslib_hash
from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.exceptions import DownloadHTTPError
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient.fetcher import FetcherInterface

logger = logging.getLogger(__name__)

SPEC_VER = ".".join(SPECIFICATION_VERSION)


@dataclass
class FetchTracker:
    """Fetcher counter for metadata and targets."""

    metadata: List[Tuple[str, Optional[int]]] = field(default_factory=list)
    targets: List[Tuple[str, Optional[str]]] = field(default_factory=list)


@dataclass
class RepositoryTarget:
    """Contains actual target data and the related target metadata."""

    data: bytes
    target_file: TargetFile


class RepositorySimulator(FetcherInterface):
    """Simulates a repository that can be used for testing."""

    def __init__(self) -> None:
        self.md_delegates: Dict[str, Metadata[Targets]] = {}

        # other metadata is signed on-demand (when fetched) but roots must be
        # explicitly published with publish_root() which maintains this list
        self.signed_roots: List[bytes] = []

        # signers are used on-demand at fetch time to sign metadata
        # keys are roles, values are dicts of {keyid: signer}
        self.signers: Dict[str, Dict[str, Signer]] = {}

        # target downloads are served from this dict
        self.target_files: Dict[str, RepositoryTarget] = {}

        # Whether to compute hashes and length for meta in snapshot/timestamp
        self.compute_metafile_hashes_length = False

        # Enable hash-prefixed target file names
        self.prefix_targets_with_hash = True

        self.dump_dir: Optional[str] = None
        self.dump_version = 0

        self.fetch_tracker = FetchTracker()

        now = datetime.datetime.now(datetime.timezone.utc)
        self.safe_expiry = now.replace(microsecond=0) + datetime.timedelta(
            days=30
        )

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

    def all_targets(self) -> Iterator[Tuple[str, Targets]]:
        """Yield role name and signed portion of targets one by one."""
        yield Targets.type, self.md_targets.signed
        for role, md in self.md_delegates.items():
            yield role, md.signed

    def add_signer(self, role: str, signer: Signer) -> None:
        if role not in self.signers:
            self.signers[role] = {}
        self.signers[role][signer.public_key.keyid] = signer

    def rotate_keys(self, role: str) -> None:
        """remove all keys for role, then add threshold of new keys"""
        self.root.roles[role].keyids.clear()
        self.signers[role].clear()
        for _ in range(self.root.roles[role].threshold):
            signer = CryptoSigner.generate_ed25519()
            self.root.add_key(signer.public_key, role)
            self.add_signer(role, signer)

    def _initialize(self) -> None:
        """Setup a minimal valid repository."""

        self.md_targets = Metadata(Targets(expires=self.safe_expiry))
        self.md_snapshot = Metadata(Snapshot(expires=self.safe_expiry))
        self.md_timestamp = Metadata(Timestamp(expires=self.safe_expiry))
        self.md_root = Metadata(Root(expires=self.safe_expiry))

        for role in TOP_LEVEL_ROLE_NAMES:
            signer = CryptoSigner.generate_ed25519()
            self.md_root.signed.add_key(signer.public_key, role)
            self.add_signer(role, signer)

        self.publish_root()

    def publish_root(self) -> None:
        """Sign and store a new serialized version of root."""
        self.md_root.signatures.clear()
        for signer in self.signers[Root.type].values():
            self.md_root.sign(signer, append=True)

        self.signed_roots.append(self.md_root.to_bytes(JSONSerializer()))
        logger.debug("Published root v%d", self.root.version)

    def _fetch(self, url: str) -> Iterator[bytes]:
        """Fetches data from the given url and returns an Iterator (or yields
        bytes).
        """
        path = parse.urlparse(url).path
        if path.startswith("/metadata/") and path.endswith(".json"):
            # figure out rolename and version
            ver_and_name = path[len("/metadata/") :][: -len(".json")]
            version_str, _, role = ver_and_name.partition(".")
            # root is always version-prefixed while timestamp is always NOT
            if role == Root.type or (
                self.root.consistent_snapshot and ver_and_name != Timestamp.type
            ):
                version: Optional[int] = int(version_str)
            else:
                # the file is not version-prefixed
                role = ver_and_name
                version = None

            yield self.fetch_metadata(role, version)
        elif path.startswith("/targets/"):
            # figure out target path and hash prefix
            target_path = path[len("/targets/") :]
            dir_parts, sep, prefixed_filename = target_path.rpartition("/")
            # extract the hash prefix, if any
            prefix: Optional[str] = None
            filename = prefixed_filename
            if self.root.consistent_snapshot and self.prefix_targets_with_hash:
                prefix, _, filename = prefixed_filename.partition(".")
            target_path = f"{dir_parts}{sep}{filename}"

            yield self.fetch_target(target_path, prefix)
        else:
            raise DownloadHTTPError(f"Unknown path '{path}'", 404)

    def fetch_target(
        self, target_path: str, target_hash: Optional[str]
    ) -> bytes:
        """Return data for 'target_path', checking 'target_hash' if it is given.

        If hash is None, then consistent_snapshot is not used.
        """
        self.fetch_tracker.targets.append((target_path, target_hash))

        repo_target = self.target_files.get(target_path)
        if repo_target is None:
            raise DownloadHTTPError(f"No target {target_path}", 404)
        if (
            target_hash
            and target_hash not in repo_target.target_file.hashes.values()
        ):
            raise DownloadHTTPError(f"hash mismatch for {target_path}", 404)

        logger.debug("fetched target %s", target_path)
        return repo_target.data

    def fetch_metadata(self, role: str, version: Optional[int] = None) -> bytes:
        """Return signed metadata for 'role', using 'version' if it is given.

        If version is None, non-versioned metadata is being requested.
        """
        self.fetch_tracker.metadata.append((role, version))
        # decode role for the metadata
        role = parse.unquote(role, encoding="utf-8")

        if role == Root.type:
            # return a version previously serialized in publish_root()
            if version is None or version > len(self.signed_roots):
                raise DownloadHTTPError(f"Unknown root version {version}", 404)
            logger.debug("fetched root version %d", version)
            return self.signed_roots[version - 1]

        # sign and serialize the requested metadata
        md: Optional[Metadata]
        if role == Timestamp.type:
            md = self.md_timestamp
        elif role == Snapshot.type:
            md = self.md_snapshot
        elif role == Targets.type:
            md = self.md_targets
        else:
            md = self.md_delegates.get(role)

        if md is None:
            raise DownloadHTTPError(f"Unknown role {role}", 404)

        md.signatures.clear()
        for signer in self.signers[role].values():
            md.sign(signer, append=True)

        logger.debug(
            "fetched %s v%d with %d sigs",
            role,
            md.signed.version,
            len(self.signers[role]),
        )
        return md.to_bytes(JSONSerializer())

    def _compute_hashes_and_length(
        self, role: str
    ) -> Tuple[Dict[str, str], int]:
        data = self.fetch_metadata(role)
        digest_object = sslib_hash.digest(sslib_hash.DEFAULT_HASH_ALGORITHM)
        digest_object.update(data)
        hashes = {sslib_hash.DEFAULT_HASH_ALGORITHM: digest_object.hexdigest()}
        return hashes, len(data)

    def update_timestamp(self) -> None:
        """Update timestamp and assign snapshot version to snapshot_meta
        version.
        """

        hashes = None
        length = None
        if self.compute_metafile_hashes_length:
            hashes, length = self._compute_hashes_and_length(Snapshot.type)

        self.timestamp.snapshot_meta = MetaFile(
            self.snapshot.version, length, hashes
        )

        self.timestamp.version += 1

    def update_snapshot(self) -> None:
        """Update snapshot, assign targets versions and update timestamp."""
        for role, delegate in self.all_targets():
            hashes = None
            length = None
            if self.compute_metafile_hashes_length:
                hashes, length = self._compute_hashes_and_length(role)

            self.snapshot.meta[f"{role}.json"] = MetaFile(
                delegate.version, length, hashes
            )

        self.snapshot.version += 1
        self.update_timestamp()

    def _get_delegator(self, delegator_name: str) -> Targets:
        """Given a delegator name return, its corresponding Targets object."""
        if delegator_name == Targets.type:
            return self.targets

        return self.md_delegates[delegator_name].signed

    def add_target(self, role: str, data: bytes, path: str) -> None:
        """Create a target from data and add it to the target_files."""
        targets = self._get_delegator(role)

        target = TargetFile.from_data(path, data, ["sha256"])
        targets.targets[path] = target
        self.target_files[path] = RepositoryTarget(data, target)

    def add_delegation(
        self, delegator_name: str, role: DelegatedRole, targets: Targets
    ) -> None:
        """Add delegated target role to the repository."""
        delegator = self._get_delegator(delegator_name)

        if (
            delegator.delegations is not None
            and delegator.delegations.succinct_roles is not None
        ):
            raise ValueError("Can't add a role when succinct_roles is used")

        # Create delegation
        if delegator.delegations is None:
            delegator.delegations = Delegations({}, roles={})

        assert delegator.delegations.roles is not None
        # put delegation last by default
        delegator.delegations.roles[role.name] = role

        # By default add one new key for the role
        signer = CryptoSigner.generate_ed25519()
        delegator.add_key(signer.public_key, role.name)
        self.add_signer(role.name, signer)

        # Add metadata for the role
        if role.name not in self.md_delegates:
            self.md_delegates[role.name] = Metadata(targets, {})

    def add_succinct_roles(
        self, delegator_name: str, bit_length: int, name_prefix: str
    ) -> None:
        """Add succinct roles info to a delegator with name "delegator_name".

        Note that for each delegated role represented by succinct roles an empty
        Targets instance is created.
        """
        delegator = self._get_delegator(delegator_name)

        if (
            delegator.delegations is not None
            and delegator.delegations.roles is not None
        ):
            raise ValueError(
                "Can't add a succinct_roles when delegated roles are used"
            )

        signer = CryptoSigner.generate_ed25519()
        succinct_roles = SuccinctRoles([], 1, bit_length, name_prefix)
        delegator.delegations = Delegations({}, None, succinct_roles)

        # Add targets metadata for all bins.
        for delegated_name in succinct_roles.get_roles():
            self.md_delegates[delegated_name] = Metadata(
                Targets(expires=self.safe_expiry)
            )

            self.add_signer(delegated_name, signer)

        delegator.add_key(signer.public_key)

    def write(self) -> None:
        """Dump current repository metadata to self.dump_dir

        This is a debugging tool: dumping repository state before running
        Updater refresh may be useful while debugging a test.
        """
        if self.dump_dir is None:
            self.dump_dir = tempfile.mkdtemp()
            print(f"Repository Simulator dumps in {self.dump_dir}")

        self.dump_version += 1
        dest_dir = os.path.join(self.dump_dir, str(self.dump_version))
        os.makedirs(dest_dir)

        for ver in range(1, len(self.signed_roots) + 1):
            with open(os.path.join(dest_dir, f"{ver}.root.json"), "wb") as f:
                f.write(self.fetch_metadata(Root.type, ver))

        for role in [Timestamp.type, Snapshot.type, Targets.type]:
            with open(os.path.join(dest_dir, f"{role}.json"), "wb") as f:
                f.write(self.fetch_metadata(role))

        for role in self.md_delegates:
            quoted_role = parse.quote(role, "")
            with open(os.path.join(dest_dir, f"{quoted_role}.json"), "wb") as f:
                f.write(self.fetch_metadata(role))
