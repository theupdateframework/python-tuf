# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Trusted collection of client-side TUF Metadata

TrustedMetadataSet keeps track of the current valid set of metadata for the
client, and handles almost every step of the "Detailed client workflow" (
https://theupdateframework.github.io/specification/latest#detailed-client-workflow)
in the TUF specification: the remaining steps are related to filesystem and
network IO, which are not handled here.

Loaded metadata can be accessed via index access with rolename as key
(trusted_set["root"]) or, in the case of top-level metadata, using the helper
properties (trusted_set.root).

The rules for top-level metadata are
 * Metadata is updatable only if metadata it depends on is loaded
 * Metadata is not updatable if any metadata depending on it has been loaded
 * Metadata must be updated in order:
   root -> timestamp -> snapshot -> targets -> (delegated targets)

Exceptions are raised if metadata fails to load in any way.

Example of loading root, timestamp and snapshot:

>>> # Load local root (RepositoryErrors here stop the update)
>>> with open(root_path, "rb") as f:
>>>     trusted_set = TrustedMetadataSet(f.read())
>>>
>>> # update root from remote until no more are available
>>> with download("root", trusted_set.root.signed.version + 1) as f:
>>>     trusted_set.update_root(f.read())
>>>
>>> # load local timestamp, then update from remote
>>> try:
>>>     with open(timestamp_path, "rb") as f:
>>>         trusted_set.update_timestamp(f.read())
>>> except (RepositoryError, OSError):
>>>     pass # failure to load a local file is ok
>>>
>>> with download("timestamp") as f:
>>>     trusted_set.update_timestamp(f.read())
>>>
>>> # load local snapshot, then update from remote if needed
>>> try:
>>>     with open(snapshot_path, "rb") as f:
>>>         trusted_set.update_snapshot(f.read())
>>> except (RepositoryError, OSError):
>>>     # local snapshot is not valid, load from remote
>>>     # (RepositoryErrors here stop the update)
>>>     with download("snapshot", version) as f:
>>>         trusted_set.update_snapshot(f.read())

TODO:
 * exceptions are not final: the idea is that client could just handle
   a generic RepositoryError that covers every issue that server provided
   metadata could inflict (other errors would be user errors), but this is not
   yet the case
 * Progress through Specification update process should be documented
   (not sure yet how: maybe a spec_logger that logs specification events?)
"""

import logging
from collections import abc
from datetime import datetime
from typing import Dict, Iterator, Optional

from tuf import exceptions
from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp
from tuf.api.serialization import DeserializationError

logger = logging.getLogger(__name__)


class TrustedMetadataSet(abc.Mapping):
    """Internal class to keep track of trusted metadata in Updater

    TrustedMetadataSet ensures that the collection of metadata in it is valid
    and trusted through the whole client update workflow. It provides easy ways
    to update the metadata with the caller making decisions on what is updated.
    """

    def __init__(self, root_data: bytes):
        """Initialize TrustedMetadataSet by loading trusted root metadata

        Args:
            root_data: Trusted root metadata as bytes. Note that this metadata
                will only be verified by itself: it is the source of trust for
                all metadata in the TrustedMetadataSet

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        self._trusted_set: Dict[str, Metadata] = {}
        self.reference_time = datetime.utcnow()

        # Load and validate the local root metadata. Valid initial trusted root
        # metadata is required
        logger.debug("Updating initial trusted root")
        self._load_trusted_root(root_data)

    def __getitem__(self, role: str) -> Metadata:
        """Returns current Metadata for 'role'"""
        return self._trusted_set[role]

    def __len__(self) -> int:
        """Returns number of Metadata objects in TrustedMetadataSet"""
        return len(self._trusted_set)

    def __iter__(self) -> Iterator[Metadata]:
        """Returns iterator over all Metadata objects in TrustedMetadataSet"""
        return iter(self._trusted_set.values())

    # Helper properties for top level metadata
    @property
    def root(self) -> Metadata[Root]:
        """Current root Metadata"""
        return self._trusted_set["root"]

    @property
    def timestamp(self) -> Optional[Metadata[Timestamp]]:
        """Current timestamp Metadata or None"""
        return self._trusted_set.get("timestamp")

    @property
    def snapshot(self) -> Optional[Metadata[Snapshot]]:
        """Current snapshot Metadata or None"""
        return self._trusted_set.get("snapshot")

    @property
    def targets(self) -> Optional[Metadata[Targets]]:
        """Current targets Metadata or None"""
        return self._trusted_set.get("targets")

    # Methods for updating metadata
    def update_root(self, data: bytes) -> None:
        """Verifies and loads 'data' as new root metadata.

        Note that an expired intermediate root is considered valid: expiry is
        only checked for the final root in update_timestamp().

        Args:
            data: unverified new root metadata as bytes

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        if self.timestamp is not None:
            raise RuntimeError("Cannot update root after timestamp")
        logger.debug("Updating root")

        try:
            new_root = Metadata[Root].from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load root") from e

        if new_root.signed.type != "root":
            raise exceptions.RepositoryError(
                f"Expected 'root', got '{new_root.signed.type}'"
            )

        # Verify that new root is signed by trusted root
        self.root.verify_delegate("root", new_root)

        if new_root.signed.version != self.root.signed.version + 1:
            raise exceptions.ReplayedMetadataError(
                "root", new_root.signed.version, self.root.signed.version
            )

        # Verify that new root is signed by itself
        new_root.verify_delegate("root", new_root)

        self._trusted_set["root"] = new_root
        logger.debug("Updated root")

    def update_timestamp(self, data: bytes) -> None:
        """Verifies and loads 'data' as new timestamp metadata.

        Note that an expired intermediate timestamp is considered valid so it
        can be used for rollback checks on newer, final timestamp. Expiry is
        only checked for the final timestamp in update_snapshot().

        Args:
            data: unverified new timestamp metadata as bytes

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        if self.snapshot is not None:
            raise RuntimeError("Cannot update timestamp after snapshot")

        # client workflow 5.3.10: Make sure final root is not expired.
        if self.root.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("Final root.json is expired")
        # No need to check for 5.3.11 (fast forward attack recovery):
        # timestamp/snapshot can not yet be loaded at this point

        try:
            new_timestamp = Metadata[Timestamp].from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load timestamp") from e

        if new_timestamp.signed.type != "timestamp":
            raise exceptions.RepositoryError(
                f"Expected 'timestamp', got '{new_timestamp.signed.type}'"
            )

        self.root.verify_delegate("timestamp", new_timestamp)

        # If an existing trusted timestamp is updated,
        # check for a rollback attack
        if self.timestamp is not None:
            # Prevent rolling back timestamp version
            if new_timestamp.signed.version < self.timestamp.signed.version:
                raise exceptions.ReplayedMetadataError(
                    "timestamp",
                    new_timestamp.signed.version,
                    self.timestamp.signed.version,
                )
            # Prevent rolling back snapshot version
            if (
                new_timestamp.signed.meta["snapshot.json"].version
                < self.timestamp.signed.meta["snapshot.json"].version
            ):
                raise exceptions.ReplayedMetadataError(
                    "snapshot",
                    new_timestamp.signed.meta["snapshot.json"].version,
                    self.timestamp.signed.meta["snapshot.json"].version,
                )

        # expiry not checked to allow old timestamp to be used for rollback
        # protection of new timestamp: expiry is checked in update_snapshot()

        self._trusted_set["timestamp"] = new_timestamp
        logger.debug("Updated timestamp")

    def update_snapshot(self, data: bytes) -> None:
        """Verifies and loads 'data' as new snapshot metadata.

        Note that intermediate snapshot is considered valid even if it is
        expired or the version does not match the timestamp meta version. This
        means the intermediate snapshot can be used for rollback checks on
        newer, final snapshot. Expiry and meta version are only checked for
        the final snapshot in update_delegated_targets().

        Args:
            data: unverified new snapshot metadata as bytes

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """

        if self.timestamp is None:
            raise RuntimeError("Cannot update snapshot before timestamp")
        if self.targets is not None:
            raise RuntimeError("Cannot update snapshot after targets")
        logger.debug("Updating snapshot")

        # Local timestamp was allowed to be expired to allow for rollback
        # checks on new timestamp but now timestamp must not be expired
        if self.timestamp.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("timestamp.json is expired")

        meta = self.timestamp.signed.meta["snapshot.json"]

        # Verify against the hashes in timestamp, if any
        try:
            meta.verify_length_and_hashes(data)
        except exceptions.LengthOrHashMismatchError as e:
            raise exceptions.RepositoryError(
                "Snapshot length or hashes do not match"
            ) from e

        try:
            new_snapshot = Metadata[Snapshot].from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load snapshot") from e

        if new_snapshot.signed.type != "snapshot":
            raise exceptions.RepositoryError(
                f"Expected 'snapshot', got '{new_snapshot.signed.type}'"
            )

        self.root.verify_delegate("snapshot", new_snapshot)

        # version not checked against meta version to allow old snapshot to be
        # used in rollback protection: it is checked when targets is updated

        # If an existing trusted snapshot is updated, check for rollback attack
        if self.snapshot is not None:
            for filename, fileinfo in self.snapshot.signed.meta.items():
                new_fileinfo = new_snapshot.signed.meta.get(filename)

                # Prevent removal of any metadata in meta
                if new_fileinfo is None:
                    raise exceptions.RepositoryError(
                        f"New snapshot is missing info for '{filename}'"
                    )

                # Prevent rollback of any metadata versions
                if new_fileinfo.version < fileinfo.version:
                    raise exceptions.BadVersionNumberError(
                        f"Expected {filename} version "
                        f"{new_fileinfo.version}, got {fileinfo.version}."
                    )

        # expiry not checked to allow old snapshot to be used for rollback
        # protection of new snapshot: it is checked when targets is updated

        self._trusted_set["snapshot"] = new_snapshot
        logger.debug("Updated snapshot")

    def _check_final_snapshot(self) -> None:
        """Check snapshot expiry and version before targets is updated"""

        assert self.snapshot is not None  # nosec
        assert self.timestamp is not None  # nosec
        if self.snapshot.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("snapshot.json is expired")

        if (
            self.snapshot.signed.version
            != self.timestamp.signed.meta["snapshot.json"].version
        ):
            raise exceptions.BadVersionNumberError(
                f"Expected snapshot version "
                f"{self.timestamp.signed.meta['snapshot.json'].version}, "
                f"got {self.snapshot.signed.version}"
            )

    def update_targets(self, data: bytes) -> None:
        """Verifies and loads 'data' as new top-level targets metadata.

        Args:
            data: unverified new targets metadata as bytes

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        self.update_delegated_targets(data, "targets", "root")

    def update_delegated_targets(
        self, data: bytes, role_name: str, delegator_name: str
    ) -> None:
        """Verifies and loads 'data' as new metadata for target 'role_name'.

        Args:
            data: unverified new metadata as bytes
            role_name: The role name of the new metadata
            delegator_name: The name of the role delegating to the new metadata

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        if self.snapshot is None:
            raise RuntimeError("Cannot load targets before snapshot")

        # Local snapshot was allowed to be expired and to not match meta
        # version to allow for rollback checks on new snapshot but now
        # snapshot must not be expired and must match meta version
        self._check_final_snapshot()

        delegator: Optional[Metadata] = self.get(delegator_name)
        if delegator is None:
            raise RuntimeError("Cannot load targets before delegator")

        logger.debug("Updating %s delegated by %s", role_name, delegator_name)

        # Verify against the hashes in snapshot, if any
        meta = self.snapshot.signed.meta.get(f"{role_name}.json")
        if meta is None:
            raise exceptions.RepositoryError(
                f"Snapshot does not contain information for '{role_name}'"
            )

        try:
            meta.verify_length_and_hashes(data)
        except exceptions.LengthOrHashMismatchError as e:
            raise exceptions.RepositoryError(
                f"{role_name} length or hashes do not match"
            ) from e

        try:
            new_delegate = Metadata[Targets].from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load snapshot") from e

        if new_delegate.signed.type != "targets":
            raise exceptions.RepositoryError(
                f"Expected 'targets', got '{new_delegate.signed.type}'"
            )

        delegator.verify_delegate(role_name, new_delegate)

        if new_delegate.signed.version != meta.version:
            raise exceptions.BadVersionNumberError(
                f"Expected {role_name} version "
                f"{meta.version}, got {new_delegate.signed.version}."
            )

        if new_delegate.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError(f"New {role_name} is expired")

        self._trusted_set[role_name] = new_delegate
        logger.debug("Updated %s delegated by %s", role_name, delegator_name)

    def _load_trusted_root(self, data: bytes) -> None:
        """Verifies and loads 'data' as trusted root metadata.

        Note that an expired initial root is considered valid: expiry is
        only checked for the final root in update_timestamp().
        """
        try:
            new_root = Metadata[Root].from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load root") from e

        if new_root.signed.type != "root":
            raise exceptions.RepositoryError(
                f"Expected 'root', got '{new_root.signed.type}'"
            )

        new_root.verify_delegate("root", new_root)

        self._trusted_set["root"] = new_root
        logger.debug("Loaded trusted root")
