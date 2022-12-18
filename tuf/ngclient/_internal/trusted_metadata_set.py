# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Trusted collection of client-side TUF Metadata.

``TrustedMetadataSet`` keeps track of the current valid set of metadata for the
client, and handles almost every step of the "Detailed client workflow" (
https://theupdateframework.github.io/specification/latest#detailed-client-workflow)
in the TUF specification: the remaining steps are related to filesystem and
network IO, which are not handled here.

Loaded metadata can be accessed via index access with rolename as key
(``trusted_set[Root.type]``) or, in the case of top-level metadata, using the
helper properties (``trusted_set.root``).

The rules that ``TrustedMetadataSet`` follows for top-level metadata are
 * Metadata must be loaded in order:
   root -> timestamp -> snapshot -> targets -> (delegated targets).
 * Metadata can be loaded even if it is expired (or in the snapshot case if the
   meta info does not match): this is called "intermediate metadata".
 * Intermediate metadata can _only_ be used to load newer versions of the
   same metadata: As an example an expired root can be used to load a new root.
 * Metadata is loadable only if metadata before it in loading order is loaded
   (and is not intermediate): As an example timestamp can be loaded if a
   final (non-expired) root has been loaded.
 * Metadata is not loadable if any metadata after it in loading order has been
   loaded: As an example new roots cannot be loaded if timestamp is loaded.

Exceptions are raised if metadata fails to load in any way.

Example of loading root, timestamp and snapshot:

>>> # Load local root (RepositoryErrors here stop the update)
>>> with open(root_path, "rb") as f:
>>>     trusted_set = TrustedMetadataSet(f.read())
>>>
>>> # update root from remote until no more are available
>>> with download(Root.type, trusted_set.root.signed.version + 1) as f:
>>>     trusted_set.update_root(f.read())
>>>
>>> # load local timestamp, then update from remote
>>> try:
>>>     with open(timestamp_path, "rb") as f:
>>>         trusted_set.update_timestamp(f.read())
>>> except (RepositoryError, OSError):
>>>     pass # failure to load a local file is ok
>>>
>>> with download(Timestamp.type) as f:
>>>     trusted_set.update_timestamp(f.read())
>>>
>>> # load local snapshot, then update from remote if needed
>>> try:
>>>     with open(snapshot_path, "rb") as f:
>>>         trusted_set.update_snapshot(f.read())
>>> except (RepositoryError, OSError):
>>>     # local snapshot is not valid, load from remote
>>>     # (RepositoryErrors here stop the update)
>>>     with download(Snapshot.type, version) as f:
>>>         trusted_set.update_snapshot(f.read())
"""

import datetime
import logging
from collections import abc
from typing import Dict, Iterator, Optional

from tuf.api import exceptions
from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp

logger = logging.getLogger(__name__)


class TrustedMetadataSet(abc.Mapping):
    """Internal class to keep track of trusted metadata in ``Updater``.

    ``TrustedMetadataSet`` ensures that the collection of metadata in it is valid
    and trusted through the whole client update workflow. It provides easy ways
    to update the metadata with the caller making decisions on what is updated.
    """

    def __init__(self, root_data: bytes):
        """Initialize ``TrustedMetadataSet`` by loading trusted root metadata.

        Args:
            root_data: Trusted root metadata as bytes. Note that this metadata
                will only be verified by itself: it is the source of trust for
                all metadata in the ``TrustedMetadataSet``

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        self._trusted_set: Dict[str, Metadata] = {}
        self.reference_time = datetime.datetime.utcnow()

        # Load and validate the local root metadata. Valid initial trusted root
        # metadata is required
        logger.debug("Updating initial trusted root")
        self._load_trusted_root(root_data)

    def __getitem__(self, role: str) -> Metadata:
        """Return current ``Metadata`` for ``role``."""
        return self._trusted_set[role]

    def __len__(self) -> int:
        """Return number of ``Metadata`` objects in ``TrustedMetadataSet``."""
        return len(self._trusted_set)

    def __iter__(self) -> Iterator[Metadata]:
        """Return iterator over ``Metadata`` objects in ``TrustedMetadataSet``."""
        return iter(self._trusted_set.values())

    # Helper properties for top level metadata
    @property
    def root(self) -> Metadata[Root]:
        """Get current root ``Metadata``."""
        return self._trusted_set[Root.type]

    @property
    def timestamp(self) -> Metadata[Timestamp]:
        """Get current timestamp ``Metadata``."""
        return self._trusted_set[Timestamp.type]

    @property
    def snapshot(self) -> Metadata[Snapshot]:
        """Get current snapshot ``Metadata``."""
        return self._trusted_set[Snapshot.type]

    @property
    def targets(self) -> Metadata[Targets]:
        """Get current top-level targets ``Metadata``."""
        return self._trusted_set[Targets.type]

    # Methods for updating metadata
    def update_root(self, data: bytes) -> Metadata[Root]:
        """Verify and load ``data`` as new root metadata.

        Note that an expired intermediate root is considered valid: expiry is
        only checked for the final root in ``update_timestamp()``.

        Args:
            data: Unverified new root metadata as bytes

        Raises:
            RuntimeError: This function is called after updating timestamp.
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.

        Returns:
            Deserialized and verified root ``Metadata`` object
        """
        if Timestamp.type in self._trusted_set:
            raise RuntimeError("Cannot update root after timestamp")
        logger.debug("Updating root")

        new_root = Metadata[Root].from_bytes(data)

        if new_root.signed.type != Root.type:
            raise exceptions.RepositoryError(
                f"Expected 'root', got '{new_root.signed.type}'"
            )

        # Verify that new root is signed by trusted root
        self.root.verify_delegate(Root.type, new_root)

        if new_root.signed.version != self.root.signed.version + 1:
            raise exceptions.BadVersionNumberError(
                f"Expected root version {self.root.signed.version + 1}"
                f" instead got version {new_root.signed.version}"
            )

        # Verify that new root is signed by itself
        new_root.verify_delegate(Root.type, new_root)

        self._trusted_set[Root.type] = new_root
        logger.debug("Updated root v%d", new_root.signed.version)

        return new_root

    def update_timestamp(self, data: bytes) -> Metadata[Timestamp]:
        """Verify and load ``data`` as new timestamp metadata.

        Note that an intermediate timestamp is allowed to be expired:
        ``TrustedMetadataSet`` will throw an ``ExpiredMetadataError`` in
        this case but the intermediate timestamp will be loaded. This way
        a newer timestamp can still be loaded (and the intermediate
        timestamp will be used for rollback protection). Expired timestamp
        will prevent loading snapshot metadata.

        Args:
            data: Unverified new timestamp metadata as bytes

        Raises:
            RuntimeError: This function is called after updating snapshot.
            RepositoryError: Metadata failed to load or verify as final
                timestamp. The actual error type and content will contain
                more details.

        Returns:
            Deserialized and verified timestamp ``Metadata`` object
        """
        if Snapshot.type in self._trusted_set:
            raise RuntimeError("Cannot update timestamp after snapshot")

        # client workflow 5.3.10: Make sure final root is not expired.
        if self.root.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("Final root.json is expired")
        # No need to check for 5.3.11 (fast forward attack recovery):
        # timestamp/snapshot can not yet be loaded at this point

        new_timestamp = Metadata[Timestamp].from_bytes(data)

        if new_timestamp.signed.type != Timestamp.type:
            raise exceptions.RepositoryError(
                f"Expected 'timestamp', got '{new_timestamp.signed.type}'"
            )

        self.root.verify_delegate(Timestamp.type, new_timestamp)

        # If an existing trusted timestamp is updated,
        # check for a rollback attack
        if Timestamp.type in self._trusted_set:
            # Prevent rolling back timestamp version
            if new_timestamp.signed.version < self.timestamp.signed.version:
                raise exceptions.BadVersionNumberError(
                    f"New timestamp version {new_timestamp.signed.version} must"
                    f" be >= {self.timestamp.signed.version}"
                )
            # Keep using old timestamp if versions are equal.
            if new_timestamp.signed.version == self.timestamp.signed.version:
                raise exceptions.EqualVersionNumberError()

            # Prevent rolling back snapshot version
            snapshot_meta = self.timestamp.signed.snapshot_meta
            new_snapshot_meta = new_timestamp.signed.snapshot_meta
            if new_snapshot_meta.version < snapshot_meta.version:
                raise exceptions.BadVersionNumberError(
                    f"New snapshot version must be >= {snapshot_meta.version}"
                    f", got version {new_snapshot_meta.version}"
                )

        # expiry not checked to allow old timestamp to be used for rollback
        # protection of new timestamp: expiry is checked in update_snapshot()

        self._trusted_set[Timestamp.type] = new_timestamp
        logger.debug("Updated timestamp v%d", new_timestamp.signed.version)

        # timestamp is loaded: raise if it is not valid _final_ timestamp
        self._check_final_timestamp()

        return new_timestamp

    def _check_final_timestamp(self) -> None:
        """Raise if timestamp is expired."""

        if self.timestamp.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("timestamp.json is expired")

    def update_snapshot(
        self, data: bytes, trusted: Optional[bool] = False
    ) -> Metadata[Snapshot]:
        """Verify and load ``data`` as new snapshot metadata.

        Note that an intermediate snapshot is allowed to be expired and version
        is allowed to not match timestamp meta version: ``TrustedMetadataSet``
        will throw an ``ExpiredMetadataError``/``BadVersionNumberError`` in
        these cases but the intermediate snapshot will be loaded. This way a
        newer snapshot can still be loaded (and the intermediate snapshot will
        be used for rollback protection). Expired snapshot or snapshot that
        does not match timestamp meta version will prevent loading targets.

        Args:
            data: Unverified new snapshot metadata as bytes
            trusted: ``True`` if data has at some point been verified by
                ``TrustedMetadataSet`` as a valid snapshot. Purpose of trusted
                is to allow loading of locally stored snapshot as intermediate
                snapshot even if hashes in current timestamp meta no longer
                match data. Default is False.

        Raises:
            RuntimeError: This function is called before updating timestamp
                or after updating targets.
            RepositoryError: Data failed to load or verify as final snapshot.
                The actual error type and content will contain more details.

        Returns:
            Deserialized and verified snapshot ``Metadata`` object
        """

        if Timestamp.type not in self._trusted_set:
            raise RuntimeError("Cannot update snapshot before timestamp")
        if Targets.type in self._trusted_set:
            raise RuntimeError("Cannot update snapshot after targets")
        logger.debug("Updating snapshot")

        # Snapshot cannot be loaded if final timestamp is expired
        self._check_final_timestamp()

        snapshot_meta = self.timestamp.signed.snapshot_meta

        # Verify non-trusted data against the hashes in timestamp, if any.
        # Trusted snapshot data has already been verified once.
        if not trusted:
            snapshot_meta.verify_length_and_hashes(data)

        new_snapshot = Metadata[Snapshot].from_bytes(data)

        if new_snapshot.signed.type != Snapshot.type:
            raise exceptions.RepositoryError(
                f"Expected 'snapshot', got '{new_snapshot.signed.type}'"
            )

        self.root.verify_delegate(Snapshot.type, new_snapshot)

        # version not checked against meta version to allow old snapshot to be
        # used in rollback protection: it is checked when targets is updated

        # If an existing trusted snapshot is updated, check for rollback attack
        if Snapshot.type in self._trusted_set:
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

        self._trusted_set[Snapshot.type] = new_snapshot
        logger.debug("Updated snapshot v%d", new_snapshot.signed.version)

        # snapshot is loaded, but we raise if it's not valid _final_ snapshot
        self._check_final_snapshot()

        return new_snapshot

    def _check_final_snapshot(self) -> None:
        """Raise if snapshot is expired or meta version does not match."""

        if self.snapshot.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("snapshot.json is expired")
        snapshot_meta = self.timestamp.signed.snapshot_meta
        if self.snapshot.signed.version != snapshot_meta.version:
            raise exceptions.BadVersionNumberError(
                f"Expected snapshot version {snapshot_meta.version}, "
                f"got {self.snapshot.signed.version}"
            )

    def update_targets(self, data: bytes) -> Metadata[Targets]:
        """Verify and load ``data`` as new top-level targets metadata.

        Args:
            data: Unverified new targets metadata as bytes

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.

        Returns:
            Deserialized and verified targets ``Metadata`` object
        """
        return self.update_delegated_targets(data, Targets.type, Root.type)

    def update_delegated_targets(
        self, data: bytes, role_name: str, delegator_name: str
    ) -> Metadata[Targets]:
        """Verify and load ``data`` as new metadata for target ``role_name``.

        Args:
            data: Unverified new metadata as bytes
            role_name: Role name of the new metadata
            delegator_name: Name of the role delegating to the new metadata

        Raises:
            RuntimeError: This function is called before updating snapshot.
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.

        Returns:
            Deserialized and verified targets ``Metadata`` object
        """
        if Snapshot.type not in self._trusted_set:
            raise RuntimeError("Cannot load targets before snapshot")

        # Targets cannot be loaded if final snapshot is expired or its version
        # does not match meta version in timestamp
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

        meta.verify_length_and_hashes(data)

        new_delegate = Metadata[Targets].from_bytes(data)

        if new_delegate.signed.type != Targets.type:
            raise exceptions.RepositoryError(
                f"Expected 'targets', got '{new_delegate.signed.type}'"
            )

        delegator.verify_delegate(role_name, new_delegate)

        version = new_delegate.signed.version
        if version != meta.version:
            raise exceptions.BadVersionNumberError(
                f"Expected {role_name} v{meta.version}, got v{version}."
            )

        if new_delegate.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError(f"New {role_name} is expired")

        self._trusted_set[role_name] = new_delegate
        logger.debug("Updated %s v%d", role_name, version)

        return new_delegate

    def _load_trusted_root(self, data: bytes) -> None:
        """Verify and load ``data`` as trusted root metadata.

        Note that an expired initial root is considered valid: expiry is
        only checked for the final root in ``update_timestamp()``.
        """
        new_root = Metadata[Root].from_bytes(data)

        if new_root.signed.type != Root.type:
            raise exceptions.RepositoryError(
                f"Expected 'root', got '{new_root.signed.type}'"
            )

        new_root.verify_delegate(Root.type, new_root)

        self._trusted_set[Root.type] = new_root
        logger.debug("Loaded trusted root v%d", new_root.signed.version)
