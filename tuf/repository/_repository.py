# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Repository Abstraction for metadata management"""

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager, suppress
from copy import deepcopy
from typing import Dict, Generator, Optional, Tuple

from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Signed,
    Snapshot,
    Targets,
    Timestamp,
)

logger = logging.getLogger(__name__)


class AbortEdit(Exception):  # noqa: N818
    """Raise to exit the edit() contextmanager without saving changes"""


class Repository(ABC):
    """Abstract class for metadata modifying implementations

    NOTE: The repository module is not considered part of the python-tuf
    stable API yet.

    This class is intended to be a base class used in any metadata editing
    application, whether it is a real repository server or a developer tool.

    Implementations must implement open() and close(), and can then use the
    edit() contextmanager to implement actual operations. Note that signing
    an already existing version of metadata (as could be done for threshold
    signing) does not fit into this model of open()+close() or edit().

    A few operations (snapshot and timestamp) are already implemented
    in this base class.
    """

    @abstractmethod
    def open(self, role: str) -> Metadata:
        """Load a roles metadata from storage or cache, return it

        If role has no metadata, create first version from scratch.
        """
        raise NotImplementedError

    @abstractmethod
    def close(self, role: str, md: Metadata) -> None:
        """Write roles metadata into storage

        Update expiry and version and replace signatures with ones from all
        available keys. Keep snapshot_info and targets_infos updated.
        """
        raise NotImplementedError

    @property
    def targets_infos(self) -> Dict[str, MetaFile]:
        """Returns the MetaFiles for current targets metadatas

        This property is used by do_snapshot() to update Snapshot.meta:
        Repository implementations should override this property to enable
        do_snapshot().

        Note that there is a difference between this return value and
        Snapshot.meta: This dictionary reflects the targets metadata that
        currently exists in the repository but Snapshot.meta also includes
        metadata that used to exist, but no longer exists, in the repository.
        """
        raise NotImplementedError

    @property
    def snapshot_info(self) -> MetaFile:
        """Returns the MetaFile for current snapshot metadata

        This property is used by do_timestamp() to update Timestamp.meta:
        Repository implementations should override this property to enable
        do_timestamp().
        """
        raise NotImplementedError

    @contextmanager
    def edit(self, role: str) -> Generator[Signed, None, None]:
        """Context manager for editing a role's metadata

        Context manager takes care of loading the roles metadata (or creating
        new metadata), updating expiry and version. The caller can do
        other changes to the Signed object and when the context manager exits,
        a new version of the roles metadata is stored.

        Context manager user can raise AbortEdit from inside the with-block to
        cancel the edit: in this case none of the changes are stored.
        """
        md = self.open(role)
        with suppress(AbortEdit):
            yield md.signed
            self.close(role, md)

    @contextmanager
    def edit_root(self) -> Generator[Root, None, None]:
        """Context manager for editing root metadata. See edit()"""
        with self.edit(Root.type) as root:
            if not isinstance(root, Root):
                raise RuntimeError("Unexpected root type")
            yield root

    @contextmanager
    def edit_timestamp(self) -> Generator[Timestamp, None, None]:
        """Context manager for editing timestamp metadata. See edit()"""
        with self.edit(Timestamp.type) as timestamp:
            if not isinstance(timestamp, Timestamp):
                raise RuntimeError("Unexpected timestamp type")
            yield timestamp

    @contextmanager
    def edit_snapshot(self) -> Generator[Snapshot, None, None]:
        """Context manager for editing snapshot metadata. See edit()"""
        with self.edit(Snapshot.type) as snapshot:
            if not isinstance(snapshot, Snapshot):
                raise RuntimeError("Unexpected snapshot type")
            yield snapshot

    @contextmanager
    def edit_targets(
        self, rolename: str = Targets.type
    ) -> Generator[Targets, None, None]:
        """Context manager for editing targets metadata. See edit()"""
        with self.edit(rolename) as targets:
            if not isinstance(targets, Targets):
                raise RuntimeError(f"Unexpected targets ({rolename}) type")
            yield targets

    def root(self) -> Root:
        """Read current root metadata"""
        root = self.open(Root.type).signed
        if not isinstance(root, Root):
            raise RuntimeError("Unexpected root type")
        return root

    def timestamp(self) -> Timestamp:
        """Read current timestamp metadata"""
        timestamp = self.open(Timestamp.type).signed
        if not isinstance(timestamp, Timestamp):
            raise RuntimeError("Unexpected timestamp type")
        return timestamp

    def snapshot(self) -> Snapshot:
        """Read current snapshot metadata"""
        snapshot = self.open(Snapshot.type).signed
        if not isinstance(snapshot, Snapshot):
            raise RuntimeError("Unexpected snapshot type")
        return snapshot

    def targets(self, rolename: str = Targets.type) -> Targets:
        """Read current targets metadata"""
        targets = self.open(rolename).signed
        if not isinstance(targets, Targets):
            raise RuntimeError("Unexpected targets type")
        return targets

    def do_snapshot(
        self, force: bool = False
    ) -> Tuple[bool, Dict[str, MetaFile]]:
        """Update snapshot meta information

        Updates the snapshot meta information according to current targets
        metadata state and the current snapshot meta information.

        Arguments:
            force: should new snapshot version be created even if meta
                information would not change?

        Returns: Tuple of
            - True if snapshot was created, False if not
            - MetaFiles for targets versions removed from snapshot meta
        """

        # Snapshot update is needed if
        # * any targets files are not yet in snapshot or
        # * any targets version is incorrect
        update_version = force
        removed: Dict[str, MetaFile] = {}

        root = self.root()
        snapshot_md = self.open(Snapshot.type)

        try:
            root.verify_delegate(
                Snapshot.type,
                snapshot_md.signed_bytes,
                snapshot_md.signatures,
            )
        except UnsignedMetadataError:
            update_version = True

        with self.edit_snapshot() as snapshot:
            for keyname, new_meta in self.targets_infos.items():
                if keyname not in snapshot.meta:
                    update_version = True
                    snapshot.meta[keyname] = deepcopy(new_meta)
                    continue

                old_meta = snapshot.meta[keyname]
                if new_meta.version < old_meta.version:
                    raise ValueError(f"{keyname} version rollback")
                if new_meta.version > old_meta.version:
                    update_version = True
                    snapshot.meta[keyname] = deepcopy(new_meta)
                    removed[keyname] = old_meta

            if not update_version:
                # prevent edit_snapshot() from storing a new version
                raise AbortEdit("Skip snapshot: No targets version changes")

        if not update_version:
            # this is reachable as edit_snapshot() handles AbortEdit
            logger.debug("Snapshot update not needed")  # type: ignore[unreachable]
        else:
            logger.debug("Snapshot v%d", snapshot.version)

        return update_version, removed

    def do_timestamp(
        self, force: bool = False
    ) -> Tuple[bool, Optional[MetaFile]]:
        """Update timestamp meta information

        Updates timestamp according to current snapshot state

        Returns: Tuple of
            - True if timestamp was created, False if not
            - MetaFile for snapshot version removed from timestamp (if any)
        """
        update_version = force
        removed = None

        root = self.root()
        timestamp_md = self.open(Timestamp.type)

        try:
            root.verify_delegate(
                Timestamp.type,
                timestamp_md.signed_bytes,
                timestamp_md.signatures,
            )
        except UnsignedMetadataError:
            update_version = True

        with self.edit_timestamp() as timestamp:
            if self.snapshot_info.version < timestamp.snapshot_meta.version:
                raise ValueError("snapshot version rollback")

            if self.snapshot_info.version > timestamp.snapshot_meta.version:
                update_version = True
                removed = timestamp.snapshot_meta
                timestamp.snapshot_meta = deepcopy(self.snapshot_info)

            if not update_version:
                raise AbortEdit("Skip timestamp: No snapshot version changes")

        if not update_version:
            # this is reachable as edit_timestamp() handles AbortEdit
            logger.debug("Timestamp update not needed")  # type: ignore[unreachable]
        else:
            logger.debug("Timestamp v%d", timestamp.version)
        return update_version, removed
