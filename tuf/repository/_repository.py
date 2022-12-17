# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Repository Abstraction for metadata management"""

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager, suppress
from copy import deepcopy
from typing import Dict, Generator, Optional, Tuple

from tuf.api.metadata import Metadata, MetaFile, Signed

logger = logging.getLogger(__name__)


class AbortEdit(Exception):
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

        If role has no metadata, create first version from scratch"""
        raise NotImplementedError

    @abstractmethod
    def close(self, role: str, md: Metadata) -> None:
        """Write roles metadata into storage

        Update expiry and version and replace signatures with ones from all
        available keys. Keep snapshot_info and targets_infos updated."""
        raise NotImplementedError

    @property
    @abstractmethod
    def targets_infos(self) -> Dict[str, MetaFile]:
        """Returns the MetaFiles for current targets metadatas

        This property is used by snapshot() to update Snapshot.meta.

        Note that there is a difference between this return value and
        Snapshot.meta: This dictionary reflects the targets metadata that
        currently exists in the repository but Snapshot.meta also includes
        metadata that used to exist, but no longer exists, in the repository.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def snapshot_info(self) -> MetaFile:
        """Returns the MetaFile for current snapshot metadata

        This property is used by timestamp() to update Timestamp.meta.
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

    def snapshot(self, force: bool = False) -> Tuple[bool, Dict[str, MetaFile]]:
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

        with self.edit("snapshot") as snapshot:
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
                # prevent edit() from storing a new snapshot version
                raise AbortEdit("Skip snapshot: No targets version changes")

        if not update_version:
            # this is reachable as edit() handles AbortEdit
            logger.debug("Snapshot update not needed")  # type: ignore[unreachable]
        else:
            logger.debug("Snapshot v%d", snapshot.version)

        return update_version, removed

    def timestamp(self, force: bool = False) -> Tuple[bool, Optional[MetaFile]]:
        """Update timestamp meta information

        Updates timestamp according to current snapshot state

        Returns: Tuple of
            - True if timestamp was created, False if not
            - MetaFile for snapshot version removed from timestamp (if any)
        """
        update_version = force
        removed = None
        with self.edit("timestamp") as timestamp:
            if self.snapshot_info.version < timestamp.snapshot_meta.version:
                raise ValueError("snapshot version rollback")

            if self.snapshot_info.version > timestamp.snapshot_meta.version:
                update_version = True
                removed = timestamp.snapshot_meta
                timestamp.snapshot_meta = deepcopy(self.snapshot_info)

            if not update_version:
                raise AbortEdit("Skip timestamp: No snapshot version changes")

        if not update_version:
            # this is reachable as edit() handles AbortEdit
            logger.debug("Timestamp update not needed")  # type: ignore[unreachable]
        else:
            logger.debug("Timestamp v%d", timestamp.version)
        return update_version, removed
