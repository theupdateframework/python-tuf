# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Repository Abstraction for metadata management"""

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager, suppress
from typing import Dict, Generator, Optional, Tuple

from tuf.api.metadata import Metadata, MetaFile, Signed

logger = logging.getLogger(__name__)


class AbortEdit(Exception):
    """Raise to exit the edit() contextmanager without saving changes"""


class Repository(ABC):
    """Abstract class for metadata modifying implementations

    This class is intended to be a base class used in any metadata editing
    application, whether it is a real repository server or a developer tool.

    Implementations must implement open() and close(), and can then use the
    edit() contextmanager to implement actual operations.

    A few operations (sign, snapshot and timestamp) are already implemented
    in this base class.
    """

    @abstractmethod
    def open(self, role: str, init: bool = False) -> Metadata:
        """Load a roles metadata from storage or cache, return it

        If 'init', then create metadata from scratch"""
        raise NotImplementedError

    @abstractmethod
    def close(self, role: str, md: Metadata, sign_only: bool = False) -> None:
        """Write roles metadata into storage

        If sign_only, then just append signatures of all available keys.

        If not sign_only, update expiry and version and replace signatures
        with ones from all available keys."""
        raise NotImplementedError

    @contextmanager
    def edit(
        self, role: str, init: bool = False
    ) -> Generator[Signed, None, None]:
        """Context manager for editing a roles metadata

        Context manager takes care of loading the roles metadata (or creating
        new metadata if 'init'), updating expiry and version. The caller can do
        other changes to the Signed object and when the context manager exits,
        a new version of the roles metadata is stored.

        Context manager user can raise AbortEdit from inside the with-block to
        cancel the edit: in this case none of the changes are stored.
        """
        md = self.open(role, init)
        with suppress(AbortEdit):
            yield md.signed
            self.close(role, md)

    def sign(self, role: str) -> None:
        """sign without modifying content, or removing existing signatures"""
        md = self.open(role)
        self.close(role, md, sign_only=True)

    def snapshot(
        self, current_targets: Dict[str, MetaFile]
    ) -> Tuple[Optional[int], Dict[str, MetaFile]]:
        """Update snapshot meta information

        Updates the meta information in snapshot according to input.

        Arguments:
            current_targets: The new currently served targets roles.

        Returns: Tuple of
            - New snapshot version or None if snapshot was not created
            - Meta information for targets metadata that were removed from repository
        """

        # Snapshot update is needed if
        # * any targets files are not yet in snapshot or
        # * any targets version is incorrect
        updated_snapshot = False
        removed: Dict[str, MetaFile] = {}

        with self.edit("snapshot") as snapshot:
            for keyname, new_meta in current_targets.items():
                if keyname not in snapshot.meta:
                    updated_snapshot = True
                    snapshot.meta[keyname] = new_meta
                    continue

                old_meta = snapshot.meta[keyname]
                if new_meta.version < old_meta.version:
                    raise ValueError(f"{keyname} version rollback")
                if new_meta.version > old_meta.version:
                    updated_snapshot = True
                    snapshot.meta[keyname] = new_meta
                    removed[keyname] = old_meta

            if not updated_snapshot:
                # prevent edit() from storing a new snapshot version
                raise AbortEdit("Skip snapshot: No targets version changes")

        if not updated_snapshot:
            # This code is reacheable as edit() handles AbortEdit
            logger.debug("Snapshot update not needed")  # type: ignore[unreachable]
        else:
            logger.debug(
                "Snapshot v%d, %d targets", snapshot.version, len(snapshot.meta)
            )

        version = snapshot.version if updated_snapshot else None
        return version, removed

    def timestamp(self, snapshot_meta: MetaFile) -> Optional[MetaFile]:
        """Update timestamp meta information

        Updates timestamp with given snapshot information.

        Returns the snapshot that was removed from repository (if any).
        """
        with self.edit("timestamp") as timestamp:
            old_snapshot_meta = timestamp.snapshot_meta
            timestamp.snapshot_meta = snapshot_meta

        logger.debug("Timestamp v%d", timestamp.version)
        if old_snapshot_meta.version == snapshot_meta.version:
            return None
        return old_snapshot_meta
