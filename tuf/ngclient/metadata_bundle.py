# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client bundle-of-metadata

MetadataBundle keeps track of current valid set of metadata for the client,
and handles almost every step of the "Detailed client workflow" (
https://theupdateframework.github.io/specification/latest#detailed-client-workflow)
in the TUF specification: the remaining steps are related to filesystem and
network IO which is not handled here.

Loaded metadata can be accessed via the index access with rolename as key
(bundle["root"]) or, in the case of top-level metadata using the helper
properties (bundle.root).

The rules for top-level metadata are
 * Metadata is loadable only if metadata it depends on is loaded
 * Metadata is immutable if any metadata depending on it has been loaded
 * Metadata must be loaded/updated in order:
   root -> timestamp -> snapshot -> targets -> (other delegated targets)


Exceptions are raised if metadata fails to load in any way.

Example of loading root, timestamp and snapshot:

>>> # Load local root (RepositoryErrors here stop the update)
>>> with open(root_path, "rb") as f:
>>>     bundle = MetadataBundle(f.read())
>>>
>>> # update root from remote until no more are available
>>> with download("root", bundle.root.signed.version + 1) as f:
>>>     bundle.update_root(f.read())
>>> # ...
>>> bundle.root_update_finished()
>>>
>>> # load local timestamp, then update from remote
>>> try:
>>>     with open(timestamp_path, "rb") as f:
>>>         bundle.update_timestamp(f.read())
>>> except (RepositoryError, OSError):
>>>     pass # failure to load a local file is ok
>>>
>>> with download("timestamp") as f:
>>>     bundle.update_timestamp(f.read())
>>>
>>> # load local snapshot, then update from remote if needed
>>> try:
>>>     with open(snapshot_path, "rb") as f:
>>>         bundle.update_snapshot(f.read())
>>> except (RepositoryError, OSError):
>>>     # local snapshot is not valid, load from remote
>>>     # (RepositoryErrors here stop the update)
>>>     with download("snapshot", version) as f:
>>>         bundle.update_snapshot(f.read())

TODO:
 * exceptions are not final: the idea is that client could just handle
   a generic RepositoryError that covers every issue that server provided
   metadata could inflict (other errors would be user errors), but this is not
   yet the case
 * usefulness of root_update_finished() can be debated: it could be done
   in the beginning of load_timestamp()...
 * some metadata interactions might work better in Metadata itself
 * Progress through Specification update process should be documented
   (not sure yet how: maybe a spec_logger that logs specification events?)
"""

import logging
from collections import abc
from datetime import datetime
from typing import Dict, Iterator, Optional

from securesystemslib import hash as sslib_hash
from securesystemslib import keys as sslib_keys

from tuf import exceptions
from tuf.api.metadata import Metadata, Root, Targets
from tuf.api.serialization import DeserializationError

logger = logging.getLogger(__name__)

# This is a placeholder until ...
# TODO issue 1306: implement this in Metadata API
def verify_with_threshold(
    delegator: Metadata, role_name: str, unverified: Metadata
) -> bool:
    """Verify 'unverified' with keys and threshold defined in delegator"""
    role = None
    keys = {}
    if isinstance(delegator.signed, Root):
        keys = delegator.signed.keys
        role = delegator.signed.roles.get(role_name)
    elif isinstance(delegator.signed, Targets):
        if delegator.signed.delegations:
            keys = delegator.signed.delegations.keys
            # role names are unique: first match is enough
            roles = delegator.signed.delegations.roles
            role = next((r for r in roles if r.name == role_name), None)
    else:
        raise ValueError("Call is valid only on delegator metadata")

    if role is None:
        raise ValueError(f"Delegated role {role_name} not found")

    # verify that delegate is signed by correct threshold of unique keys
    unique_keys = set()
    for keyid in role.keyids:
        key_dict = keys[keyid].to_dict()
        key, dummy = sslib_keys.format_metadata_to_key(key_dict)

        try:
            if unverified.verify(key):
                unique_keys.add(key["keyval"]["public"])
        except Exception as e:  # pylint: disable=broad-except
            # TODO specify the Exceptions (see issue #1351)
            logger.info("verify failed: %s", e)

    return len(unique_keys) >= role.threshold


class MetadataBundle(abc.Mapping):
    """Internal class to keep track of valid metadata in Updater

    MetadataBundle ensures that the collection of metadata in the bundle is
    valid. It provides easy ways to update the metadata with the caller making
    decisions on what is updated.
    """

    def __init__(self, root_data: bytes):
        """Initialize bundle by loading trusted root metadata

        Args:
            root_data: Trusted root metadata as bytes. Note that this metadata
                will only be verified by itself: it is the source of trust for
                all metadata in the bundle.

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        self._bundle = {}  # type: Dict[str: Metadata]
        self.reference_time = datetime.utcnow()
        self._root_update_finished = False

        # Load and validate the local root metadata. Valid initial trusted root
        # metadata is required
        logger.debug("Updating initial trusted root")
        self.update_root(root_data)

    def __getitem__(self, role: str) -> Metadata:
        """Returns current Metadata for 'role'"""
        return self._bundle[role]

    def __len__(self) -> int:
        """Returns number of Metadata objects in bundle"""
        return len(self._bundle)

    def __iter__(self) -> Iterator[Metadata]:
        """Returns iterator over all Metadata objects in bundle"""
        return iter(self._bundle)

    # Helper properties for top level metadata
    @property
    def root(self) -> Optional[Metadata]:
        """Current root Metadata or None"""
        return self._bundle.get("root")

    @property
    def timestamp(self) -> Optional[Metadata]:
        """Current timestamp Metadata or None"""
        return self._bundle.get("timestamp")

    @property
    def snapshot(self) -> Optional[Metadata]:
        """Current snapshot Metadata or None"""
        return self._bundle.get("snapshot")

    @property
    def targets(self) -> Optional[Metadata]:
        """Current targets Metadata or None"""
        return self._bundle.get("targets")

    # Methods for updating metadata
    def update_root(self, data: bytes):
        """Verifies and loads 'data' as new root metadata.

        Note that an expired intermediate root is considered valid: expiry is
        only checked for the final root in root_update_finished().

        Args:
            data: unverified new root metadata as bytes

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        if self._root_update_finished:
            raise RuntimeError(
                "Cannot update root after root update is finished"
            )
        logger.debug("Updating root")

        try:
            new_root = Metadata.from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load root") from e

        if new_root.signed.type != "root":
            raise exceptions.RepositoryError(
                f"Expected 'root', got '{new_root.signed.type}'"
            )

        if self.root is not None:
            # We are not loading initial trusted root: verify the new one
            if not verify_with_threshold(self.root, "root", new_root):
                raise exceptions.UnsignedMetadataError(
                    "New root is not signed by root", new_root.signed
                )

            if new_root.signed.version != self.root.signed.version + 1:
                raise exceptions.ReplayedMetadataError(
                    "root", new_root.signed.version, self.root.signed.version
                )

        if not verify_with_threshold(new_root, "root", new_root):
            raise exceptions.UnsignedMetadataError(
                "New root is not signed by itself", new_root.signed
            )

        self._bundle["root"] = new_root
        logger.debug("Updated root")

    def root_update_finished(self):
        """Marks root metadata as final and verifies it is not expired

        Raises:
            ExpiredMetadataError: The final root metadata is expired.
        """
        if self._root_update_finished:
            raise RuntimeError("Root update is already finished")

        if self.root.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("New root.json is expired")

        self._root_update_finished = True
        logger.debug("Verified final root.json")

    def update_timestamp(self, data: bytes):
        """Verifies and loads 'data' as new timestamp metadata.

        Args:
            data: unverified new timestamp metadata as bytes

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        if not self._root_update_finished:
            # root_update_finished() not called
            raise RuntimeError("Cannot update timestamp before root")
        if self.snapshot is not None:
            raise RuntimeError("Cannot update timestamp after snapshot")

        try:
            new_timestamp = Metadata.from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load timestamp") from e

        if new_timestamp.signed.type != "timestamp":
            raise exceptions.RepositoryError(
                f"Expected 'timestamp', got '{new_timestamp.signed.type}'"
            )

        if not verify_with_threshold(self.root, "timestamp", new_timestamp):
            raise exceptions.UnsignedMetadataError(
                "New timestamp is not signed by root", new_timestamp.signed
            )

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
                # TODO not sure about the correct exception here
                raise exceptions.ReplayedMetadataError(
                    "snapshot",
                    new_timestamp.signed.meta["snapshot.json"].version,
                    self.timestamp.signed.meta["snapshot.json"].version,
                )

        if new_timestamp.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("New timestamp is expired")

        self._bundle["timestamp"] = new_timestamp
        logger.debug("Updated timestamp")

    # TODO: remove pylint disable once the hash verification is in metadata.py
    def update_snapshot(self, data: bytes):  # pylint: disable=too-many-branches
        """Verifies and loads 'data' as new snapshot metadata.

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

        meta = self.timestamp.signed.meta["snapshot.json"]

        # Verify against the hashes in timestamp, if any
        hashes = meta.hashes or {}
        for algo, stored_hash in hashes.items():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            observed_hash = digest_object.hexdigest()
            if observed_hash != stored_hash:
                # TODO: Error should derive from RepositoryError
                raise exceptions.BadHashError(stored_hash, observed_hash)

        try:
            new_snapshot = Metadata.from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load snapshot") from e

        if new_snapshot.signed.type != "snapshot":
            raise exceptions.RepositoryError(
                f"Expected 'snapshot', got '{new_snapshot.signed.type}'"
            )

        if not verify_with_threshold(self.root, "snapshot", new_snapshot):
            raise exceptions.UnsignedMetadataError(
                "New snapshot is not signed by root", new_snapshot.signed
            )

        if (
            new_snapshot.signed.version
            != self.timestamp.signed.meta["snapshot.json"].version
        ):
            raise exceptions.BadVersionNumberError(
                f"Expected snapshot version"
                f"{self.timestamp.signed.meta['snapshot.json'].version},"
                f"got {new_snapshot.signed.version}"
            )

        if self.snapshot:
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
                        f"Expected {filename} version"
                        f"{new_fileinfo.version}, got {fileinfo.version}"
                    )

        if new_snapshot.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError("New snapshot is expired")

        self._bundle["snapshot"] = new_snapshot
        logger.debug("Updated snapshot")

    def update_targets(self, data: bytes):
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
    ):
        """Verifies and loads 'data' as new metadata for target 'role_name'.

        Args:
            data: unverified new metadata as bytes
            role_name: The role name of the new metadata
            delegator_name: The name of the role delegating the new metadata

        Raises:
            RepositoryError: Metadata failed to load or verify. The actual
                error type and content will contain more details.
        """
        if self.snapshot is None:
            raise RuntimeError("Cannot load targets before snapshot")

        delegator = self.get(delegator_name)
        if delegator is None:
            raise RuntimeError("Cannot load targets before delegator")

        logger.debug("Updating %s delegated by %s", role_name, delegator_name)

        # Verify against the hashes in snapshot, if any
        meta = self.snapshot.signed.meta.get(f"{role_name}.json")
        if meta is None:
            raise exceptions.RepositoryError(
                f"Snapshot does not contain information for '{role_name}'"
            )

        hashes = meta.hashes or {}
        for algo, stored_hash in hashes.items():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            observed_hash = digest_object.hexdigest()
            if observed_hash != stored_hash:
                # TODO: Error should derive from RepositoryError
                raise exceptions.BadHashError(stored_hash, observed_hash)

        try:
            new_delegate = Metadata.from_bytes(data)
        except DeserializationError as e:
            raise exceptions.RepositoryError("Failed to load snapshot") from e

        if new_delegate.signed.type != "targets":
            raise exceptions.RepositoryError(
                f"Expected 'targets', got '{new_delegate.signed.type}'"
            )

        if not verify_with_threshold(delegator, role_name, new_delegate):
            raise exceptions.UnsignedMetadataError(
                f"New {role_name} is not signed by {delegator_name}",
                new_delegate,
            )

        if new_delegate.signed.version != meta.version:
            raise exceptions.BadVersionNumberError(
                f"Expected {role_name} version"
                f"{meta.version}, got {new_delegate.signed.version}"
            )

        if new_delegate.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError(f"New {role_name} is expired")

        self._bundle[role_name] = new_delegate
        logger.debug("Updated %s delegated by %s", role_name, delegator_name)
