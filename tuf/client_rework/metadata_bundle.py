# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client bundle-of-metadata

MetadataBundle keeps track of current valid set of metadata for the client,
and handles almost every step of the "Detailed client workflow" in the TUF
specification (the remaining steps are download related). The bundle takes
care of persisting valid metadata on disk, loading local metadata from disk
and deleting invalid local metadata.

New metadata (downloaded from a remote repository) can be loaded using
'update_metadata()'. The type of accepted metadata depends on bundle state
(states are "root"/"timestamp"/"snapshot"/"targets"/). Bundle states advances
to next state on every successful metadata update, except for "root" where state
only advances when 'root_update_finished()' is called. Exceptions will be thrown
if metadata fails to load in any way.

Example (with hypothetical download function):

>>> # Load local root
>>> bundle = MetadataBundle("path/to/metadata")
>>>
>>> # state: "root", load more root versions from remote
>>> with download("root", bundle.root.signed.version + 1) as f:
>>>     bundle.load_metadata(f.read())
>>> with download("root", bundle.root.signed.version + 1) as f:
>>>     bundle.load_metadata(f.read())
>>>
>>> # Finally, no more root from remote
>>> bundle.root_update_finished()
>>>
>>> # state: "timestamp", load timestamp
>>> with download("timestamp") as f:
>>>     bundle.load_metadata(f.read())
>>>
>>> # state: "snapshot", load snapshot (consistent snapshot not shown)
>>> with download("snapshot") as f:
>>>     bundle.load_metadata(f.read())
>>>
>>> # state: "targets", load targets
>>> version = bundle.snapshot.signed.meta["targets.json"]["version"]
>>> with download("snapshot", version + 1) as f:
>>>     bundle.load_metadata(f.read())
>>>
>>> # Top level metadata is now fully loaded and verified


TODO:
 * Delegated targets not implement yet
 * exceptions are all over the place and not thought out at all
 * a bit of repetition
 * No tests!
 * Naming maybe not final?
 * some metadata interactions might work better in Metadata itself
 * Progress through Specification update process should be documented
   (not sure yet how)
"""

from collections import abc
from datetime import datetime
import logging
import os
from typing import Dict

from securesystemslib import keys as sslib_hash
from securesystemslib import keys as sslib_keys

from tuf import exceptions
from tuf.api.metadata import Metadata

logger = logging.getLogger(__name__)

# This is a placeholder until ...
# TODO issue 1306: implement this in Metadata API
def verify_with_threshold(root: Metadata, role: str, unverified: Metadata):
    unique_keys = set()
    for keyid in root.signed.roles[role]["keyids"]:
        key_metadata = root.signed.keys[keyid]
        key, _ = sslib_keys.format_metadata_to_key(key_metadata)

        try:
            if unverified.verify(key):
                unique_keys.add(key["keyval"]["public"])
        except:
            pass

    return len(unique_keys) >= root.signed.roles[role]["threshold"]


# TODO issue 1336: implement in metadata api
from tuf.api.serialization.json import JSONDeserializer


def from_string(data: str) -> Metadata:
    return JSONDeserializer().deserialize(data)


class MetadataBundle(abc.Mapping):
    def __init__(self, path: str):
        """Initialize by loading root metadata from disk
        """
        self._path = path
        self._bundle = {}  # type: Dict[str: Metadata]
        self._state = "root"
        self.reference_time = None

        if not os.path.exists(path):
            # TODO try to create dir instead?
            raise exceptions.RepositoryError("Repository does not exist")

        # Load and validate the local root metadata
        # Valid root metadata is required (but invalid files are not removed)
        try:
            with open(os.path.join(self._path, "root.json"), "rb") as f:
                self._load_intermediate_root(f.read())
            logger.debug("Loaded local root.json")
        except:
            raise exceptions.RepositoryError("Failed to load local root metadata")

    def update_metadata(self, metadata_str: str):
        logger.debug("Updating %s", self._state)
        if self._state == "root":
            self._load_intermediate_root(metadata_str)
            self.root.to_file(os.path.join(self._path, "root.json"))
        elif self._state == "timestamp":
            self._load_timestamp(metadata_str)
            self.timestamp.to_file(os.path.join(self._path, "timestamp.json"))
            self._state = "snapshot"
        elif self._state == "snapshot":
            self._load_snapshot(metadata_str)
            self.snapshot.to_file(os.path.join(self._path, "snapshot.json"))
            self._state = "targets"
        elif self._state == "targets":
            self._load_targets(metadata_str)
            self.targets.to_file(os.path.join(self._path, "targets.json"))
            self._state = ""
        else:
            raise NotImplementedError

    def root_update_finished(self):
        if self._state != "root":
            # bundle does not support this order of ops
            raise exceptions.RepositoryError

        self._make_root_permanent(self)
        self._state = "timestamp"

    # Implement Mapping
    def __getitem__(self, key: str):
        return self._bundle[key]

    def __len__(self):
        return len(self._bundle)

    def __iter__(self):
        return iter(self._bundle)

    # Helper properties for top level metadata
    @property
    def root(self):
        return self._bundle.get("root")

    @property
    def timestamp(self):
        return self._bundle.get("timestamp")

    @property
    def snapshot(self):
        return self._bundle.get("snapshot")

    @property
    def targets(self):
        return self._bundle.get("targets")

    def _load_intermediate_root(self, data: str):
        """Verify the new root using current root (if any) and use it as current root

        Raises if root fails verification
        """
        new_root = from_string(data)
        if new_root.signed._type != "root":
            raise exceptions.RepositoryError

        if self.root is not None:
            if not verify_with_threshold(self.root, "root", new_root):
                raise exceptions.UnsignedMetadataError(
                    "New root is not signed by root", new_root.signed
                )

            if new_root.signed.version != self.root.signed.version + 1:
                # TODO not a "Replayed Metadata attack": the version is just not what we expected
                raise exceptions.ReplayedMetadataError(
                    "root", new_root.signed.version, self.root.signed.version
                )

        if not verify_with_threshold(new_root, "root", new_root):
            raise exceptions.UnsignedMetadataError(
                "New root is not signed by itself", new_root.signed
            )

        self._bundle["root"] = new_root

    def _make_root_permanent(self):
        # Store our reference "now", verify root expiry
        self.reference_time = datetime.utcnow()
        if self.root.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError

        logger.debug("Verified final root.json")

        # Load remaning local metadata: this ensures invalid
        # metadata gets wiped from disk
        try:
            with open(os.path.join(self._path, "timestamp.json"), "rb") as f:
                self._load_timestamp(f.read())
            logger.debug("Loaded local timestamp.json")
        except Exception as e:
            # TODO only handle specific errors
            logger.debug("Failed to load local timestamp.json")
            # TODO delete local file

        try:
            with open(os.path.join(self._path, "snapshot.json"), "rb") as f:
                self._load_snapshot(f.read())
            logger.debug("Loaded local snapshot.json")
        except Exception as e:
            # TODO only handle specific errors
            logger.debug("Failed to load local snapshot.json")
            # TODO delete local file

        try:
            with open(os.path.join(self._path, "targets.json"), "rb") as f:
                self._load_targets(f.read())
            logger.debug("Loaded local targets.json")
        except Exception as e:
            # TODO only handle specific errors
            logger.debug("Failed to load local targets.json")
            # TODO delete local file

    def _load_timestamp(self, data: str):
        """Verifies the new timestamp and uses it as current timestamp

        Raises if verification fails
        """
        new_timestamp = from_string(data)
        if new_timestamp.signed._type != "timestamp":
            raise exceptions.RepositoryError

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
                new_timestamp.signed.meta["snapshot.json"]["version"]
                < self.timestamp.signed.meta["snapshot.json"]["version"]
            ):
                # TODO not sure about the
                raise exceptions.ReplayedMetadataError(
                    "snapshot",
                    new_timestamp.signed.meta["snapshot.json"]["version"],
                    self.timestamp.signed.meta["snapshot.json"]["version"],
                )

        if new_timestamp.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError

        self._bundle["timestamp"] = new_timestamp

    def _load_snapshot(self, data: str):
        # Verify against the hashes in timestamp, if any
        meta = self.timestamp.signed.meta["snapshot.json"]
        hashes = meta.get("hashes") or {}
        for algo, _hash in meta["hashes"].items():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            if digest_object.hexdigest() != _hash:
                raise exceptions.BadHashError()
        new_snapshot = from_string(data)
        if new_snapshot.signed._type != "snapshot":
            raise exceptions.RepositoryError

        if not verify_with_threshold(self.root, "snapshot", new_snapshot):
            raise exceptions.UnsignedMetadataError(
                "New snapshot is not signed by root", new_snapshot.signed
            )

        if (
            new_snapshot.signed.version
            != self.timestamp.signed.meta["snapshot.json"]["version"]
        ):
            raise exceptions.BadVersionNumberError

        if self.snapshot:
            for filename, fileinfo in self.snapshot.signed.meta.items():
                new_fileinfo = new_snapshot.signed.meta.get(filename)

                # Prevent removal of any metadata in meta
                if new_fileinfo is None:
                    raise exceptions.ReplayedMetadataError

                # Prevent rollback of any metadata versions
                if new_fileinfo["version"] < fileinfo["version"]:
                    raise exceptions.ReplayedMetadataError

        if new_snapshot.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError

        self._bundle["snapshot"] = new_snapshot

    def _load_targets(self, data: str):
        # Verify against the hashes in snapshot, if any
        meta = self.snapshot.signed.meta["targets.json"]

        hashes = meta.get("hashes") or {}
        for algo, _hash in hashes.items():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            if digest_object.hexdigest() != _hash:
                raise exceptions.BadHashError()

        new_targets = from_string(data)
        if new_targets.signed._type != "targets":
            raise exceptions.RepositoryError

        if not verify_with_threshold(self.root, "targets", new_targets):
            raise exceptions.UnsignedMetadataError(
                "New targets is not signed by root", new_targets.signed
            )

        if new_targets.signed.version != meta["version"]:
            raise exceptions.BadVersionNumberError

        if new_targets.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError

        self._bundle["targets"] = new_targets
