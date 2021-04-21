# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client bundle-of-metadata

MetadataBundle keeps track of current valid set of metadata for the client,
and handles almost every step of the "Detailed client workflow" in the TUF
specification (the remaining steps are download related). The bundle takes
care of persisting valid metadata on disk, loading local metadata from disk
and deleting invalid local metadata.

New metadata (downloaded from a remote repository) can be loaded using
'update_metadata()'. The type of accepted metadata depends on bundle state:
 * Metadata is loadable only if all metadata it depends on is loaded
 * Metadata is immutable if any metadata depending on it has been loaded 

Exceptions are raised if metadata fails to load in any way (except in the
case of local loads -- see locad_local_metadata()).

Example (with hypothetical download function):

>>> # Load local root
>>> bundle = MetadataBundle("path/to/metadata")
>>>
>>> # load more root versions from remote
>>> with download("root", bundle.root.signed.version + 1) as f:
>>>     bundle.update_metadata(f.read())
>>> with download("root", bundle.root.signed.version + 1) as f:
>>>     bundle.update_metadata(f.read())
>>>
>>> # Finally, no more roots from remote
>>> bundle.root_update_finished()
>>>
>>> # load local timestamp, then update it
>>> bundle.load_local_metadata("timestamp")
>>> with download("timestamp") as f:
>>>     bundle.update_metadata(f.read())
>>>
>>> # load local snapshot, then update it if needed
>>> if not bundle.load_local_metadata("snapshot"):
>>>     # load snapshot (consistent snapshot not shown)
>>>     with download("snapshot") as f:
>>>         bundle.update_metadata(f.read())
>>>
>>> # load local targets, then update it if needed
>>> if not bundle.load_local_metadata("targets"):
>>>     version = bundle.snapshot.signed.meta["targets.json"]["version"]
>>>     with download("snapshot", version + 1) as f:
>>>         bundle.update_metadata(f.read())
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
def verify_with_threshold(delegator: Metadata, role_name: str, unverified: Metadata):
    if delegator.signed._type == 'root':
        keys = delegator.signed.keys
        role = delegator.signed.roles.get(role_name)
    elif delegator.signed._type == 'targets':
        keys = delegator.signed.delegations["keys"]
        # role names are unique: first match is enough
        roles = delegator.signed.delegations["roles"]
        role = next((role for role in roles if role["name"] == role_name), None)
    else:
        raise ValueError('Call is valid only on delegator metadata')

    if role is None:
        raise exceptions.UnknownRoleError

    # verify that delegate is signed by correct threshold of unique keys
    unique_keys = set()
    for keyid in role["keyids"]:
        key_metadata = keys[keyid]
        key, dummy = sslib_keys.format_metadata_to_key(key_metadata)

        try:
            if unverified.verify(key):
                unique_keys.add(key["keyval"]["public"])
        except:  # TODO specify the Exceptions
            pass

    return len(unique_keys) >= role["threshold"]


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
        self.reference_time = None

        if not os.path.exists(path):
            # TODO try to create dir instead?
            raise exceptions.RepositoryError("Repository does not exist")

        # Load and validate the local root metadata
        # Valid root metadata is required
        if not self.load_local_metadata("root"):
            raise exceptions.RepositoryError("Failed to load local root metadata")

    def load_local_metadata(self, role_name: str, delegator_name: str = None) -> bool:
        """Loads metadata from local storage and inserts into bundle
        
        If bundle already contains 'role_name', nothing is loaded.
        Failure to read the file, failure to parse it and failure to
        load it as valid metadata will not raise exceptions: the function
        will just fail.

        Returns True if 'role_name' is now in the bundle
        """
        if self.get(role_name) is not None:
            logger.debug("Already loaded %s.json", role_name)
            return True

        logger.debug("Loading local %s.json", role_name)

        self._raise_on_unsupported_state(role_name)

        try:
            with open(os.path.join(self._path, f"{role_name}.json"), "rb") as f:
                data = f.read()
            
            if role_name == "root":
                self._load_intermediate_root(data)
            elif role_name == "timestamp": 
                self._load_timestamp(data)
            elif role_name == "snapshot": 
                self._load_snapshot(data)
            elif role_name == "targets":
                self._load_targets(data)
            else:
                self._load_delegated_targets(data, role_name, delegator_name)

            return True
        except Exception as e:
            # TODO only handle specific errors
            logger.debug("Failed to load local %s.json", role_name)
            # TODO delete local file (except probably should not delete root.json?)
            return False

    def update_metadata(self, metadata_str: str, role_name: str, delegator_name: str = None):
        logger.debug("Updating %s", role_name)

        self._raise_on_unsupported_state(role_name)

        if role_name == "root":
            self.load_local_metadata("root")
            self._load_intermediate_root(metadata_str)
            self.root.to_file(os.path.join(self._path, "root.json"))
        elif role_name == "timestamp":
            self.load_local_metadata("timestamp")
            self._load_timestamp(metadata_str)
            self.timestamp.to_file(os.path.join(self._path, "timestamp.json"))
        elif role_name == "snapshot":
            self.load_local_metadata("snapshot")
            self._load_snapshot(metadata_str)
            self.snapshot.to_file(os.path.join(self._path, "snapshot.json"))
        elif role_name == "targets":
            self._load_targets(metadata_str)
            self.targets.to_file(os.path.join(self._path, "targets.json"))
        else:
            self._load_delegated_targets(metadata_str, role_name, delegator_name)
            self[role_name].to_file(os.path.join(self._path, f"{role_name}.json"))

    def root_update_finished(self):
        if self.timestamp is not None:
            # bundle does not support this order of ops
            raise exceptions.RepositoryError

        # Store our reference "now", verify root expiry
        self.reference_time = datetime.utcnow()
        if self.root.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError

        logger.debug("Verified final root.json")

    def _raise_on_unsupported_state(self, role_name: str):
        """Raise if updating 'role_name' is not supported at this state"""
        if role_name == "root":
            if self.timestamp is not None:
                raise exceptions.RepositoryError
        elif role_name == "timestamp":
            if self.reference_time is None:
                # root_update_finished() not called
                raise exceptions.RepositoryError
            if self.snapshot is not None:
                raise exceptions.RepositoryError
        elif role_name == "snapshot":
            if self.timestamp is None:
                raise exceptions.RepositoryError
            if self.targets is not None:
                raise exceptions.RepositoryError
        elif role_name == "targets":
            if self.snapshot is None:
                raise exceptions.RepositoryError
            if len(self) > 4:
                # delegates have been loaded already
                raise exceptions.RepositoryError
        else: # delegated role
            if self.targets is None:
                raise exceptions.RepositoryError

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
        logger.debug("Loaded root")

    def _load_timestamp(self, data: str):
        """Verifies the new timestamp and uses it as current timestamp

        Raises if verification fails
        """
        if self.root is None:
            # bundle does not support this order of ops
            raise exceptions.RepositoryError

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
        logger.debug("Loaded timestamp")

    def _load_snapshot(self, data: str):
        if self.root is None or self.timestamp is None:
            # bundle does not support this order of ops
            raise exceptions.RepositoryError

        # Verify against the hashes in timestamp, if any
        meta = self.timestamp.signed.meta.get("snapshot.json")
        if meta is None:
            raise exceptions.RepositoryError

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
        logger.debug("Loaded snapshot")

    def _load_targets(self, data: str):
        self._load_delegated_targets(data, "targets", "root")

    def _load_delegated_targets(self, data: str, role_name: str, delegator_name: str):
        logger.debug(f"Loading {role_name} delegated by {delegator_name}")
        delegator = self.get(delegator_name)
        if delegator == None:
            raise exceptions.RepositoryError

        # Verify against the hashes in snapshot, if any
        meta = self.snapshot.signed.meta.get(f"{role_name}.json")
        if meta is None:
            raise exceptions.RepositoryError

        hashes = meta.get("hashes") or {}
        for algo, _hash in hashes.items():
            digest_object = sslib_hash.digest(algo)
            digest_object.update(data)
            if digest_object.hexdigest() != _hash:
                raise exceptions.BadHashError()

        new_delegate = from_string(data)
        if new_delegate.signed._type != "targets":
            raise exceptions.RepositoryError

        if not verify_with_threshold(delegator, role_name, new_delegate):
            raise exceptions.UnsignedMetadataError(
                f"New {role_name} is not signed by {delegator_name}"
            )

        if new_delegate.signed.version != meta["version"]:
            raise exceptions.BadVersionNumberError

        if new_delegate.signed.is_expired(self.reference_time):
            raise exceptions.ExpiredMetadataError

        self._bundle[role_name] = new_delegate
        logger.debug("Loaded {role_name}")
