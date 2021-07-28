# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Client update workflow implementation

The Updater class provides an implementation of the
`TUF client workflow
<https://theupdateframework.github.io/specification/latest/#detailed-client-workflow>`_.
Updater provides an API to query available targets and to download them in a
secure manner: All downloaded files are verified by signed metadata.

High-level description of Updater functionality:
  * Initializing an :class:`~tuf.ngclient.updater.Updater` loads and validates
    the trusted local root metadata: This root metadata is used as the source
    of trust for all other metadata.
  * Calling :func:`~tuf.ngclient.updater.Updater.refresh()` will update root
    metadata and load all other top-level metadata as described in the
    specification, using both locally cached metadata and metadata downloaded
    from the remote repository.
  * When metadata is up-to-date, targets can be dowloaded. The repository
    snapshot is consistent so multiple targets can be downloaded without
    fear of repository content changing. For each target:

      * :func:`~tuf.ngclient.updater.Updater.get_one_valid_targetinfo()` is
        used to find information about a specific target. This will load new
        targets metadata as needed (from local cache or remote repository).
      * :func:`~tuf.ngclient.updater.Updater.updated_targets()` can be used to
        check if target files are already locally cached.
      * :func:`~tuf.ngclient.updater.Updater.download_target()` downloads a
        target file and ensures it is verified correct by the metadata.

Below is a simple example of using the Updater to download and verify
"file.txt" from a remote repository. The required environment for this example
is:

    * A webserver running on http://localhost:8000, serving TUF repository
      metadata at "/tuf-repo/" and targets at "/targets/"
    * Local metadata directory "~/tufclient/metadata/" is writable and contains
      a root metadata version for the remote repository
    * Download directory "~/tufclient/downloads/" is writable

Example::

    from tuf.ngclient import Updater

    # Load trusted local root metadata from client metadata cache. Define the
    # remote repository metadata URL prefix and target URL prefix.
    updater = Updater(
        repository_dir="~/tufclient/metadata/",
        metadata_base_url="http://localhost:8000/tuf-repo/",
        target_base_url="http://localhost:8000/targets/",
    )

    # Update top-level metadata from remote
    updater.refresh()

    # Securely download a target:
    # Update target metadata, then download and verify target
    targetinfo = updater.get_one_valid_targetinfo("file.txt")
    updater.download_target(targetinfo, "~/tufclient/downloads/")
"""

import logging
import os
from typing import List, Optional, Set, Tuple
from urllib import parse

from securesystemslib import util as sslib_util

from tuf import exceptions
from tuf.api.metadata import TargetFile, Targets
from tuf.ngclient._internal import requests_fetcher, trusted_metadata_set
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface

logger = logging.getLogger(__name__)


class Updater:
    """Implementation of the TUF client workflow."""

    def __init__(
        self,
        repository_dir: str,
        metadata_base_url: str,
        target_base_url: Optional[str] = None,
        fetcher: Optional[FetcherInterface] = None,
        config: Optional[UpdaterConfig] = None,
    ):
        """Creates a new Updater instance and loads trusted root metadata.

        Args:
            repository_dir: Local metadata directory. Directory must be
                writable and it must contain a trusted root.json file.
            metadata_base_url: Base URL for all remote metadata downloads
            target_base_url: Optional; Default base URL for all remote target
                downloads. Can be individually set in download_target()
            fetcher: Optional; FetcherInterface implementation used to download
                both metadata and targets. Default is RequestsFetcher

        Raises:
            OSError: Local root.json cannot be read
            RepositoryError: Local root.json is invalid
        """
        self._dir = repository_dir
        self._metadata_base_url = _ensure_trailing_slash(metadata_base_url)
        if target_base_url is None:
            self._target_base_url = None
        else:
            self._target_base_url = _ensure_trailing_slash(target_base_url)

        # Read trusted local root metadata
        data = self._load_local_metadata("root")
        self._trusted_set = trusted_metadata_set.TrustedMetadataSet(data)
        self._fetcher = fetcher or requests_fetcher.RequestsFetcher()
        self.config = config or UpdaterConfig()

    def refresh(self) -> None:
        """Refreshes top-level metadata.

        Downloads, verifies, and loads metadata for the top-level roles in the
        specified order (root -> timestamp -> snapshot -> targets) implementing
        all the checks required in the TUF client workflow.

        The metadata for delegated roles are not refreshed by this method as
        that happens on demand during get_one_valid_targetinfo().

        The refresh() method should be called by the client before any other
        method calls.

        Raises:
            OSError: New metadata could not be written to disk
            RepositoryError: Metadata failed to verify in some way
            TODO: download-related errors
        """

        self._load_root()
        self._load_timestamp()
        self._load_snapshot()
        self._load_targets("targets", "root")

    def get_one_valid_targetinfo(
        self, target_path: str
    ) -> Optional[TargetFile]:
        """Returns TargetFile instance with information for 'target_path'.

        The return value can be used as an argument to
        :func:`download_target()` and :func:`updated_targets()`.

        :func:`refresh()` must be called before calling
        `get_one_valid_targetinfo()`. Subsequent calls to
        `get_one_valid_targetinfo()` will use the same consistent repository
        state: Changes that happen in the repository between calling
        :func:`refresh()` and `get_one_valid_targetinfo()` will not be
        seen by the updater.

        As a side-effect this method downloads all the additional (delegated
        targets) metadata it needs to return the target information.

        Args:
            target_path: A target identifier that is a path-relative-URL string
                (https://url.spec.whatwg.org/#path-relative-url-string).
                Typically this is also the unix file path of the eventually
                downloaded file.

        Raises:
            OSError: New metadata could not be written to disk
            RepositoryError: Metadata failed to verify in some way
            TODO: download-related errors

        Returns:
            A TargetFile instance or None.
        """
        return self._preorder_depth_first_walk(target_path)

    @staticmethod
    def updated_targets(
        targets: List[TargetFile], destination_directory: str
    ) -> List[TargetFile]:
        """Checks whether local cached target files are up to date

        After retrieving the target information for the targets that should be
        updated, updated_targets() can be called to determine which targets
        have changed compared to locally stored versions.

        All the targets that are not up-to-date in destination_directory are
        returned in a list. The list items can be downloaded with
        'download_target()'.
        """
        # Keep track of the target objects and filepaths of updated targets.
        # Return 'updated_targets' and use 'updated_targetpaths' to avoid
        # duplicates.
        updated_targets = []
        updated_targetpaths = []

        for target in targets:
            # Prepend 'destination_directory' to the target's relative filepath
            # (as stored in metadata.)  Verify the hash of 'target_filepath'
            # against each hash listed for its fileinfo.  Note: join() discards
            # 'destination_directory' if 'filepath' contains a leading path
            # separator (i.e., is treated as an absolute path).
            target_filepath = os.path.join(destination_directory, target.path)

            if target_filepath in updated_targetpaths:
                continue

            try:
                with open(target_filepath, "rb") as target_file:
                    target.verify_length_and_hashes(target_file)
            # If the file does not exist locally or length and hashes
            # do not match, append to updated targets.
            except (OSError, exceptions.LengthOrHashMismatchError):
                updated_targets.append(target)
                updated_targetpaths.append(target_filepath)

        return updated_targets

    def download_target(
        self,
        targetinfo: TargetFile,
        destination_directory: str,
        target_base_url: Optional[str] = None,
    ) -> None:
        """Downloads the target file specified by 'targetinfo'.

        Args:
            targetinfo: TargetFile instance received from
                get_one_valid_targetinfo() or updated_targets().
            destination_directory: existing local directory to download into.
                Note that new directories may be created inside
                destination_directory as required.
            target_base_url: Optional; Base URL used to form the final target
                download URL. Default is the value provided in Updater()

        Raises:
            TODO: download-related errors
            TODO: file write errors
        """

        if target_base_url is None:
            if self._target_base_url is None:
                raise ValueError(
                    "target_base_url must be set in either "
                    "download_target() or constructor"
                )

            target_base_url = self._target_base_url
        else:
            target_base_url = _ensure_trailing_slash(target_base_url)

        target_filepath = targetinfo.path
        consistent_snapshot = self._trusted_set.root.signed.consistent_snapshot
        if consistent_snapshot and self.config.prefix_targets_with_hash:
            hashes = list(targetinfo.hashes.values())
            target_filepath = f"{hashes[0]}.{target_filepath}"
        full_url = parse.urljoin(target_base_url, target_filepath)

        with self._fetcher.download_file(
            full_url, targetinfo.length
        ) as target_file:
            try:
                targetinfo.verify_length_and_hashes(target_file)
            except exceptions.LengthOrHashMismatchError as e:
                raise exceptions.RepositoryError(
                    f"{target_filepath} length or hashes do not match"
                ) from e

            # Store the target file name without the HASH prefix.
            local_filepath = os.path.join(
                destination_directory, targetinfo.path
            )
            sslib_util.persist_temp_file(target_file, local_filepath)

    def _download_metadata(
        self, rolename: str, length: int, version: Optional[int] = None
    ) -> bytes:
        """Download a metadata file and return it as bytes"""
        if version is None:
            filename = f"{rolename}.json"
        else:
            filename = f"{version}.{rolename}.json"
        url = parse.urljoin(self._metadata_base_url, filename)
        return self._fetcher.download_bytes(url, length)

    def _load_local_metadata(self, rolename: str) -> bytes:
        with open(os.path.join(self._dir, f"{rolename}.json"), "rb") as f:
            return f.read()

    def _persist_metadata(self, rolename: str, data: bytes) -> None:
        with open(os.path.join(self._dir, f"{rolename}.json"), "wb") as f:
            f.write(data)

    def _load_root(self) -> None:
        """Load remote root metadata.

        Sequentially load and persist on local disk every newer root metadata
        version available on the remote.
        """

        # Update the root role
        lower_bound = self._trusted_set.root.signed.version + 1
        upper_bound = lower_bound + self.config.max_root_rotations

        for next_version in range(lower_bound, upper_bound):
            try:
                data = self._download_metadata(
                    "root", self.config.root_max_length, next_version
                )
                self._trusted_set.update_root(data)
                self._persist_metadata("root", data)

            except exceptions.FetcherHTTPError as exception:
                if exception.status_code not in {403, 404}:
                    raise
                # 404/403 means current root is newest available
                break

    def _load_timestamp(self) -> None:
        """Load local and remote timestamp metadata"""
        try:
            data = self._load_local_metadata("timestamp")
            self._trusted_set.update_timestamp(data)
        except (OSError, exceptions.RepositoryError) as e:
            # Local timestamp does not exist or is invalid
            logger.debug("Failed to load local timestamp %s", e)

        # Load from remote (whether local load succeeded or not)
        data = self._download_metadata(
            "timestamp", self.config.timestamp_max_length
        )
        self._trusted_set.update_timestamp(data)
        self._persist_metadata("timestamp", data)

    def _load_snapshot(self) -> None:
        """Load local (and if needed remote) snapshot metadata"""
        try:
            data = self._load_local_metadata("snapshot")
            self._trusted_set.update_snapshot(data)
            logger.debug("Local snapshot is valid: not downloading new one")
        except (OSError, exceptions.RepositoryError) as e:
            # Local snapshot does not exist or is invalid: update from remote
            logger.debug("Failed to load local snapshot %s", e)

            assert self._trusted_set.timestamp is not None  # nosec
            metainfo = self._trusted_set.timestamp.signed.meta["snapshot.json"]
            length = metainfo.length or self.config.snapshot_max_length
            version = None
            if self._trusted_set.root.signed.consistent_snapshot:
                version = metainfo.version

            data = self._download_metadata("snapshot", length, version)
            self._trusted_set.update_snapshot(data)
            self._persist_metadata("snapshot", data)

    def _load_targets(self, role: str, parent_role: str) -> None:
        """Load local (and if needed remote) metadata for 'role'."""
        try:
            data = self._load_local_metadata(role)
            self._trusted_set.update_delegated_targets(data, role, parent_role)
            logger.debug("Local %s is valid: not downloading new one", role)
        except (OSError, exceptions.RepositoryError) as e:
            # Local 'role' does not exist or is invalid: update from remote
            logger.debug("Failed to load local %s: %s", role, e)

            assert self._trusted_set.snapshot is not None  # nosec
            metainfo = self._trusted_set.snapshot.signed.meta[f"{role}.json"]
            length = metainfo.length or self.config.targets_max_length
            version = None
            if self._trusted_set.root.signed.consistent_snapshot:
                version = metainfo.version

            data = self._download_metadata(role, length, version)
            self._trusted_set.update_delegated_targets(data, role, parent_role)
            self._persist_metadata(role, data)

    def _preorder_depth_first_walk(
        self, target_filepath: str
    ) -> Optional[TargetFile]:
        """
        Interrogates the tree of target delegations in order of appearance
        (which implicitly order trustworthiness), and returns the matching
        target found in the most trusted role.
        """

        # List of delegations to be interrogated. A (role, parent role) pair
        # is needed to load and verify the delegated targets metadata.
        delegations_to_visit = [("targets", "root")]
        visited_role_names: Set[Tuple[str, str]] = set()
        number_of_delegations = self.config.max_delegations

        # Preorder depth-first traversal of the graph of target delegations.
        while number_of_delegations > 0 and len(delegations_to_visit) > 0:

            # Pop the role name from the top of the stack.
            role_name, parent_role = delegations_to_visit.pop(-1)

            # Skip any visited current role to prevent cycles.
            if (role_name, parent_role) in visited_role_names:
                logger.debug("Skipping visited current role %s", role_name)
                continue

            # The metadata for 'role_name' must be downloaded/updated before
            # its targets, delegations, and child roles can be inspected.
            self._load_targets(role_name, parent_role)

            role_metadata: Targets = self._trusted_set[role_name].signed
            target = role_metadata.targets.get(target_filepath)

            if target is not None:
                logger.debug("Found target in current role %s", role_name)
                return target

            # After preorder check, add current role to set of visited roles.
            visited_role_names.add((role_name, parent_role))

            # And also decrement number of visited roles.
            number_of_delegations -= 1

            if role_metadata.delegations is not None:
                child_roles_to_visit = []
                # NOTE: This may be a slow operation if there are many
                # delegated roles.
                for child_role in role_metadata.delegations.roles:
                    if child_role.is_delegated_path(target_filepath):
                        logger.debug("Adding child role %s", child_role.name)

                        child_roles_to_visit.append(
                            (child_role.name, role_name)
                        )
                        if child_role.terminating:
                            logger.debug("Not backtracking to other roles.")
                            delegations_to_visit = []
                            break
                # Push 'child_roles_to_visit' in reverse order of appearance
                # onto 'delegations_to_visit'.  Roles are popped from the end of
                # the list.
                child_roles_to_visit.reverse()
                delegations_to_visit.extend(child_roles_to_visit)

        if number_of_delegations == 0 and len(delegations_to_visit) > 0:
            logger.debug(
                "%d roles left to visit, but allowed to "
                "visit at most %d delegations.",
                len(delegations_to_visit),
                self.config.max_delegations,
            )

        # If this point is reached then target is not found, return None
        return None


def _ensure_trailing_slash(url: str) -> str:
    """Return url guaranteed to end in a slash"""
    return url if url.endswith("/") else f"{url}/"
