# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Configuration options for ``Updater`` class.
"""

from dataclasses import dataclass


@dataclass
# pylint: disable=too-many-instance-attributes
class UpdaterConfig:
    """Used to store ``Updater`` configuration.

    Args:
        max_root_rotations: Maximum number of root rotations.
        max_delegations: Maximum number of delegations.
        root_max_length: Maxmimum length of a root metadata file.
        timestamp_max_length: Maximum length of a timestamp metadata file.
        snapshot_max_length: Maximum length of a snapshot metadata file.
        targets_max_length: Maximum length of a targets metadata file.
        prefix_targets_with_hash: When `consistent snapshots
            <https://theupdateframework.github.io/specification/latest/#consistent-snapshots>`_
            are used, target download URLs are formed by prefixing the filename
            with a hash digest of file content by default. This can be
            overridden by setting ``prefix_targets_with_hash`` to ``False``.
        offline: When offline, Updater works normally except for two differences: First,
            expired metadata is considered valid. Second, Updater will not
            download metadata or targets (if a download would be needed, a DownloadError
            is raised instead). This is useful for a client that has all required
            metadata and targets cached locally and is willing to sacrifice timeliness of
            metadata for offline functionality. Offline mode is not strictly compatible
            with the TUF client workflow.
    """

    max_root_rotations: int = 32
    max_delegations: int = 32
    root_max_length: int = 512000  # bytes
    timestamp_max_length: int = 16384  # bytes
    snapshot_max_length: int = 2000000  # bytes
    targets_max_length: int = 5000000  # bytes
    prefix_targets_with_hash: bool = True
    offline: bool = False
