# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Configuration options for ``Updater`` class
"""

from dataclasses import dataclass


@dataclass
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
        lazy_refresh: Do not fetch metadata from remote if the local metadata
            is still valid. Setting lazy_refresh to True means refresh() no
            longer implements the full client workflow that is described in the
            specification, and should only be used with repositories that
            suggest using it:
             * The client may stay unaware of metadata updates for the
               expiry periods (typically timestamp expiry period).
             * Repository maintenance has some additional requirements as the
               clients may operate with older metadata.
    """

    max_root_rotations: int = 32
    max_delegations: int = 32
    root_max_length: int = 512000  # bytes
    timestamp_max_length: int = 16384  # bytes
    snapshot_max_length: int = 2000000  # bytes
    targets_max_length: int = 5000000  # bytes
    prefix_targets_with_hash: bool = True
    lazy_refresh = False
