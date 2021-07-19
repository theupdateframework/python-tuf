# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Configuration options for Updater class
"""

from dataclasses import dataclass


@dataclass
class UpdaterConfig:
    max_root_rotations: int = 32
    max_delegations: int = 32
    root_max_length: int = 512000  # bytes
    timestamp_max_length: int = 16384  # bytes
    snapshot_max_length: int = 2000000  # bytes
    targets_max_length: int = 5000000  # bytes
    # We need this variable because there are use cases like Warehouse where
    # you could use consistent_snapshot, but without adding a hash prefix.
    # By default, prefix_targets_with_hash is set to true to use uniquely
    # identifiable targets file names for repositories.
    prefix_targets_with_hash: bool = True
