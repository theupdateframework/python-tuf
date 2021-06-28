# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Configuration options for Updater class
"""

from dataclasses import dataclass


@dataclass
class UpdaterConfig:
    MAX_ROOT_ROTATIONS: int = 32
    MAX_DELEGATIONS: int = 32
    DEFAULT_ROOT_MAX_LENGTH: int = 512000  # bytes
    DEFAULT_TIMESTAMP_MAX_LENGTH: int = 16384  # bytes
    DEFAULT_SNAPSHOT_MAX_LENGTH: int = 2000000  # bytes
    DEFAULT_TARGETS_MAX_LENGTH: int = 5000000  # bytes
