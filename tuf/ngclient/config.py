# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Configuration options for ``Updater`` class."""

from dataclasses import dataclass
from enum import Flag, unique
from typing import Optional


@unique
class EnvelopeType(Flag):
    """Configures deserialization and verification mode of TUF metadata.

    Args:
        METADATA: Traditional canonical JSON -based TUF Metadata.
        SIMPLE: Dead Simple Signing Envelope. (experimental)
    """

    METADATA = 1
    SIMPLE = 2


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
        envelope_type: Configures deserialization and verification mode of TUF
            metadata. Per default, it is treated as traditional canonical JSON
            -based TUF Metadata.
        app_user_agent: Application user agent, e.g. "MyApp/1.0.0". This will be
            prefixed to ngclient user agent when the default fetcher is used.
    """

    max_root_rotations: int = 256
    max_delegations: int = 32
    root_max_length: int = 512000  # bytes
    timestamp_max_length: int = 16384  # bytes
    snapshot_max_length: int = 2000000  # bytes
    targets_max_length: int = 5000000  # bytes
    prefix_targets_with_hash: bool = True
    envelope_type: EnvelopeType = EnvelopeType.METADATA
    app_user_agent: Optional[str] = None
