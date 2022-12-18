# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Public API for ``tuf.api``."""

from .metadata import (
    BaseFile,
    DelegatedRole,
    Delegations,
    Key,
    MetaFile,
    Metadata,
    Role,
    Root,
    SPECIFICATION_VERSION,
    Signed,
    Snapshot,
    SuccinctRoles,
    TOP_LEVEL_ROLE_NAMES,
    TargetFile,
    Targets,
    Timestamp,
)

from .exceptions import (
    BadVersionNumberError,
    DownloadError,
    DownloadHTTPError,
    DownloadLengthMismatchError,
    EqualVersionNumberError,
    ExpiredMetadataError,
    LengthOrHashMismatchError,
    RepositoryError,
    SlowRetrievalError,
    StorageError,
    UnsignedMetadataError,
)

__all__ = [
    "SPECIFICATION_VERSION",
    "TOP_LEVEL_ROLE_NAMES",
    BadVersionNumberError.__name__,
    BaseFile.__name__,
    DelegatedRole.__name__,
    Delegations.__name__,
    DownloadError.__name__,
    DownloadHTTPError.__name__,
    DownloadLengthMismatchError.__name__,
    EqualVersionNumberError.__name__,
    ExpiredMetadataError.__name__,
    Key.__name__,
    LengthOrHashMismatchError.__name__,
    MetaFile.__name__,
    Metadata.__name__,
    RepositoryError.__name__,
    Role.__name__,
    Root.__name__,
    Signed.__name__,
    SlowRetrievalError.__name__,
    Snapshot.__name__,
    StorageError.__name__,
    SuccinctRoles.__name__,
    TargetFile.__name__,
    Targets.__name__,
    Timestamp.__name__,
    UnsignedMetadataError.__name__,
]
