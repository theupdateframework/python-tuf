"""
Provides validation functionality for tuf/api modules.
"""
from datetime import datetime

import tuf

METADATA_TYPES = ["root", "snapshot", "targets", "timestamp"]


def validate_spec_version(spec_version: str) -> None:
    """Validate that the SPEC_VERSION is a string in semantic versioning
    format and that its spec version is not higher than the current
    official tuf spec version."""
    if not isinstance(spec_version, str):
        raise TypeError(f"Expected {spec_version} to be an str")
    spec_version_split = spec_version.split(".")
    if len(spec_version_split) != 3:
        raise ValueError(
            "spec_version should be in a semantic versioning format."
        )

    spec_major_version = int(spec_version_split[0])
    code_spec_version_split = tuf.SPECIFICATION_VERSION.split(".")
    code_spec_major_version = int(code_spec_version_split[0])

    if spec_major_version != code_spec_major_version:
        raise ValueError(
            f"version major version must be ,"
            f"{code_spec_major_version} got {spec_major_version}"
        )


def validate_type(_type: str) -> None:
    """Validate the _TYPE Signed attribute."""
    if not isinstance(_type, str):
        raise TypeError("Expected _type to be an str")
    if _type not in METADATA_TYPES:
        raise ValueError(f"_type must be one of {METADATA_TYPES} got {_type}")


def validate_version(version: int) -> None:
    """Validate the VERSION Signed attribute."""
    if not isinstance(version, int):
        raise TypeError("Expected version to be an integer")
    if isinstance(version, (float, bool)):
        raise TypeError("Expected version to be an integer, not float or bool!")
    if version <= 0:
        raise ValueError(f"version must be > 0, got {version}")


def validate_expires(expires: datetime) -> None:
    """Validate the EXPIRES Signed attribute."""
    if not isinstance(expires, datetime):
        raise TypeError("Expected expires to be a datetime.datetime object!")
    now = datetime.utcnow()
    if now > expires:
        raise ValueError(
            f"Expected expires to reference time in the future,"
            f" instead got {expires}!"
        )
