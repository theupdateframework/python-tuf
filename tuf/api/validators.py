"""
Provides validation functionality for tuf/api modules.
"""
from datetime import datetime
from typing import Any, Mapping

import tuf

METADATA_TYPES = {"root", "snapshot", "targets", "timestamp"}


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


def validate_consistent_snapshot(consistent_snapshot: bool) -> None:
    """Validate the "CONSISTENT_SNAPSHOT" Root attribute."""
    if not isinstance(consistent_snapshot, bool):
        raise TypeError("Expected consistent_snapshot to be bool!")


def validate_keyid(keyid: str) -> None:
    """Validate the KEYID Root attribute."""
    if not isinstance(keyid, str):
        raise TypeError("Expected keyid to be a string!")
    if len(keyid) != 64:
        raise ValueError(
            f"Expected a 64 character long hexdigest string,"
            f" instead got: {keyid}!"
        )


def validate_keytype(keytype: str) -> None:
    """Validate the KEYTYPE Key attribute."""
    if not isinstance(keytype, str):
        raise TypeError("Expected keytype to be a string!")


def validate_scheme(scheme: str) -> None:
    """Validate the SCHEME Key attribute."""
    if not isinstance(scheme, str):
        raise TypeError("Expected scheme to be a string!")


def validate_keyval(keyval: Mapping[str, Any]) -> None:
    """Validate the KEYVAL Key attribute."""
    if not isinstance(keyval, Mapping):
        raise TypeError("Expected keyval to be a mapping!")
    if not keyval.get("public"):
        raise ValueError("keyval doesn't follow the specification format!")
    if len(keyval["public"]) < 64:
        raise ValueError(
            f"The public portion of keyval should be at least 64 character long"
            f"hexdigest string, instead got: {keyval}"
        )


def validate_role(role: str) -> None:
    """Validate the ROLE Root attribute."""
    if not isinstance(role, str):
        raise TypeError("Expected role to be a string!")
    if role not in METADATA_TYPES:
        raise ValueError(
            f"Role should one of the metadata, instead got: {role}!"
        )


def validate_threshold(threshold: int) -> None:
    """Validate the THRESHOLD Root attribute."""
    if not isinstance(threshold, int):
        raise TypeError("Expected threshold to be an integer!")
    if isinstance(threshold, (float, bool)):
        raise TypeError(
            "Expected threshold to be an integer, not float or bool!"
        )
    if threshold <= 0:
        raise ValueError("Expected threshold to be > 0!")
