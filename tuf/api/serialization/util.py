"""Utility functions to facilitate TUF metadata de/serialization.

Currently, this module contains functions to convert between the TUF metadata
class model and a corresponding dictionary representation.

"""


from typing import Any, Dict, Mapping

from tuf import formats
from tuf.api.metadata import (Signed, Metadata, Root, Timestamp, Snapshot,
                              Targets)


def _get_signed_common_args_from_dict(_dict: Mapping[str, Any]) -> list:
    """Returns ordered positional arguments for 'Signed' subclass constructors.

    See '{root, timestamp, snapshot, targets}_from_dict' functions for usage.

    """
    _type = _dict.pop("_type")
    version = _dict.pop("version")
    spec_version = _dict.pop("spec_version")
    expires_str = _dict.pop("expires")
    expires = formats.expiry_string_to_datetime(expires_str)
    return [_type, version, spec_version, expires]


def root_from_dict(_dict: Mapping[str, Any]) -> Root:
    """Returns 'Root' object based on its dict representation. """
    common_args = _get_signed_common_args_from_dict(_dict)
    consistent_snapshot = _dict.pop("consistent_snapshot")
    keys = _dict.pop("keys")
    roles = _dict.pop("roles")
    return Root(*common_args, consistent_snapshot, keys, roles)


def timestamp_from_dict(_dict: Mapping[str, Any]) -> Timestamp:
    """Returns 'Timestamp' object based on its dict representation. """
    common_args = _get_signed_common_args_from_dict(_dict)
    meta = _dict.pop("meta")
    return Timestamp(*common_args, meta)


def snapshot_from_dict(_dict: Mapping[str, Any]) -> Snapshot:
    """Returns 'Snapshot' object based on its dict representation. """
    common_args = _get_signed_common_args_from_dict(_dict)
    meta = _dict.pop("meta")
    return Snapshot(*common_args, meta)


def targets_from_dict(_dict: Mapping[str, Any]) -> Targets:
    """Returns 'Targets' object based on its dict representation. """
    common_args = _get_signed_common_args_from_dict(_dict)
    targets = _dict.pop("targets")
    delegations = _dict.pop("delegations")
    return Targets(*common_args, targets, delegations)

def signed_from_dict(_dict) -> Signed:
    """Returns 'Signed'-subclass object based on its dict representation. """
    # Dispatch to '*_from_dict'-function based on '_type' field.
    # TODO: Use if/else cascade, if easier to read!
    # TODO: Use constants for types! (e.g. Root._type, Targets._type, etc.)
    return {
        "root": root_from_dict,
        "timestamp": timestamp_from_dict,
        "snapshot": snapshot_from_dict,
        "targets": targets_from_dict
    }[_dict["_type"]](_dict)


def metadata_from_dict(_dict: Mapping[str, Any]) -> Metadata:
    """Returns 'Metadata' object based on its dict representation. """
    signed_dict = _dict.pop("signed")
    signatures = _dict.pop("signatures")
    return Metadata(signatures=signatures,
                    signed=signed_from_dict(signed_dict))


def _get_signed_common_fields_as_dict(obj: Signed) -> Dict[str, Any]:
    """Returns dict representation of 'Signed' object.

    See '{root, timestamp, snapshot, targets}_to_dict' functions for usage.

    """
    return {
        "_type": obj._type,
        "version": obj.version,
        "spec_version": obj.spec_version,
        "expires": obj.expires.isoformat() + "Z"
    }


def root_to_dict(obj: Root) -> Dict[str, Any]:
    """Returns dict representation of 'Root' object. """
    _dict = _get_signed_common_fields_as_dict(obj)
    _dict.update({
        "consistent_snapshot": obj.consistent_snapshot,
        "keys": obj.keys,
        "roles": obj.roles
    })
    return _dict


def timestamp_to_dict(obj: Timestamp) -> Dict[str, Any]:
    """Returns dict representation of 'Timestamp' object. """
    _dict = _get_signed_common_fields_as_dict(obj)
    _dict.update({
        "meta": obj.meta
    })
    return _dict


def snapshot_to_dict(obj: Snapshot) -> Dict[str, Any]:
    """Returns dict representation of 'Snapshot' object. """
    _dict = _get_signed_common_fields_as_dict(obj)
    _dict.update({
        "meta": obj.meta
    })
    return _dict


def targets_to_dict(obj: Targets) -> Dict[str, Any]:
    """Returns dict representation of 'Targets' object. """
    _dict = _get_signed_common_fields_as_dict(obj)
    _dict.update({
        "targets": obj.targets,
        "delegations": obj.delegations,
    })
    return _dict

def signed_to_dict(obj: Signed) -> Dict[str, Any]:
    """Returns dict representation of 'Signed'-subclass object. """
    # Dispatch to '*_to_dict'-function based on 'Signed' subclass type.
    # TODO: Use if/else cascade, if easier to read!
    return {
        Root: root_to_dict,
        Timestamp: timestamp_to_dict,
        Snapshot: snapshot_to_dict,
        Targets: targets_to_dict
    }[obj.__class__](obj)

def metadata_to_dict(obj: Metadata) -> Dict[str, Any]:
    """Returns dict representation of 'Metadata' object. """
    return {
        "signatures": obj.signatures,
        "signed": signed_to_dict(obj.signed)
    }
