"""
Provides validation functionality for tuf/api modules.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Mapping

import tuf

METADATA_TYPES = {"root", "snapshot", "targets", "timestamp"}


def _check_semantic_versioning(spec_version: str) -> None:
    spec_version_split = spec_version.split(".")
    if len(spec_version_split) != 3:
        raise ValueError(
            "spec_version should be in a semantic versioning format."
        )

    spec_major_version = int(spec_version_split[0])
    code_spec_version_split = tuf.SPECIFICATION_VERSION.split(".")
    code_spec_major_version = int(code_spec_version_split[0])

    if spec_major_version != code_spec_major_version:
        return False

    return True


def _check_str_one_of_metadata_types(s):
    if not s in METADATA_TYPES:
        return False
    return True


def _check_dict_elements_uniqueness(d: Mapping[str, Any]):
    keys_list = d.keys()
    keys_set = set(keys_list)
    if len(keys_set) != len(keys_list):
        return False
    return True


def validate_spec_version(spec_version: str) -> None:
    """Validate that the SPEC_VERSION is a string in semantic versioning
    format and that its spec version is not higher than the current
    official tuf spec version."""
    if not isinstance(spec_version, str):
        raise TypeError(f"Expected {spec_version} to be an str")

    if not _check_semantic_versioning(spec_version):
        raise ValueError(f"spec version must be in semating versioning!")


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
    if not _check_str_one_of_metadata_types(role):
        raise ValueError(f"Expected role to be one of {METADATA_TYPES}")


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


class Validator(ABC):
    def __set_name__(self, owner, name):
        self.private_name = "_" + "NO_VALIDATION_" + name

    def __get__(self, obj, objtype=None):
        return getattr(obj, self.private_name)

    def __set__(self, obj, value):
        self.validate(value)
        setattr(obj, self.private_name, value)

    @abstractmethod
    def validate(self, value):
        pass


class OneOf(Validator):
    def __init__(self, options):
        self.options = set(options)

    def validate(self, value):
        if value not in self.options:
            raise ValueError(
                f"Expected {value!r} to be one of {self.options!r}"
            )


class Integer(Validator):
    def __init__(self, minvalue=None, maxvalue=None):
        self.minvalue = minvalue
        self.maxvalue = maxvalue

    def validate(self, value):
        if not isinstance(value, int):
            raise TypeError(f"Expected {value!r} to be an int!")
        if isinstance(value, (float, bool)):
            raise TypeError(
                "Expected {value!r} to be an integer, not float or bool! "
            )
        if self.minvalue is not None and value < self.minvalue:
            raise ValueError(
                f"Expected {value!r} to be at least {self.minvalue!r}!"
            )
        if self.maxvalue is not None and value > self.maxvalue:
            raise ValueError(
                f"Expected {value!r} to be no more than {self.maxvalue!r}!"
            )


class String(Validator):
    def __init__(self, minsize=None, maxsize=None, predicate=None):
        self.minsize = minsize
        self.maxsize = maxsize
        # The predicate function must return a boolean value.
        self.predicate = predicate

    def validate(self, value):
        if not isinstance(value, str):
            raise TypeError(f"Expected {value!r} to be a str!")
        if self.minsize is not None and len(value) < self.minsize:
            raise ValueError(
                f"Expected {value!r} to be no smaller than {self.minsize!r}!"
            )
        if self.maxsize is not None and len(value) > self.maxsize:
            raise ValueError(
                f"Expected {value!r} to be no bigger than {self.maxsize!r}!"
            )
        if self.predicate is not None and not self.predicate(value):
            raise ValueError(
                f"Expected {self.predicate} to be true for {value!r}!"
            )


class Dictionary(Validator):
    def __init__(
        self,
        keys_type=None,
        values_type=None,
        predicate=None,
        predicate_keys=None,
        predicate_values=None,
    ):
        self.keys_type = keys_type
        self.values_type = values_type
        # The predicate functions must return a boolean value.
        self.predicate = predicate
        self.predicate_keys = predicate_keys
        self.predicate_values = predicate_values

    def validate(self, value: Mapping):
        if not isinstance(value, Mapping):
            raise TypeError(f"Expected {value!r} to be a Mapping object!")
        if self.keys_type:
            for key in value.keys():
                if not isinstance(key, self.keys_type):
                    raise TypeError(
                        f"Expected {key!r} to be a {self.keys_type} type!"
                    )
        if self.values_type:
            for val in value.values():
                if not isinstance(val, self.values_type):
                    raise TypeError(
                        f"Expected {val!r} to be a {self.values_type} type!"
                    )
        if self.predicate and not self.predicate(value):
            raise ValueError(
                f"Expected {self.predicate} to be true for {value!r}!"
            )
        if self.predicate_keys:
            for key in value.keys():
                if not self.predicate_keys(key):
                    raise ValueError(
                        f"Expected {self.predicate_keys} to be true for {key!r}!"
                    )
        if self.predicate_values:
            for val in value.values():
                if not self.predicate_values(val):
                    raise ValueError(
                        f"Expected {self.predicate_values} to be true for {val!r}!"
                    )


class Bool(Validator):
    def validate(self, value):
        if not isinstance(value, bool):
            raise TypeError(f"Expected {value!r} to be a bool object!")


class DateTime(Validator):
    def validate(self, value):
        if not isinstance(value, datetime):
            raise TypeError(
                f"Expected {value!r} to be a datetime.datetime object!"
            )
        now = datetime.utcnow()
        # Add additional 10 minutes gratis between the call and this check.
        value += timedelta(minutes=10)
        if now > value:
            raise ValueError(
                f"Expected {value!r} to reference time in the future,"
            )
