# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0


"""Helper classes for low-level Metadata API."""

import abc
import fnmatch
import io
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    IO,
    Any,
    ClassVar,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

from securesystemslib import exceptions as sslib_exceptions
from securesystemslib import hash as sslib_hash
from securesystemslib.signer import Key, Signature

from tuf.api.exceptions import LengthOrHashMismatchError, UnsignedMetadataError

_ROOT = "root"
_SNAPSHOT = "snapshot"
_TARGETS = "targets"
_TIMESTAMP = "timestamp"

# We aim to support SPECIFICATION_VERSION and require the input metadata
# files to have the same major version (the first number) as ours.
SPECIFICATION_VERSION = ["1", "0", "31"]
TOP_LEVEL_ROLE_NAMES = {_ROOT, _TIMESTAMP, _SNAPSHOT, _TARGETS}

logger = logging.getLogger(__name__)

# T is a Generic type constraint for container payloads
T = TypeVar("T", "Root", "Timestamp", "Snapshot", "Targets")


class Signed(metaclass=abc.ABCMeta):
    """A base class for the signed part of TUF metadata.

    Objects with base class Signed are usually included in a ``Metadata`` object
    on the signed attribute. This class provides attributes and methods that
    are common for all TUF metadata types (roles).

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number. If None, then 1 is assigned.
        spec_version: Supported TUF specification version. If None, then the
            version currently supported by the library is assigned.
        expires: Metadata expiry date in UTC timezone. If None, then current
            date and time is assigned.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError: Invalid arguments.
    """

    # type is required for static reference without changing the API
    type: ClassVar[str] = "signed"

    # _type and type are identical: 1st replicates file format, 2nd passes lint
    @property
    def _type(self) -> str:
        return self.type

    @property
    def expires(self) -> datetime:
        """Get the metadata expiry date."""
        return self._expires

    @expires.setter
    def expires(self, value: datetime) -> None:
        """Set the metadata expiry date.

        # Use 'datetime' module to e.g. expire in seven days from now
        obj.expires = now(timezone.utc) + timedelta(days=7)
        """
        self._expires = value.replace(microsecond=0)
        if self._expires.tzinfo is None:
            # Naive datetime: just make it UTC
            self._expires = self._expires.replace(tzinfo=timezone.utc)
        elif self._expires.tzinfo != timezone.utc:
            raise ValueError(f"Expected tz UTC, not {self._expires.tzinfo}")

    # NOTE: Signed is a stupid name, because this might not be signed yet, but
    # we keep it to match spec terminology (I often refer to this as "payload",
    # or "inner metadata")
    def __init__(
        self,
        version: Optional[int],
        spec_version: Optional[str],
        expires: Optional[datetime],
        unrecognized_fields: Optional[Dict[str, Any]],
    ):
        if spec_version is None:
            spec_version = ".".join(SPECIFICATION_VERSION)
        # Accept semver (X.Y.Z) but also X.Y for legacy compatibility
        spec_list = spec_version.split(".")
        if len(spec_list) not in [2, 3] or not all(
            el.isdigit() for el in spec_list
        ):
            raise ValueError(f"Failed to parse spec_version {spec_version}")

        # major version must match
        if spec_list[0] != SPECIFICATION_VERSION[0]:
            raise ValueError(f"Unsupported spec_version {spec_version}")

        self.spec_version = spec_version

        self.expires = expires or datetime.now(timezone.utc)

        if version is None:
            version = 1
        elif version <= 0:
            raise ValueError(f"version must be > 0, got {version}")
        self.version = version

        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Signed):
            return False

        return (
            self.type == other.type
            and self.version == other.version
            and self.spec_version == other.spec_version
            and self.expires == other.expires
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @abc.abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Serialize and return a dict representation of self."""
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Signed":
        """Deserialization helper, creates object from json/dict
        representation.
        """
        raise NotImplementedError

    @classmethod
    def _common_fields_from_dict(
        cls, signed_dict: Dict[str, Any]
    ) -> Tuple[int, str, datetime]:
        """Return common fields of ``Signed`` instances from the passed dict
        representation, and returns an ordered list to be passed as leading
        positional arguments to a subclass constructor.

        See ``{Root, Timestamp, Snapshot, Targets}.from_dict``
        methods for usage.

        """
        _type = signed_dict.pop("_type")
        if _type != cls.type:
            raise ValueError(f"Expected type {cls.type}, got {_type}")

        version = signed_dict.pop("version")
        spec_version = signed_dict.pop("spec_version")
        expires_str = signed_dict.pop("expires")
        # Convert 'expires' TUF metadata string to a datetime object, which is
        # what the constructor expects and what we store. The inverse operation
        # is implemented in '_common_fields_to_dict'.
        expires = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )

        return version, spec_version, expires

    def _common_fields_to_dict(self) -> Dict[str, Any]:
        """Return a dict representation of common fields of
        ``Signed`` instances.

        See ``{Root, Timestamp, Snapshot, Targets}.to_dict`` methods for usage.

        """
        return {
            "_type": self._type,
            "version": self.version,
            "spec_version": self.spec_version,
            "expires": self.expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            **self.unrecognized_fields,
        }

    def is_expired(self, reference_time: Optional[datetime] = None) -> bool:
        """Check metadata expiration against a reference time.

        Args:
            reference_time: Time to check expiration date against. A naive
                datetime in UTC expected. Default is current UTC date and time.

        Returns:
            ``True`` if expiration time is less than the reference time.
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)

        return reference_time >= self.expires


class Role:
    """Container that defines which keys are required to sign roles metadata.

    Role defines how many keys are required to successfully sign the roles
    metadata, and which keys are accepted.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        keyids: Roles signing key identifiers.
        threshold: Number of keys required to sign this role's metadata.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError: Invalid arguments.
    """

    def __init__(
        self,
        keyids: List[str],
        threshold: int,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        if len(set(keyids)) != len(keyids):
            raise ValueError(f"Nonunique keyids: {keyids}")
        if threshold < 1:
            raise ValueError("threshold should be at least 1!")
        self.keyids = keyids
        self.threshold = threshold
        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Role):
            return False

        return (
            self.keyids == other.keyids
            and self.threshold == other.threshold
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @classmethod
    def from_dict(cls, role_dict: Dict[str, Any]) -> "Role":
        """Create ``Role`` object from its json/dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
        """
        keyids = role_dict.pop("keyids")
        threshold = role_dict.pop("threshold")
        # All fields left in the role_dict are unrecognized.
        return cls(keyids, threshold, role_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of self."""
        return {
            "keyids": self.keyids,
            "threshold": self.threshold,
            **self.unrecognized_fields,
        }


@dataclass
class VerificationResult:
    """Signature verification result for delegated role metadata.

    Attributes:
        threshold: Number of required signatures.
        signed: dict of keyid to Key, containing keys that have signed.
        unsigned: dict of keyid to Key, containing keys that have not signed.
    """

    threshold: int
    signed: Dict[str, Key]
    unsigned: Dict[str, Key]

    def __bool__(self) -> bool:
        return self.verified

    @property
    def verified(self) -> bool:
        """True if threshold of signatures is met."""
        return len(self.signed) >= self.threshold

    @property
    def missing(self) -> int:
        """Number of additional signatures required to reach threshold."""
        return max(0, self.threshold - len(self.signed))


@dataclass
class RootVerificationResult:
    """Signature verification result for root metadata.

    Root must be verified by itself and the previous root version. This
    dataclass represents both results. For the edge case of first version
    of root, these underlying results are identical.

    Note that `signed` and `unsigned` correctness requires the underlying
    VerificationResult keys to not conflict (no reusing the same keyid for
    different keys).

    Attributes:
        first: First underlying VerificationResult
        second: Second underlying VerificationResult
    """

    first: VerificationResult
    second: VerificationResult

    def __bool__(self) -> bool:
        return self.verified

    @property
    def verified(self) -> bool:
        """True if threshold of signatures is met in both underlying
        VerificationResults.
        """
        return self.first.verified and self.second.verified

    @property
    def signed(self) -> Dict[str, Key]:
        """Dictionary of all signing keys that have signed, from both
        VerificationResults.
        return a union of all signed (in python<3.9 this requires
        dict unpacking)
        """
        return {**self.first.signed, **self.second.signed}

    @property
    def unsigned(self) -> Dict[str, Key]:
        """Dictionary of all signing keys that have not signed, from both
        VerificationResults.
        return a union of all unsigned (in python<3.9 this requires
        dict unpacking)
        """
        return {**self.first.unsigned, **self.second.unsigned}


class _DelegatorMixin(metaclass=abc.ABCMeta):
    """Class that implements verify_delegate() for Root and Targets"""

    @abc.abstractmethod
    def get_delegated_role(self, delegated_role: str) -> Role:
        """Return the role object for the given delegated role.

        Raises ValueError if delegated_role is not actually delegated.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_key(self, keyid: str) -> Key:
        """Return the key object for the given keyid.

        Raises ValueError if key is not found.
        """
        raise NotImplementedError

    def get_verification_result(
        self,
        delegated_role: str,
        payload: bytes,
        signatures: Dict[str, Signature],
    ) -> VerificationResult:
        """Return signature threshold verification result for delegated role.

        NOTE: Unlike `verify_delegate()` this method does not raise, if the
        role metadata is not fully verified.

        Args:
            delegated_role: Name of the delegated role to verify
            payload: Signed payload bytes for the delegated role
            signatures: Signatures over payload bytes

        Raises:
            ValueError: no delegation was found for ``delegated_role``.
        """
        role = self.get_delegated_role(delegated_role)

        signed = {}
        unsigned = {}

        for keyid in role.keyids:
            try:
                key = self.get_key(keyid)
            except ValueError:
                logger.info("No key for keyid %s", keyid)
                continue

            if keyid not in signatures:
                unsigned[keyid] = key
                logger.info("No signature for keyid %s", keyid)
                continue

            sig = signatures[keyid]
            try:
                key.verify_signature(sig, payload)
                signed[keyid] = key
            except sslib_exceptions.UnverifiedSignatureError:
                unsigned[keyid] = key
                logger.info("Key %s failed to verify %s", keyid, delegated_role)

        return VerificationResult(role.threshold, signed, unsigned)

    def verify_delegate(
        self,
        delegated_role: str,
        payload: bytes,
        signatures: Dict[str, Signature],
    ) -> None:
        """Verify signature threshold for delegated role.

        Verify that there are enough valid ``signatures`` over ``payload``, to
        meet the threshold of keys for ``delegated_role``, as defined by the
        delegator (``self``).

        Args:
            delegated_role: Name of the delegated role to verify
            payload: Signed payload bytes for the delegated role
            signatures: Signatures over payload bytes

        Raises:
            UnsignedMetadataError: ``delegated_role`` was not signed with
                required threshold of keys for ``role_name``.
            ValueError: no delegation was found for ``delegated_role``.
        """
        result = self.get_verification_result(
            delegated_role, payload, signatures
        )
        if not result:
            raise UnsignedMetadataError(
                f"{delegated_role} was signed by {len(result.signed)}/"
                f"{result.threshold} keys"
            )


class Root(Signed, _DelegatorMixin):
    """A container for the signed part of root metadata.

    Parameters listed below are also instance attributes.

    Args:
        version: Metadata version number. Default is 1.
        spec_version: Supported TUF specification version. Default is the
            version currently supported by the library.
        expires: Metadata expiry date. Default is current date and time.
        keys: Dictionary of keyids to Keys. Defines the keys used in ``roles``.
            Default is empty dictionary.
        roles: Dictionary of role names to Roles. Defines which keys are
            required to sign the metadata for a specific role. Default is
            a dictionary of top level roles without keys and threshold of 1.
        consistent_snapshot: ``True`` if repository supports consistent
        snapshots. Default is True.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError: Invalid arguments.
    """

    type = _ROOT

    def __init__(
        self,
        version: Optional[int] = None,
        spec_version: Optional[str] = None,
        expires: Optional[datetime] = None,
        keys: Optional[Dict[str, Key]] = None,
        roles: Optional[Dict[str, Role]] = None,
        consistent_snapshot: Optional[bool] = True,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.consistent_snapshot = consistent_snapshot
        self.keys = keys if keys is not None else {}

        if roles is None:
            roles = {r: Role([], 1) for r in TOP_LEVEL_ROLE_NAMES}
        elif set(roles) != TOP_LEVEL_ROLE_NAMES:
            raise ValueError("Role names must be the top-level metadata roles")
        self.roles = roles

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Root):
            return False

        return (
            super().__eq__(other)
            and self.keys == other.keys
            and self.roles == other.roles
            and self.consistent_snapshot == other.consistent_snapshot
        )

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Root":
        """Create ``Root`` object from its json/dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
        common_args = cls._common_fields_from_dict(signed_dict)
        consistent_snapshot = signed_dict.pop("consistent_snapshot", None)
        keys = signed_dict.pop("keys")
        roles = signed_dict.pop("roles")

        for keyid, key_dict in keys.items():
            keys[keyid] = Key.from_dict(keyid, key_dict)
        for role_name, role_dict in roles.items():
            roles[role_name] = Role.from_dict(role_dict)

        # All fields left in the signed_dict are unrecognized.
        return cls(*common_args, keys, roles, consistent_snapshot, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""
        root_dict = self._common_fields_to_dict()
        keys = {keyid: key.to_dict() for (keyid, key) in self.keys.items()}
        roles = {}
        for role_name, role in self.roles.items():
            roles[role_name] = role.to_dict()
        if self.consistent_snapshot is not None:
            root_dict["consistent_snapshot"] = self.consistent_snapshot

        root_dict.update(
            {
                "keys": keys,
                "roles": roles,
            }
        )
        return root_dict

    def add_key(self, key: Key, role: str) -> None:
        """Add new signing key for delegated role ``role``.

        Args:
            key: Signing key to be added for ``role``.
            role: Name of the role, for which ``key`` is added.

        Raises:
            ValueError: If the argument order is wrong or if ``role`` doesn't
                exist.
        """
        # Verify that our users are not using the old argument order.
        if isinstance(role, Key):
            raise ValueError("Role must be a string, not a Key instance")

        if role not in self.roles:
            raise ValueError(f"Role {role} doesn't exist")
        if key.keyid not in self.roles[role].keyids:
            self.roles[role].keyids.append(key.keyid)
        self.keys[key.keyid] = key

    def revoke_key(self, keyid: str, role: str) -> None:
        """Revoke key from ``role`` and updates the key store.

        Args:
            keyid: Identifier of the key to be removed for ``role``.
            role: Name of the role, for which a signing key is removed.

        Raises:
            ValueError: If ``role`` doesn't exist or if ``role`` doesn't include
                the key.
        """
        if role not in self.roles:
            raise ValueError(f"Role {role} doesn't exist")
        if keyid not in self.roles[role].keyids:
            raise ValueError(f"Key with id {keyid} is not used by {role}")
        self.roles[role].keyids.remove(keyid)
        for keyinfo in self.roles.values():
            if keyid in keyinfo.keyids:
                return

        del self.keys[keyid]

    def get_delegated_role(self, delegated_role: str) -> Role:
        """Return the role object for the given delegated role.

        Raises ValueError if delegated_role is not actually delegated.
        """
        if delegated_role not in self.roles:
            raise ValueError(f"Delegated role {delegated_role} not found")

        return self.roles[delegated_role]

    def get_key(self, keyid: str) -> Key:
        if keyid not in self.keys:
            raise ValueError(f"Key {keyid} not found")

        return self.keys[keyid]

    def get_root_verification_result(
        self,
        previous: Optional["Root"],
        payload: bytes,
        signatures: Dict[str, Signature],
    ) -> RootVerificationResult:
        """Return signature threshold verification result for two root roles.

        Verify root metadata with two roles (`self` and optionally `previous`).

        If the repository has no root role versions yet, `previous` can be left
        None. In all other cases, `previous` must be the previous version of
        the Root.

        NOTE: Unlike `verify_delegate()` this method does not raise, if the
        root metadata is not fully verified.

        Args:
            previous: The previous `Root` to verify payload with, or None
            payload: Signed payload bytes for root
            signatures: Signatures over payload bytes

        Raises:
            ValueError: no delegation was found for ``root`` or given Root
                versions are not sequential.
        """

        if previous is None:
            previous = self
        elif self.version != previous.version + 1:
            versions = f"v{previous.version} and v{self.version}"
            raise ValueError(
                f"Expected sequential root versions, got {versions}."
            )

        return RootVerificationResult(
            previous.get_verification_result(Root.type, payload, signatures),
            self.get_verification_result(Root.type, payload, signatures),
        )


class BaseFile:
    """A base class of ``MetaFile`` and ``TargetFile``.

    Encapsulates common static methods for length and hash verification.
    """

    @staticmethod
    def _verify_hashes(
        data: Union[bytes, IO[bytes]], expected_hashes: Dict[str, str]
    ) -> None:
        """Verify that the hash of ``data`` matches ``expected_hashes``."""
        is_bytes = isinstance(data, bytes)
        for algo, exp_hash in expected_hashes.items():
            try:
                if is_bytes:
                    digest_object = sslib_hash.digest(algo)
                    digest_object.update(data)
                else:
                    # if data is not bytes, assume it is a file object
                    digest_object = sslib_hash.digest_fileobject(data, algo)
            except (
                sslib_exceptions.UnsupportedAlgorithmError,
                sslib_exceptions.FormatError,
            ) as e:
                raise LengthOrHashMismatchError(
                    f"Unsupported algorithm '{algo}'"
                ) from e

            observed_hash = digest_object.hexdigest()
            if observed_hash != exp_hash:
                raise LengthOrHashMismatchError(
                    f"Observed hash {observed_hash} does not match "
                    f"expected hash {exp_hash}"
                )

    @staticmethod
    def _verify_length(
        data: Union[bytes, IO[bytes]], expected_length: int
    ) -> None:
        """Verify that the length of ``data`` matches ``expected_length``."""
        if isinstance(data, bytes):
            observed_length = len(data)
        else:
            # if data is not bytes, assume it is a file object
            data.seek(0, io.SEEK_END)
            observed_length = data.tell()

        if observed_length != expected_length:
            raise LengthOrHashMismatchError(
                f"Observed length {observed_length} does not match "
                f"expected length {expected_length}"
            )

    @staticmethod
    def _validate_hashes(hashes: Dict[str, str]) -> None:
        if not hashes:
            raise ValueError("Hashes must be a non empty dictionary")
        for key, value in hashes.items():
            if not (isinstance(key, str) and isinstance(value, str)):
                raise TypeError("Hashes items must be strings")

    @staticmethod
    def _validate_length(length: int) -> None:
        if length < 0:
            raise ValueError(f"Length must be >= 0, got {length}")

    @staticmethod
    def _get_length_and_hashes(
        data: Union[bytes, IO[bytes]], hash_algorithms: Optional[List[str]]
    ) -> Tuple[int, Dict[str, str]]:
        """Calculate length and hashes of ``data``."""
        if isinstance(data, bytes):
            length = len(data)
        else:
            data.seek(0, io.SEEK_END)
            length = data.tell()

        hashes = {}

        if hash_algorithms is None:
            hash_algorithms = [sslib_hash.DEFAULT_HASH_ALGORITHM]

        for algorithm in hash_algorithms:
            try:
                if isinstance(data, bytes):
                    digest_object = sslib_hash.digest(algorithm)
                    digest_object.update(data)
                else:
                    digest_object = sslib_hash.digest_fileobject(
                        data, algorithm
                    )
            except (
                sslib_exceptions.UnsupportedAlgorithmError,
                sslib_exceptions.FormatError,
            ) as e:
                raise ValueError(f"Unsupported algorithm '{algorithm}'") from e

            hashes[algorithm] = digest_object.hexdigest()

        return (length, hashes)


class MetaFile(BaseFile):
    """A container with information about a particular metadata file.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Version of the metadata file.
        length: Length of the metadata file in bytes.
        hashes: Dictionary of hash algorithm names to hashes of the metadata
            file content.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError, TypeError: Invalid arguments.
    """

    def __init__(
        self,
        version: int = 1,
        length: Optional[int] = None,
        hashes: Optional[Dict[str, str]] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        if version <= 0:
            raise ValueError(f"Metafile version must be > 0, got {version}")
        if length is not None:
            self._validate_length(length)
        if hashes is not None:
            self._validate_hashes(hashes)

        self.version = version
        self.length = length
        self.hashes = hashes
        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MetaFile):
            return False

        return (
            self.version == other.version
            and self.length == other.length
            and self.hashes == other.hashes
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @classmethod
    def from_dict(cls, meta_dict: Dict[str, Any]) -> "MetaFile":
        """Create ``MetaFile`` object from its json/dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
        """
        version = meta_dict.pop("version")
        length = meta_dict.pop("length", None)
        hashes = meta_dict.pop("hashes", None)

        # All fields left in the meta_dict are unrecognized.
        return cls(version, length, hashes, meta_dict)

    @classmethod
    def from_data(
        cls,
        version: int,
        data: Union[bytes, IO[bytes]],
        hash_algorithms: List[str],
    ) -> "MetaFile":
        """Creates MetaFile object from bytes.
        This constructor should only be used if hashes are wanted.
        By default, MetaFile(ver) should be used.
        Args:
            version: Version of the metadata file.
            data: Metadata bytes that the metafile represents.
            hash_algorithms: Hash algorithms to create the hashes with. If not
            specified, the securesystemslib default hash algorithm is used.

        Raises:
            ValueError: The hash algorithms list contains an unsupported
            algorithm.
        """
        length, hashes = cls._get_length_and_hashes(data, hash_algorithms)
        return cls(version, length, hashes)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of self."""
        res_dict: Dict[str, Any] = {
            "version": self.version,
            **self.unrecognized_fields,
        }

        if self.length is not None:
            res_dict["length"] = self.length

        if self.hashes is not None:
            res_dict["hashes"] = self.hashes

        return res_dict

    def verify_length_and_hashes(self, data: Union[bytes, IO[bytes]]) -> None:
        """Verify that the length and hashes of ``data`` match expected values.

        Args:
            data: File object or its content in bytes.

        Raises:
            LengthOrHashMismatchError: Calculated length or hashes do not
                match expected values or hash algorithm is not supported.
        """
        if self.length is not None:
            self._verify_length(data, self.length)

        if self.hashes is not None:
            self._verify_hashes(data, self.hashes)


class Timestamp(Signed):
    """A container for the signed part of timestamp metadata.

    TUF file format uses a dictionary to contain the snapshot information:
    this is not the case with ``Timestamp.snapshot_meta`` which is a
    ``MetaFile``.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number. Default is 1.
        spec_version: Supported TUF specification version. Default is the
            version currently supported by the library.
        expires: Metadata expiry date. Default is current date and time.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API
        snapshot_meta: Meta information for snapshot metadata. Default is a
            MetaFile with version 1.

    Raises:
        ValueError: Invalid arguments.
    """

    type = _TIMESTAMP

    def __init__(
        self,
        version: Optional[int] = None,
        spec_version: Optional[str] = None,
        expires: Optional[datetime] = None,
        snapshot_meta: Optional[MetaFile] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.snapshot_meta = snapshot_meta or MetaFile(1)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Timestamp):
            return False

        return (
            super().__eq__(other) and self.snapshot_meta == other.snapshot_meta
        )

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Timestamp":
        """Create ``Timestamp`` object from its json/dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
        """
        common_args = cls._common_fields_from_dict(signed_dict)
        meta_dict = signed_dict.pop("meta")
        snapshot_meta = MetaFile.from_dict(meta_dict["snapshot.json"])
        # All fields left in the timestamp_dict are unrecognized.
        return cls(*common_args, snapshot_meta, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""
        res_dict = self._common_fields_to_dict()
        res_dict["meta"] = {"snapshot.json": self.snapshot_meta.to_dict()}
        return res_dict


class Snapshot(Signed):
    """A container for the signed part of snapshot metadata.

    Snapshot contains information about all target Metadata files.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number. Default is 1.
        spec_version: Supported TUF specification version. Default is the
            version currently supported by the library.
        expires: Metadata expiry date. Default is current date and time.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API
        meta: Dictionary of targets filenames to ``MetaFile`` objects. Default
            is a dictionary with a Metafile for "snapshot.json" version 1.

    Raises:
        ValueError: Invalid arguments.
    """

    type = _SNAPSHOT

    def __init__(
        self,
        version: Optional[int] = None,
        spec_version: Optional[str] = None,
        expires: Optional[datetime] = None,
        meta: Optional[Dict[str, MetaFile]] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.meta = meta if meta is not None else {"targets.json": MetaFile(1)}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Snapshot):
            return False

        return super().__eq__(other) and self.meta == other.meta

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Snapshot":
        """Create ``Snapshot`` object from its json/dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
        """
        common_args = cls._common_fields_from_dict(signed_dict)
        meta_dicts = signed_dict.pop("meta")
        meta = {}
        for meta_path, meta_dict in meta_dicts.items():
            meta[meta_path] = MetaFile.from_dict(meta_dict)
        # All fields left in the snapshot_dict are unrecognized.
        return cls(*common_args, meta, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""
        snapshot_dict = self._common_fields_to_dict()
        meta_dict = {}
        for meta_path, meta_info in self.meta.items():
            meta_dict[meta_path] = meta_info.to_dict()

        snapshot_dict["meta"] = meta_dict
        return snapshot_dict


class DelegatedRole(Role):
    """A container with information about a delegated role.

    A delegation can happen in two ways:

        - ``paths`` is set: delegates targets matching any path pattern in
          ``paths``
        - ``path_hash_prefixes`` is set: delegates targets whose target path
          hash starts with any of the prefixes in ``path_hash_prefixes``

        ``paths`` and ``path_hash_prefixes`` are mutually exclusive:
        both cannot be set, at least one of them must be set.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        name: Delegated role name.
        keyids: Delegated role signing key identifiers.
        threshold: Number of keys required to sign this role's metadata.
        terminating: ``True`` if this delegation terminates a target lookup.
        paths: Path patterns. See note above.
        path_hash_prefixes: Hash prefixes. See note above.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API.

    Raises:
        ValueError: Invalid arguments.
    """

    def __init__(
        self,
        name: str,
        keyids: List[str],
        threshold: int,
        terminating: bool,
        paths: Optional[List[str]] = None,
        path_hash_prefixes: Optional[List[str]] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(keyids, threshold, unrecognized_fields)
        self.name = name
        self.terminating = terminating
        exclusive_vars = [paths, path_hash_prefixes]
        if sum(1 for var in exclusive_vars if var is not None) != 1:
            raise ValueError(
                "Only one of (paths, path_hash_prefixes) must be set"
            )

        if paths is not None and any(not isinstance(p, str) for p in paths):
            raise ValueError("Paths must be strings")
        if path_hash_prefixes is not None and any(
            not isinstance(p, str) for p in path_hash_prefixes
        ):
            raise ValueError("Path_hash_prefixes must be strings")

        self.paths = paths
        self.path_hash_prefixes = path_hash_prefixes

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DelegatedRole):
            return False

        return (
            super().__eq__(other)
            and self.name == other.name
            and self.terminating == other.terminating
            and self.paths == other.paths
            and self.path_hash_prefixes == other.path_hash_prefixes
        )

    @classmethod
    def from_dict(cls, role_dict: Dict[str, Any]) -> "DelegatedRole":
        """Create ``DelegatedRole`` object from its json/dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
        name = role_dict.pop("name")
        keyids = role_dict.pop("keyids")
        threshold = role_dict.pop("threshold")
        terminating = role_dict.pop("terminating")
        paths = role_dict.pop("paths", None)
        path_hash_prefixes = role_dict.pop("path_hash_prefixes", None)
        # All fields left in the role_dict are unrecognized.
        return cls(
            name,
            keyids,
            threshold,
            terminating,
            paths,
            path_hash_prefixes,
            role_dict,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""
        base_role_dict = super().to_dict()
        res_dict = {
            "name": self.name,
            "terminating": self.terminating,
            **base_role_dict,
        }
        if self.paths is not None:
            res_dict["paths"] = self.paths
        elif self.path_hash_prefixes is not None:
            res_dict["path_hash_prefixes"] = self.path_hash_prefixes
        return res_dict

    @staticmethod
    def _is_target_in_pathpattern(targetpath: str, pathpattern: str) -> bool:
        """Determine whether ``targetpath`` matches the ``pathpattern``."""
        # We need to make sure that targetpath and pathpattern are pointing to
        # the same directory as fnmatch doesn't threat "/" as a special symbol.
        target_parts = targetpath.split("/")
        pattern_parts = pathpattern.split("/")
        if len(target_parts) != len(pattern_parts):
            return False

        # Every part in the pathpattern could include a glob pattern, that's why
        # each of the target and pathpattern parts should match.
        for target_dir, pattern_dir in zip(target_parts, pattern_parts):
            if not fnmatch.fnmatch(target_dir, pattern_dir):
                return False

        return True

    def is_delegated_path(self, target_filepath: str) -> bool:
        """Determine whether the given ``target_filepath`` is in one of
        the paths that ``DelegatedRole`` is trusted to provide.

        The ``target_filepath`` and the ``DelegatedRole`` paths are expected to
        be in their canonical forms, so e.g. "a/b" instead of "a//b" . Only "/"
        is supported as target path separator. Leading separators are not
        handled as special cases (see `TUF specification on targetpath
        <https://theupdateframework.github.io/specification/latest/#targetpath>`_).

        Args:
            target_filepath: URL path to a target file, relative to a base
                targets URL.
        """

        if self.path_hash_prefixes is not None:
            # Calculate the hash of the filepath
            # to determine in which bin to find the target.
            digest_object = sslib_hash.digest(algorithm="sha256")
            digest_object.update(target_filepath.encode("utf-8"))
            target_filepath_hash = digest_object.hexdigest()

            for path_hash_prefix in self.path_hash_prefixes:
                if target_filepath_hash.startswith(path_hash_prefix):
                    return True

        elif self.paths is not None:
            for pathpattern in self.paths:
                # A delegated role path may be an explicit path or glob
                # pattern (Unix shell-style wildcards).
                if self._is_target_in_pathpattern(target_filepath, pathpattern):
                    return True

        return False


class SuccinctRoles(Role):
    """Succinctly defines a hash bin delegation graph.

    A ``SuccinctRoles`` object describes a delegation graph that covers all
    targets, distributing them uniformly over the delegated roles (i.e. bins)
    in the graph.

    The total number of bins is 2 to the power of the passed ``bit_length``.

    Bin names are the concatenation of the passed ``name_prefix`` and a
    zero-padded hex representation of the bin index separated by a hyphen.

    The passed ``keyids`` and ``threshold`` is used for each bin, and each bin
    is 'terminating'.

    For details: https://github.com/theupdateframework/taps/blob/master/tap15.md

    Args:
        keyids: Signing key identifiers for any bin metadata.
        threshold: Number of keys required to sign any bin metadata.
        bit_length: Number of bits between 1 and 32.
        name_prefix: Prefix of all bin names.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API.

    Raises:
            ValueError, TypeError, AttributeError: Invalid arguments.
    """

    def __init__(
        self,
        keyids: List[str],
        threshold: int,
        bit_length: int,
        name_prefix: str,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(keyids, threshold, unrecognized_fields)

        if bit_length <= 0 or bit_length > 32:
            raise ValueError("bit_length must be between 1 and 32")
        if not isinstance(name_prefix, str):
            raise ValueError("name_prefix must be a string")

        self.bit_length = bit_length
        self.name_prefix = name_prefix

        # Calculate the suffix_len value based on the total number of bins in
        # hex. If bit_length = 10 then number_of_bins = 1024 or bin names will
        # have a suffix between "000" and "3ff" in hex and suffix_len will be 3
        # meaning the third bin will have a suffix of "003".
        self.number_of_bins = 2**bit_length
        # suffix_len is calculated based on "number_of_bins - 1" as the name
        # of the last bin contains the number "number_of_bins -1" as a suffix.
        self.suffix_len = len(f"{self.number_of_bins-1:x}")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SuccinctRoles):
            return False

        return (
            super().__eq__(other)
            and self.bit_length == other.bit_length
            and self.name_prefix == other.name_prefix
        )

    @classmethod
    def from_dict(cls, role_dict: Dict[str, Any]) -> "SuccinctRoles":
        """Create ``SuccinctRoles`` object from its json/dict representation.

        Raises:
            ValueError, KeyError, AttributeError, TypeError: Invalid arguments.
        """
        keyids = role_dict.pop("keyids")
        threshold = role_dict.pop("threshold")
        bit_length = role_dict.pop("bit_length")
        name_prefix = role_dict.pop("name_prefix")
        # All fields left in the role_dict are unrecognized.
        return cls(keyids, threshold, bit_length, name_prefix, role_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""
        base_role_dict = super().to_dict()
        return {
            "bit_length": self.bit_length,
            "name_prefix": self.name_prefix,
            **base_role_dict,
        }

    def get_role_for_target(self, target_filepath: str) -> str:
        """Calculate the name of the delegated role responsible for
        ``target_filepath``.

        The target at path ``target_filepath`` is assigned to a bin by casting
        the left-most ``bit_length`` of bits of the file path hash digest to
        int, using it as bin index between 0 and ``2**bit_length - 1``.

        Args:
            target_filepath: URL path to a target file, relative to a base
                targets URL.
        """
        hasher = sslib_hash.digest(algorithm="sha256")
        hasher.update(target_filepath.encode("utf-8"))

        # We can't ever need more than 4 bytes (32 bits).
        hash_bytes = hasher.digest()[:4]
        # Right shift hash bytes, so that we only have the leftmost
        # bit_length bits that we care about.
        shift_value = 32 - self.bit_length
        bin_number = int.from_bytes(hash_bytes, byteorder="big") >> shift_value
        # Add zero padding if necessary and cast to hex the suffix.
        suffix = f"{bin_number:0{self.suffix_len}x}"
        return f"{self.name_prefix}-{suffix}"

    def get_roles(self) -> Iterator[str]:
        """Yield the names of all different delegated roles one by one."""
        for i in range(self.number_of_bins):
            suffix = f"{i:0{self.suffix_len}x}"
            yield f"{self.name_prefix}-{suffix}"

    def is_delegated_role(self, role_name: str) -> bool:
        """Determine whether the given ``role_name`` is in one of
        the delegated roles that ``SuccinctRoles`` represents.

        Args:
            role_name: The name of the role to check against.
        """
        desired_prefix = self.name_prefix + "-"

        if not role_name.startswith(desired_prefix):
            return False

        suffix = role_name[len(desired_prefix) :]
        if len(suffix) != self.suffix_len:
            return False

        try:
            # make sure suffix is hex value
            num = int(suffix, 16)
        except ValueError:
            return False

        return 0 <= num < self.number_of_bins


class Delegations:
    """A container object storing information about all delegations.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        keys: Dictionary of keyids to Keys. Defines the keys used in ``roles``.
        roles: Ordered dictionary of role names to DelegatedRoles instances. It
            defines which keys are required to sign the metadata for a specific
            role. The roles order also defines the order that role delegations
            are considered during target searches.
        succinct_roles: Contains succinct information about hash bin
            delegations. Note that succinct roles is not a TUF specification
            feature yet and setting `succinct_roles` to a value makes the
            resulting metadata non-compliant. The metadata will not be accepted
            as valid by specification compliant clients such as those built with
            python-tuf <= 1.1.0. For more information see: https://github.com/theupdateframework/taps/blob/master/tap15.md
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Exactly one of ``roles`` and ``succinct_roles`` must be set.

    Raises:
        ValueError: Invalid arguments.
    """

    def __init__(
        self,
        keys: Dict[str, Key],
        roles: Optional[Dict[str, DelegatedRole]] = None,
        succinct_roles: Optional[SuccinctRoles] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        self.keys = keys
        if sum(1 for v in [roles, succinct_roles] if v is not None) != 1:
            raise ValueError("One of roles and succinct_roles must be set")

        if roles is not None:
            for role in roles:
                if not role or role in TOP_LEVEL_ROLE_NAMES:
                    raise ValueError(
                        "Delegated roles cannot be empty or use top-level "
                        "role names"
                    )

        self.roles = roles
        self.succinct_roles = succinct_roles
        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Delegations):
            return False

        all_attributes_check = (
            self.keys == other.keys
            and self.roles == other.roles
            and self.succinct_roles == other.succinct_roles
            and self.unrecognized_fields == other.unrecognized_fields
        )

        if self.roles is not None and other.roles is not None:
            all_attributes_check = (
                all_attributes_check
                # Order of the delegated roles matters (see issue #1788).
                and list(self.roles.items()) == list(other.roles.items())
            )

        return all_attributes_check

    @classmethod
    def from_dict(cls, delegations_dict: Dict[str, Any]) -> "Delegations":
        """Create ``Delegations`` object from its json/dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
        keys = delegations_dict.pop("keys")
        keys_res = {}
        for keyid, key_dict in keys.items():
            keys_res[keyid] = Key.from_dict(keyid, key_dict)
        roles = delegations_dict.pop("roles", None)
        roles_res: Optional[Dict[str, DelegatedRole]] = None

        if roles is not None:
            roles_res = {}
            for role_dict in roles:
                new_role = DelegatedRole.from_dict(role_dict)
                if new_role.name in roles_res:
                    raise ValueError(f"Duplicate role {new_role.name}")
                roles_res[new_role.name] = new_role

        succinct_roles_dict = delegations_dict.pop("succinct_roles", None)
        succinct_roles_info = None
        if succinct_roles_dict is not None:
            succinct_roles_info = SuccinctRoles.from_dict(succinct_roles_dict)

        # All fields left in the delegations_dict are unrecognized.
        return cls(keys_res, roles_res, succinct_roles_info, delegations_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""
        keys = {keyid: key.to_dict() for keyid, key in self.keys.items()}
        res_dict: Dict[str, Any] = {
            "keys": keys,
            **self.unrecognized_fields,
        }
        if self.roles is not None:
            roles = [role_obj.to_dict() for role_obj in self.roles.values()]
            res_dict["roles"] = roles
        elif self.succinct_roles is not None:
            res_dict["succinct_roles"] = self.succinct_roles.to_dict()

        return res_dict

    def get_roles_for_target(
        self, target_filepath: str
    ) -> Iterator[Tuple[str, bool]]:
        """Given ``target_filepath`` get names and terminating status of all
        delegated roles who are responsible for it.

        Args:
            target_filepath: URL path to a target file, relative to a base
                targets URL.
        """
        if self.roles is not None:
            for role in self.roles.values():
                if role.is_delegated_path(target_filepath):
                    yield role.name, role.terminating

        elif self.succinct_roles is not None:
            # We consider all succinct_roles as terminating.
            # For more information read TAP 15.
            yield self.succinct_roles.get_role_for_target(target_filepath), True


class TargetFile(BaseFile):
    """A container with information about a particular target file.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        length: Length of the target file in bytes.
        hashes: Dictionary of hash algorithm names to hashes of the target
            file content.
        path: URL path to a target file, relative to a base targets URL.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError, TypeError: Invalid arguments.
    """

    def __init__(
        self,
        length: int,
        hashes: Dict[str, str],
        path: str,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        self._validate_length(length)
        self._validate_hashes(hashes)

        self.length = length
        self.hashes = hashes
        self.path = path
        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    @property
    def custom(self) -> Any:  # noqa: ANN401
        """Get implementation specific data related to the target.

        python-tuf does not use or validate this data.
        """
        return self.unrecognized_fields.get("custom")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TargetFile):
            return False

        return (
            self.length == other.length
            and self.hashes == other.hashes
            and self.path == other.path
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @classmethod
    def from_dict(cls, target_dict: Dict[str, Any], path: str) -> "TargetFile":
        """Create ``TargetFile`` object from its json/dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
        length = target_dict.pop("length")
        hashes = target_dict.pop("hashes")

        # All fields left in the target_dict are unrecognized.
        return cls(length, hashes, path, target_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the JSON-serializable dictionary representation of self."""
        return {
            "length": self.length,
            "hashes": self.hashes,
            **self.unrecognized_fields,
        }

    @classmethod
    def from_file(
        cls,
        target_file_path: str,
        local_path: str,
        hash_algorithms: Optional[List[str]] = None,
    ) -> "TargetFile":
        """Create ``TargetFile`` object from a file.

        Args:
            target_file_path: URL path to a target file, relative to a base
                targets URL.
            local_path: Local path to target file content.
            hash_algorithms: Hash algorithms to calculate hashes with. If not
                specified the securesystemslib default hash algorithm is used.

        Raises:
            FileNotFoundError: The file doesn't exist.
            ValueError: The hash algorithms list contains an unsupported
                algorithm.
        """
        with open(local_path, "rb") as file:
            return cls.from_data(target_file_path, file, hash_algorithms)

    @classmethod
    def from_data(
        cls,
        target_file_path: str,
        data: Union[bytes, IO[bytes]],
        hash_algorithms: Optional[List[str]] = None,
    ) -> "TargetFile":
        """Create ``TargetFile`` object from bytes.

        Args:
            target_file_path: URL path to a target file, relative to a base
                targets URL.
            data: Target file content.
            hash_algorithms: Hash algorithms to create the hashes with. If not
                specified the securesystemslib default hash algorithm is used.

        Raises:
            ValueError: The hash algorithms list contains an unsupported
                algorithm.
        """
        length, hashes = cls._get_length_and_hashes(data, hash_algorithms)
        return cls(length, hashes, target_file_path)

    def verify_length_and_hashes(self, data: Union[bytes, IO[bytes]]) -> None:
        """Verify that length and hashes of ``data`` match expected values.

        Args:
            data: Target file object or its content in bytes.

        Raises:
            LengthOrHashMismatchError: Calculated length or hashes do not
                match expected values or hash algorithm is not supported.
        """
        self._verify_length(data, self.length)
        self._verify_hashes(data, self.hashes)

    def get_prefixed_paths(self) -> List[str]:
        """
        Return hash-prefixed URL path fragments for the target file path.
        """
        paths = []
        parent, sep, name = self.path.rpartition("/")
        for hash_value in self.hashes.values():
            paths.append(f"{parent}{sep}{hash_value}.{name}")

        return paths


class Targets(Signed, _DelegatorMixin):
    """A container for the signed part of targets metadata.

    Targets contains verifying information about target files and also
    delegates responsibility to other Targets roles.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number. Default is 1.
        spec_version: Supported TUF specification version. Default is the
            version currently supported by the library.
        expires: Metadata expiry date. Default is current date and time.
        targets: Dictionary of target filenames to TargetFiles. Default is an
            empty dictionary.
        delegations: Defines how this Targets delegates responsibility to other
            Targets Metadata files. Default is None.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError: Invalid arguments.
    """

    type = _TARGETS

    def __init__(
        self,
        version: Optional[int] = None,
        spec_version: Optional[str] = None,
        expires: Optional[datetime] = None,
        targets: Optional[Dict[str, TargetFile]] = None,
        delegations: Optional[Delegations] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.targets = targets if targets is not None else {}
        self.delegations = delegations

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Targets):
            return False

        return (
            super().__eq__(other)
            and self.targets == other.targets
            and self.delegations == other.delegations
        )

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Targets":
        """Create ``Targets`` object from its json/dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
        common_args = cls._common_fields_from_dict(signed_dict)
        targets = signed_dict.pop(_TARGETS)
        try:
            delegations_dict = signed_dict.pop("delegations")
        except KeyError:
            delegations = None
        else:
            delegations = Delegations.from_dict(delegations_dict)
        res_targets = {}
        for target_path, target_info in targets.items():
            res_targets[target_path] = TargetFile.from_dict(
                target_info, target_path
            )
        # All fields left in the targets_dict are unrecognized.
        return cls(*common_args, res_targets, delegations, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""
        targets_dict = self._common_fields_to_dict()
        targets = {}
        for target_path, target_file_obj in self.targets.items():
            targets[target_path] = target_file_obj.to_dict()
        targets_dict[_TARGETS] = targets
        if self.delegations is not None:
            targets_dict["delegations"] = self.delegations.to_dict()
        return targets_dict

    def add_key(self, key: Key, role: Optional[str] = None) -> None:
        """Add new signing key for delegated role ``role``.

        If succinct_roles is used then the ``role`` argument is not required.

        Args:
            key: Signing key to be added for ``role``.
            role: Name of the role, for which ``key`` is added.

        Raises:
            ValueError: If the argument order is wrong or if there are no
                delegated roles or if ``role`` is not delegated by this Target.
        """
        # Verify that our users are not using the old argument order.
        if isinstance(role, Key):
            raise ValueError("Role must be a string, not a Key instance")

        if self.delegations is None:
            raise ValueError(f"Delegated role {role} doesn't exist")

        if self.delegations.roles is not None:
            if role not in self.delegations.roles:
                raise ValueError(f"Delegated role {role} doesn't exist")
            if key.keyid not in self.delegations.roles[role].keyids:
                self.delegations.roles[role].keyids.append(key.keyid)

        elif self.delegations.succinct_roles is not None:
            if key.keyid not in self.delegations.succinct_roles.keyids:
                self.delegations.succinct_roles.keyids.append(key.keyid)

        self.delegations.keys[key.keyid] = key

    def revoke_key(self, keyid: str, role: Optional[str] = None) -> None:
        """Revokes key from delegated role ``role`` and updates the delegations
        key store.

        If succinct_roles is used then the ``role`` argument is not required.

        Args:
            keyid: Identifier of the key to be removed for ``role``.
            role: Name of the role, for which a signing key is removed.

        Raises:
            ValueError: If there are no delegated roles or if ``role`` is not
                delegated by this ``Target`` or if key is not used by ``role``
                or if key with id ``keyid`` is not used by succinct roles.
        """
        if self.delegations is None:
            raise ValueError(f"Delegated role {role} doesn't exist")

        if self.delegations.roles is not None:
            if role not in self.delegations.roles:
                raise ValueError(f"Delegated role {role} doesn't exist")
            if keyid not in self.delegations.roles[role].keyids:
                raise ValueError(f"Key with id {keyid} is not used by {role}")

            self.delegations.roles[role].keyids.remove(keyid)
            for keyinfo in self.delegations.roles.values():
                if keyid in keyinfo.keyids:
                    return

        elif self.delegations.succinct_roles is not None:
            if keyid not in self.delegations.succinct_roles.keyids:
                raise ValueError(
                    f"Key with id {keyid} is not used by succinct_roles"
                )

            self.delegations.succinct_roles.keyids.remove(keyid)

        del self.delegations.keys[keyid]

    def get_delegated_role(self, delegated_role: str) -> Role:
        """Return the role object for the given delegated role.

        Raises ValueError if delegated_role is not actually delegated.
        """
        if self.delegations is None:
            raise ValueError("No delegations found")

        role: Optional[Role] = None
        if self.delegations.roles is not None:
            role = self.delegations.roles.get(delegated_role)
        elif self.delegations.succinct_roles is not None:
            succinct = self.delegations.succinct_roles
            if succinct.is_delegated_role(delegated_role):
                role = succinct

        if not role:
            raise ValueError(f"Delegated role {delegated_role} not found")

        return role

    def get_key(self, keyid: str) -> Key:
        if self.delegations is None:
            raise ValueError("No delegations found")
        if keyid not in self.delegations.keys:
            raise ValueError(f"Key {keyid} not found")

        return self.delegations.keys[keyid]
