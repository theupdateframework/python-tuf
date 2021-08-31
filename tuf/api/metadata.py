# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF role metadata model.

This module provides container classes for TUF role metadata, including methods
to read and write from and to file, perform TUF-compliant metadata updates, and
create and verify signatures.

The metadata model supports any custom serialization format, defaulting to JSON
as wireline format and Canonical JSON for reproducible signature creation and
verification.
Custom serializers must implement the abstract serialization interface defined
in 'tuf.api.serialization', and may use the [to|from]_dict convenience methods
available in the class model.

"""
import abc
import fnmatch
import io
import logging
import tempfile
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import (
    IO,
    Any,
    ClassVar,
    Dict,
    Generic,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from securesystemslib import exceptions as sslib_exceptions
from securesystemslib import hash as sslib_hash
from securesystemslib import keys as sslib_keys
from securesystemslib.signer import Signature, Signer
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface
from securesystemslib.util import persist_temp_file

from tuf import exceptions
from tuf.api.serialization import (
    MetadataDeserializer,
    MetadataSerializer,
    SignedSerializer,
)

# pylint: disable=too-many-lines

logger = logging.getLogger(__name__)

# We aim to support SPECIFICATION_VERSION and require the input metadata
# files to have the same major version (the first number) as ours.
SPECIFICATION_VERSION = ["1", "0", "19"]

# T is a Generic type constraint for Metadata.signed
T = TypeVar("T", "Root", "Timestamp", "Snapshot", "Targets")


class Metadata(Generic[T]):
    """A container for signed TUF metadata.

    Provides methods to convert to and from dictionary, read and write to and
    from file and to create and verify metadata signatures.

    Metadata[T] is a generic container type where T can be any one type of
    [Root, Timestamp, Snapshot, Targets]. The purpose of this is to allow
    static type checking of the signed attribute in code using Metadata::

        root_md = Metadata[Root].from_file("root.json")
        # root_md type is now Metadata[Root]. This means signed and its
        # attributes like consistent_snapshot are now statically typed and the
        # types can be verified by static type checkers and shown by IDEs
        print(root_md.signed.consistent_snapshot)

    Using a type constraint is not required but not doing so means T is not a
    specific type so static typing cannot happen. Note that the type constraint
    "[Root]" is not validated at runtime (as pure annotations are not available
    then).

    Attributes:
        signed: A subclass of Signed, which has the actual metadata payload,
            i.e. one of Targets, Snapshot, Timestamp or Root.
        signatures: An ordered dictionary of keyids to Signature objects, each
            signing the canonical serialized representation of 'signed'.
    """

    def __init__(self, signed: T, signatures: "OrderedDict[str, Signature]"):
        self.signed: T = signed
        self.signatures = signatures

    @classmethod
    def from_dict(cls, metadata: Dict[str, Any]) -> "Metadata[T]":
        """Creates Metadata object from its dict representation.

        Arguments:
            metadata: TUF metadata in dict representation.

        Raises:
            KeyError: The metadata dict format is invalid.
            ValueError: The metadata has an unrecognized signed._type field.

        Side Effect:
            Destroys the metadata dict passed by reference.

        Returns:
            A TUF Metadata object.
        """

        # Dispatch to contained metadata class on metadata _type field.
        _type = metadata["signed"]["_type"]

        if _type == "targets":
            inner_cls: Type[Signed] = Targets
        elif _type == "snapshot":
            inner_cls = Snapshot
        elif _type == "timestamp":
            inner_cls = Timestamp
        elif _type == "root":
            inner_cls = Root
        else:
            raise ValueError(f'unrecognized metadata type "{_type}"')

        # Make sure signatures are unique
        signatures: "OrderedDict[str, Signature]" = OrderedDict()
        for sig_dict in metadata.pop("signatures"):
            sig = Signature.from_dict(sig_dict)
            if sig.keyid in signatures:
                raise ValueError(
                    f"Multiple signatures found for keyid {sig.keyid}"
                )
            signatures[sig.keyid] = sig

        return cls(
            # Specific type T is not known at static type check time: use cast
            signed=cast(T, inner_cls.from_dict(metadata.pop("signed"))),
            signatures=signatures,
        )

    @classmethod
    def from_file(
        cls,
        filename: str,
        deserializer: Optional[MetadataDeserializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> "Metadata[T]":
        """Loads TUF metadata from file storage.

        Arguments:
            filename: The path to read the file from.
            deserializer: A MetadataDeserializer subclass instance that
                implements the desired wireline format deserialization. Per
                default a JSONDeserializer is used.
            storage_backend: An object that implements
                securesystemslib.storage.StorageBackendInterface. Per default
                a (local) FilesystemBackend is used.

        Raises:
            securesystemslib.exceptions.StorageError: The file cannot be read.
            tuf.api.serialization.DeserializationError:
                The file cannot be deserialized.

        Returns:
            A TUF Metadata object.
        """

        if storage_backend is None:
            storage_backend = FilesystemBackend()

        with storage_backend.get(filename) as file_obj:
            return cls.from_bytes(file_obj.read(), deserializer)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        deserializer: Optional[MetadataDeserializer] = None,
    ) -> "Metadata[T]":
        """Loads TUF metadata from raw data.

        Arguments:
            data: metadata content as bytes.
            deserializer: Optional; A MetadataDeserializer instance that
                implements deserialization. Default is JSONDeserializer.

        Raises:
            tuf.api.serialization.DeserializationError:
                The file cannot be deserialized.

        Returns:
            A TUF Metadata object.
        """

        if deserializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import JSONDeserializer

            deserializer = JSONDeserializer()

        return deserializer.deserialize(data)

    def to_bytes(
        self, serializer: Optional[MetadataSerializer] = None
    ) -> bytes:
        """Return the serialized TUF file format as bytes.

        Arguments:
            serializer: A MetadataSerializer instance that implements the
                desired serialization format. Default is JSONSerializer.

        Raises:
            tuf.api.serialization.SerializationError:
                The metadata object cannot be serialized.
        """

        if serializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import JSONSerializer

            serializer = JSONSerializer(compact=True)

        return serializer.serialize(self)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""

        signatures = [sig.to_dict() for sig in self.signatures.values()]

        return {"signatures": signatures, "signed": self.signed.to_dict()}

    def to_file(
        self,
        filename: str,
        serializer: Optional[MetadataSerializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> None:
        """Writes TUF metadata to file storage.

        Arguments:
            filename: The path to write the file to.
            serializer: A MetadataSerializer instance that implements the
                desired serialization format. Default is JSONSerializer.
            storage_backend: A StorageBackendInterface implementation. Default
                is FilesystemBackend (i.e. a local file).

        Raises:
            tuf.api.serialization.SerializationError:
                The metadata object cannot be serialized.
            securesystemslib.exceptions.StorageError:
                The file cannot be written.
        """

        bytes_data = self.to_bytes(serializer)

        with tempfile.TemporaryFile() as temp_file:
            temp_file.write(bytes_data)
            persist_temp_file(temp_file, filename, storage_backend)

    # Signatures.
    def sign(
        self,
        signer: Signer,
        append: bool = False,
        signed_serializer: Optional[SignedSerializer] = None,
    ) -> Signature:
        """Creates signature over 'signed' and assigns it to 'signatures'.

        Arguments:
            signer: A securesystemslib.signer.Signer implementation.
            append: A boolean indicating if the signature should be appended to
                the list of signatures or replace any existing signatures. The
                default behavior is to replace signatures.
            signed_serializer: A SignedSerializer that implements the desired
                serialization format. Default is CanonicalJSONSerializer.

        Raises:
            tuf.api.serialization.SerializationError:
                'signed' cannot be serialized.
            securesystemslib.exceptions.CryptoError, \
                    securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            Securesystemslib Signature object that was added into signatures.
        """

        if signed_serializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import CanonicalJSONSerializer

            signed_serializer = CanonicalJSONSerializer()

        signature = signer.sign(signed_serializer.serialize(self.signed))

        if not append:
            self.signatures.clear()

        self.signatures[signature.keyid] = signature

        return signature

    def verify_delegate(
        self,
        delegated_role: str,
        delegated_metadata: "Metadata",
        signed_serializer: Optional[SignedSerializer] = None,
    ) -> None:
        """Verifies that 'delegated_metadata' is signed with the required
        threshold of keys for the delegated role 'delegated_role'.

        Args:
            delegated_role: Name of the delegated role to verify
            delegated_metadata: The Metadata object for the delegated role
            signed_serializer: Optional; serializer used for delegate
                serialization. Default is CanonicalJSONSerializer.

        Raises:
            UnsignedMetadataError: 'delegate' was not signed with required
                threshold of keys for 'role_name'
        """

        # Find the keys and role in delegator metadata
        role = None
        if isinstance(self.signed, Root):
            keys = self.signed.keys
            role = self.signed.roles.get(delegated_role)
        elif isinstance(self.signed, Targets):
            if self.signed.delegations is None:
                raise ValueError(f"No delegation found for {delegated_role}")

            keys = self.signed.delegations.keys
            roles = self.signed.delegations.roles
            # Assume role names are unique in delegations.roles: #1426
            # Find first role in roles with matching name (or None if no match)
            role = next((r for r in roles if r.name == delegated_role), None)
        else:
            raise TypeError("Call is valid only on delegator metadata")

        if role is None:
            raise ValueError(f"No delegation found for {delegated_role}")

        # verify that delegated_metadata is signed by threshold of unique keys
        signing_keys = set()
        for keyid in role.keyids:
            key = keys[keyid]
            try:
                key.verify_signature(delegated_metadata, signed_serializer)
                signing_keys.add(key.keyid)
            except exceptions.UnsignedMetadataError:
                logger.info("Key %s failed to verify %s", keyid, delegated_role)

        if len(signing_keys) < role.threshold:
            raise exceptions.UnsignedMetadataError(
                f"{delegated_role} was signed by {len(signing_keys)}/"
                f"{role.threshold} keys",
                delegated_metadata.signed,
            )


class Signed(metaclass=abc.ABCMeta):
    """A base class for the signed part of TUF metadata.

    Objects with base class Signed are usually included in a Metadata object
    on the signed attribute. This class provides attributes and methods that
    are common for all TUF metadata types (roles).

    Attributes:
        _type: The metadata type string. Also available without underscore.
        version: The metadata version number.
        spec_version: The TUF specification version number (semver) the
            metadata format adheres to.
        expires: The metadata expiration datetime object.
        unrecognized_fields: Dictionary of all unrecognized fields.
    """

    # Signed implementations are expected to override this
    _signed_type: ClassVar[str] = "signed"

    # _type and type are identical: 1st replicates file format, 2nd passes lint
    @property
    def _type(self) -> str:
        return self._signed_type

    @property
    def type(self) -> str:
        return self._signed_type

    # NOTE: Signed is a stupid name, because this might not be signed yet, but
    # we keep it to match spec terminology (I often refer to this as "payload",
    # or "inner metadata")
    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        spec_list = spec_version.split(".")
        if (
            len(spec_list) != 3
            or not all(el.isdigit() for el in spec_list)
            or spec_list[0] != SPECIFICATION_VERSION[0]
        ):
            raise ValueError(
                f"Unsupported spec_version, got {spec_list}, "
                f"supported {'.'.join(SPECIFICATION_VERSION)}"
            )
        self.spec_version = spec_version
        self.expires = expires

        if version <= 0:
            raise ValueError(f"version must be > 0, got {version}")
        self.version = version
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @abc.abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Serialization helper that returns dict representation of self"""
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Signed":
        """Deserialization helper, creates object from dict representation"""
        raise NotImplementedError

    @classmethod
    def _common_fields_from_dict(
        cls, signed_dict: Dict[str, Any]
    ) -> Tuple[int, str, datetime]:
        """Returns common fields of 'Signed' instances from the passed dict
        representation, and returns an ordered list to be passed as leading
        positional arguments to a subclass constructor.

        See '{Root, Timestamp, Snapshot, Targets}.from_dict' methods for usage.

        """
        _type = signed_dict.pop("_type")
        if _type != cls._signed_type:
            raise ValueError(f"Expected type {cls._signed_type}, got {_type}")

        version = signed_dict.pop("version")
        spec_version = signed_dict.pop("spec_version")
        expires_str = signed_dict.pop("expires")
        # Convert 'expires' TUF metadata string to a datetime object, which is
        # what the constructor expects and what we store. The inverse operation
        # is implemented in '_common_fields_to_dict'.
        expires = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%SZ")
        return version, spec_version, expires

    def _common_fields_to_dict(self) -> Dict[str, Any]:
        """Returns dict representation of common fields of 'Signed' instances.

        See '{Root, Timestamp, Snapshot, Targets}.to_dict' methods for usage.

        """
        return {
            "_type": self._type,
            "version": self.version,
            "spec_version": self.spec_version,
            "expires": self.expires.isoformat() + "Z",
            **self.unrecognized_fields,
        }

    def is_expired(self, reference_time: Optional[datetime] = None) -> bool:
        """Checks metadata expiration against a reference time.

        Args:
            reference_time: Optional; The time to check expiration date against.
                A naive datetime in UTC expected.
                If not provided, checks against the current UTC date and time.

        Returns:
            True if expiration time is less than the reference time.
        """
        if reference_time is None:
            reference_time = datetime.utcnow()

        return reference_time >= self.expires

    # Modification.
    def bump_expiration(self, delta: timedelta = timedelta(days=1)) -> None:
        """Increments the expires attribute by the passed timedelta."""
        self.expires += delta

    def bump_version(self) -> None:
        """Increments the metadata version number by 1."""
        self.version += 1


class Key:
    """A container class representing the public portion of a Key.

    Please note that "Key" instances are not semanticly validated during
    initialization: this only happens at signature verification time.

    Attributes:
        keyid: An identifier string that must uniquely identify a key within
            the metadata it is used in. This implementation does not verify
            that keyid is the hash of a specific representation of the key.
        keytype: A string denoting a public key signature system,
            such as "rsa", "ed25519", "ecdsa" and "ecdsa-sha2-nistp256".
        scheme: A string denoting a corresponding signature scheme. For example:
            "rsassa-pss-sha256", "ed25519", and "ecdsa-sha2-nistp256".
        keyval: A dictionary containing the public portion of the key.
        unrecognized_fields: Dictionary of all unrecognized fields.
    """

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: Dict[str, str],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not all(
            isinstance(at, str) for at in [keyid, keytype, scheme]
        ) or not isinstance(keyval, Dict):
            raise TypeError("Unexpected Key attributes types!")
        self.keyid = keyid
        self.keytype = keytype
        self.scheme = scheme
        self.keyval = keyval
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "Key":
        """Creates Key object from its dict representation."""
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")
        # All fields left in the key_dict are unrecognized.
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation of self."""
        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

    def to_securesystemslib_key(self) -> Dict[str, Any]:
        """Returns a Securesystemslib compatible representation of self."""
        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
        }

    @classmethod
    def from_securesystemslib_key(cls, key_dict: Dict[str, Any]) -> "Key":
        """
        Creates a Key object from a securesystemlib key dict representation
        removing the private key from keyval.
        """
        key_meta = sslib_keys.format_keyval_to_metadata(
            key_dict["keytype"],
            key_dict["scheme"],
            key_dict["keyval"],
        )
        return cls(
            key_dict["keyid"],
            key_meta["keytype"],
            key_meta["scheme"],
            key_meta["keyval"],
        )

    def verify_signature(
        self,
        metadata: Metadata,
        signed_serializer: Optional[SignedSerializer] = None,
    ) -> None:
        """Verifies that the 'metadata.signatures' contains a signature made
        with this key, correctly signing 'metadata.signed'.

        Arguments:
            metadata: Metadata to verify
            signed_serializer: Optional; SignedSerializer to serialize
                'metadata.signed' with. Default is CanonicalJSONSerializer.

        Raises:
            UnsignedMetadataError: The signature could not be verified for a
                variety of possible reasons: see error message.
        """
        try:
            signature = metadata.signatures[self.keyid]
        except KeyError:
            raise exceptions.UnsignedMetadataError(
                f"no signature for key {self.keyid} found in metadata",
                metadata.signed,
            ) from None

        if signed_serializer is None:
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import CanonicalJSONSerializer

            signed_serializer = CanonicalJSONSerializer()

        try:
            if not sslib_keys.verify_signature(
                self.to_securesystemslib_key(),
                signature.to_dict(),
                signed_serializer.serialize(metadata.signed),
            ):
                raise exceptions.UnsignedMetadataError(
                    f"Failed to verify {self.keyid} signature",
                    metadata.signed,
                )
        except (
            sslib_exceptions.CryptoError,
            sslib_exceptions.FormatError,
            sslib_exceptions.UnsupportedAlgorithmError,
        ) as e:
            raise exceptions.UnsignedMetadataError(
                f"Failed to verify {self.keyid} signature",
                metadata.signed,
            ) from e


class Role:
    """Container that defines which keys are required to sign roles metadata.

    Role defines how many keys are required to successfully sign the roles
    metadata, and which keys are accepted.

    Attributes:
        keyids: A set of strings representing signing keys for this role.
        threshold: Number of keys required to sign this role's metadata.
        unrecognized_fields: Dictionary of all unrecognized fields.
    """

    def __init__(
        self,
        keyids: List[str],
        threshold: int,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        keyids_set = set(keyids)
        if len(keyids_set) != len(keyids):
            raise ValueError(
                f"keyids should be a list of unique strings,"
                f" instead got {keyids}"
            )
        if threshold < 1:
            raise ValueError("threshold should be at least 1!")
        self.keyids = keyids_set
        self.threshold = threshold
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, role_dict: Dict[str, Any]) -> "Role":
        """Creates Role object from its dict representation."""
        keyids = role_dict.pop("keyids")
        threshold = role_dict.pop("threshold")
        # All fields left in the role_dict are unrecognized.
        return cls(keyids, threshold, role_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation of self."""
        return {
            "keyids": sorted(self.keyids),
            "threshold": self.threshold,
            **self.unrecognized_fields,
        }


class Root(Signed):
    """A container for the signed part of root metadata.

    Attributes:
        consistent_snapshot: An optional boolean indicating whether the
            repository supports consistent snapshots.
        keys: Dictionary of keyids to Keys. Defines the keys used in 'roles'.
        roles: Dictionary of role names to Roles. Defines which keys are
            required to sign the metadata for a specific role.
    """

    _signed_type = "root"

    # TODO: determine an appropriate value for max-args
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        keys: Dict[str, Key],
        roles: Dict[str, Role],
        consistent_snapshot: Optional[bool] = None,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.consistent_snapshot = consistent_snapshot
        self.keys = keys
        self.roles = roles

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Root":
        """Creates Root object from its dict representation."""
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
        """Returns the dict representation of self."""
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

    # Update key for a role.
    def add_key(self, role: str, key: Key) -> None:
        """Adds new signing key for delegated role 'role'."""
        self.roles[role].keyids.add(key.keyid)
        self.keys[key.keyid] = key

    def remove_key(self, role: str, keyid: str) -> None:
        """Removes key from 'role' and updates the key store.

        Raises:
            KeyError: If 'role' does not include the key
        """
        self.roles[role].keyids.remove(keyid)
        for keyinfo in self.roles.values():
            if keyid in keyinfo.keyids:
                return

        del self.keys[keyid]


class BaseFile:
    """A base class of MetaFile and TargetFile.

    Encapsulates common static methods for length and hash verification.
    """

    @staticmethod
    def _verify_hashes(
        data: Union[bytes, IO[bytes]], expected_hashes: Dict[str, str]
    ) -> None:
        """Verifies that the hash of 'data' matches 'expected_hashes'"""
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
                raise exceptions.LengthOrHashMismatchError(
                    f"Unsupported algorithm '{algo}'"
                ) from e

            observed_hash = digest_object.hexdigest()
            if observed_hash != exp_hash:
                raise exceptions.LengthOrHashMismatchError(
                    f"Observed hash {observed_hash} does not match"
                    f"expected hash {exp_hash}"
                )

    @staticmethod
    def _verify_length(
        data: Union[bytes, IO[bytes]], expected_length: int
    ) -> None:
        """Verifies that the length of 'data' matches 'expected_length'"""
        if isinstance(data, bytes):
            observed_length = len(data)
        else:
            # if data is not bytes, assume it is a file object
            data.seek(0, io.SEEK_END)
            observed_length = data.tell()

        if observed_length != expected_length:
            raise exceptions.LengthOrHashMismatchError(
                f"Observed length {observed_length} does not match"
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
        if length <= 0:
            raise ValueError(f"Length must be > 0, got {length}")


class MetaFile(BaseFile):
    """A container with information about a particular metadata file.

    Attributes:
        version: An integer indicating the version of the metadata file.
        length: An optional integer indicating the length of the metadata file.
        hashes: An optional dictionary of hash algorithm names to hash values.
        unrecognized_fields: Dictionary of all unrecognized fields.
    """

    def __init__(
        self,
        version: int,
        length: Optional[int] = None,
        hashes: Optional[Dict[str, str]] = None,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:

        if version <= 0:
            raise ValueError(f"Metafile version must be > 0, got {version}")
        if length is not None:
            self._validate_length(length)
        if hashes is not None:
            self._validate_hashes(hashes)

        self.version = version
        self.length = length
        self.hashes = hashes
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, meta_dict: Dict[str, Any]) -> "MetaFile":
        """Creates MetaFile object from its dict representation."""
        version = meta_dict.pop("version")
        length = meta_dict.pop("length", None)
        hashes = meta_dict.pop("hashes", None)

        # All fields left in the meta_dict are unrecognized.
        return cls(version, length, hashes, meta_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation of self."""
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
        """Verifies that the length and hashes of "data" match expected values.

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

    Timestamp contains information about the snapshot Metadata file.

    Attributes:
        meta: A dictionary of filenames to MetaFiles. The only valid key value
            is the snapshot filename, as defined by the specification.
    """

    _signed_type = "timestamp"

    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        meta: Dict[str, MetaFile],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.meta = meta

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Timestamp":
        """Creates Timestamp object from its dict representation."""
        common_args = cls._common_fields_from_dict(signed_dict)
        meta_dict = signed_dict.pop("meta")
        meta = {"snapshot.json": MetaFile.from_dict(meta_dict["snapshot.json"])}
        # All fields left in the timestamp_dict are unrecognized.
        return cls(*common_args, meta, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""
        res_dict = self._common_fields_to_dict()
        res_dict["meta"] = {
            "snapshot.json": self.meta["snapshot.json"].to_dict()
        }
        return res_dict

    # Modification.
    def update(self, snapshot_meta: MetaFile) -> None:
        """Assigns passed info about snapshot metadata to meta dict."""
        self.meta["snapshot.json"] = snapshot_meta


class Snapshot(Signed):
    """A container for the signed part of snapshot metadata.

    Snapshot contains information about all target Metadata files.

    Attributes:
        meta: A dictionary of target metadata filenames to MetaFile objects.
    """

    _signed_type = "snapshot"

    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        meta: Dict[str, MetaFile],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.meta = meta

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Snapshot":
        """Creates Snapshot object from its dict representation."""
        common_args = cls._common_fields_from_dict(signed_dict)
        meta_dicts = signed_dict.pop("meta")
        meta = {}
        for meta_path, meta_dict in meta_dicts.items():
            meta[meta_path] = MetaFile.from_dict(meta_dict)
        # All fields left in the snapshot_dict are unrecognized.
        return cls(*common_args, meta, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""
        snapshot_dict = self._common_fields_to_dict()
        meta_dict = {}
        for meta_path, meta_info in self.meta.items():
            meta_dict[meta_path] = meta_info.to_dict()

        snapshot_dict["meta"] = meta_dict
        return snapshot_dict

    # Modification.
    def update(self, rolename: str, role_info: MetaFile) -> None:
        """Assigns passed (delegated) targets role info to meta dict."""
        metadata_fn = f"{rolename}.json"
        self.meta[metadata_fn] = role_info


class DelegatedRole(Role):
    """A container with information about a delegated role.

    A delegation can happen in two ways:

        - paths is set: delegates targets matching any path pattern in paths
        - path_hash_prefixes is set: delegates targets whose target path hash
          starts with any of the prefixes in path_hash_prefixes

        paths and path_hash_prefixes are mutually exclusive: both cannot be set,
        at least one of them must be set.

    Attributes:
        name: A string giving the name of the delegated role.
        terminating: A boolean indicating whether subsequent delegations
            should be considered during a target lookup.
        paths: An optional list of path pattern strings. See note above.
        path_hash_prefixes: An optional list of hash prefixes. See note above.
        unrecognized_fields: Dictionary of all unrecognized fields.
    """

    def __init__(
        self,
        name: str,
        keyids: List[str],
        threshold: int,
        terminating: bool,
        paths: Optional[List[str]] = None,
        path_hash_prefixes: Optional[List[str]] = None,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(keyids, threshold, unrecognized_fields)
        self.name = name
        self.terminating = terminating
        if paths is not None and path_hash_prefixes is not None:
            raise ValueError("Either paths or path_hash_prefixes can be set")

        if paths is None and path_hash_prefixes is None:
            raise ValueError("One of paths or path_hash_prefixes must be set")

        self.paths = paths
        self.path_hash_prefixes = path_hash_prefixes

    @classmethod
    def from_dict(cls, role_dict: Dict[str, Any]) -> "DelegatedRole":
        """Creates DelegatedRole object from its dict representation."""
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
        """Returns the dict representation of self."""
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
        """Determines whether "targetname" matches the "pathpattern"."""
        # We need to make sure that targetname and pathpattern are pointing to
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
        """Determines whether the given 'target_filepath' is in one of
        the paths that DelegatedRole is trusted to provide.

        The target_filepath and the DelegatedRole paths are expected to be in
        their canonical forms, so e.g. "a/b" instead of "a//b" . Only "/" is
        supported as target path separator. Leading separators are not handled
        as special cases (see `TUF specification on targetpath
        <https://theupdateframework.github.io/specification/latest/#targetpath>`_).
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


class Delegations:
    """A container object storing information about all delegations.

    Attributes:
        keys: Dictionary of keyids to Keys. Defines the keys used in 'roles'.
        roles: List of DelegatedRoles that define which keys are required to
            sign the metadata for a specific role. The roles order also
            defines the order that role delegations are considered in.
        unrecognized_fields: Dictionary of all unrecognized fields.
    """

    def __init__(
        self,
        keys: Dict[str, Key],
        roles: List[DelegatedRole],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.keys = keys
        self.roles = roles
        self.unrecognized_fields = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, delegations_dict: Dict[str, Any]) -> "Delegations":
        """Creates Delegations object from its dict representation."""
        keys = delegations_dict.pop("keys")
        keys_res = {}
        for keyid, key_dict in keys.items():
            keys_res[keyid] = Key.from_dict(keyid, key_dict)
        roles = delegations_dict.pop("roles")
        roles_res = []
        for role_dict in roles:
            new_role = DelegatedRole.from_dict(role_dict)
            roles_res.append(new_role)
        # All fields left in the delegations_dict are unrecognized.
        return cls(keys_res, roles_res, delegations_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""
        keys = {keyid: key.to_dict() for keyid, key in self.keys.items()}
        roles = [role_obj.to_dict() for role_obj in self.roles]
        return {
            "keys": keys,
            "roles": roles,
            **self.unrecognized_fields,
        }


class TargetFile(BaseFile):
    """A container with information about a particular target file.

    Attributes:
        length: An integer indicating the length of the target file.
        hashes: A dictionary of hash algorithm names to hash values.
        path: A string denoting the path to a target file relative to a base
            URL of targets.
        unrecognized_fields: Dictionary of all unrecognized fields.
    """

    def __init__(
        self,
        length: int,
        hashes: Dict[str, str],
        path: str,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:

        self._validate_length(length)
        self._validate_hashes(hashes)

        self.length = length
        self.hashes = hashes
        self.path = path
        self.unrecognized_fields = unrecognized_fields or {}

    @property
    def custom(self) -> Any:
        return self.unrecognized_fields.get("custom", None)

    @classmethod
    def from_dict(cls, target_dict: Dict[str, Any], path: str) -> "TargetFile":
        """Creates TargetFile object from its dict representation."""
        length = target_dict.pop("length")
        hashes = target_dict.pop("hashes")

        # All fields left in the target_dict are unrecognized.
        return cls(length, hashes, path, target_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the JSON-serializable dictionary representation of self."""
        return {
            "length": self.length,
            "hashes": self.hashes,
            **self.unrecognized_fields,
        }

    def verify_length_and_hashes(self, data: Union[bytes, IO[bytes]]) -> None:
        """Verifies that length and hashes of "data" match expected values.

        Args:
            data: File object or its content in bytes.

        Raises:
            LengthOrHashMismatchError: Calculated length or hashes do not
                match expected values or hash algorithm is not supported.
        """
        self._verify_length(data, self.length)
        self._verify_hashes(data, self.hashes)


class Targets(Signed):
    """A container for the signed part of targets metadata.

    Targets contains verifying information about target files and also
    delegates responsibility to other Targets roles.

    Attributes:
        targets: A dictionary of target filenames to TargetFiles
        delegations: An optional Delegations that defines how this Targets
            further delegates responsibility to other Targets Metadata files.
    """

    _signed_type = "targets"

    # TODO: determine an appropriate value for max-args
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        targets: Dict[str, TargetFile],
        delegations: Optional[Delegations] = None,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.targets = targets
        self.delegations = delegations

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Targets":
        """Creates Targets object from its dict representation."""
        common_args = cls._common_fields_from_dict(signed_dict)
        targets = signed_dict.pop("targets")
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
        """Returns the dict representation of self."""
        targets_dict = self._common_fields_to_dict()
        targets = {}
        for target_path, target_file_obj in self.targets.items():
            targets[target_path] = target_file_obj.to_dict()
        targets_dict["targets"] = targets
        if self.delegations is not None:
            targets_dict["delegations"] = self.delegations.to_dict()
        return targets_dict

    # Modification.
    def update(self, fileinfo: TargetFile) -> None:
        """Assigns passed target file info to meta dict."""
        self.targets[fileinfo.path] = fileinfo
