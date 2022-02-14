# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
The low-level Metadata API in ``tuf.api.metadata`` module contains:

* Safe de/serialization of metadata to and from files.
* Access to and modification of signed metadata content.
* Signing metadata and verifying signatures.

Metadata API implements functionality at the metadata file level, it does
not provide TUF repository or client functionality on its own (but can be used
to implement them).

The API design is based on the file format defined in the `TUF specification
<https://theupdateframework.github.io/specification/latest/>`_ and the object
attributes generally follow the JSON format used in the specification.

The above principle means that a ``Metadata`` object represents a single
metadata file, and has a ``signed`` attribute that is an instance of one of the
four top level signed classes (``Root``, ``Timestamp``, ``Snapshot`` and ``Targets``).
To make Python type annotations useful ``Metadata`` can be type constrained: e.g. the
signed attribute of ``Metadata[Root]`` is known to be ``Root``.

Currently Metadata API supports JSON as the file format.

A basic example of repository implementation using the Metadata is available in
`examples/repo_example <https://github.com/theupdateframework/python-tuf/tree/develop/examples/repo_example>`_.
"""
import abc
import fnmatch
import io
import logging
import tempfile
from datetime import datetime
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

from tuf.api import exceptions
from tuf.api.serialization import (
    MetadataDeserializer,
    MetadataSerializer,
    SerializationError,
    SignedSerializer,
)

_ROOT = "root"
_SNAPSHOT = "snapshot"
_TARGETS = "targets"
_TIMESTAMP = "timestamp"

# pylint: disable=too-many-lines

logger = logging.getLogger(__name__)

# We aim to support SPECIFICATION_VERSION and require the input metadata
# files to have the same major version (the first number) as ours.
SPECIFICATION_VERSION = ["1", "0", "28"]
TOP_LEVEL_ROLE_NAMES = {_ROOT, _TIMESTAMP, _SNAPSHOT, _TARGETS}

# T is a Generic type constraint for Metadata.signed
T = TypeVar("T", "Root", "Timestamp", "Snapshot", "Targets")


class Metadata(Generic[T]):
    """A container for signed TUF metadata.

    Provides methods to convert to and from dictionary, read and write to and
    from file and to create and verify metadata signatures.

    ``Metadata[T]`` is a generic container type where T can be any one type of
    [``Root``, ``Timestamp``, ``Snapshot``, ``Targets``]. The purpose of this
    is to allow static type checking of the signed attribute in code using
    Metadata::

        root_md = Metadata[Root].from_file("root.json")
        # root_md type is now Metadata[Root]. This means signed and its
        # attributes like consistent_snapshot are now statically typed and the
        # types can be verified by static type checkers and shown by IDEs
        print(root_md.signed.consistent_snapshot)

    Using a type constraint is not required but not doing so means T is not a
    specific type so static typing cannot happen. Note that the type constraint
    ``[Root]`` is not validated at runtime (as pure annotations are not available
    then).

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        signed: Actual metadata payload, i.e. one of ``Targets``,
            ``Snapshot``, ``Timestamp`` or ``Root``.
        signatures: Ordered dictionary of keyids to ``Signature`` objects, each
            signing the canonical serialized representation of ``signed``.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API. These fields are NOT signed and it's preferable
            if unrecognized fields are added to the Signed derivative classes.
    """

    def __init__(
        self,
        signed: T,
        signatures: Dict[str, Signature],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        self.signed: T = signed
        self.signatures = signatures
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, metadata: Dict[str, Any]) -> "Metadata[T]":
        """Creates ``Metadata`` object from its dict representation.

        Args:
            metadata: TUF metadata in dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.

        Side Effect:
            Destroys the metadata dict passed by reference.

        Returns:
            TUF ``Metadata`` object.
        """

        # Dispatch to contained metadata class on metadata _type field.
        _type = metadata["signed"]["_type"]

        if _type == _TARGETS:
            inner_cls: Type[Signed] = Targets
        elif _type == _SNAPSHOT:
            inner_cls = Snapshot
        elif _type == _TIMESTAMP:
            inner_cls = Timestamp
        elif _type == _ROOT:
            inner_cls = Root
        else:
            raise ValueError(f'unrecognized metadata type "{_type}"')

        # Make sure signatures are unique
        signatures: Dict[str, Signature] = {}
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
            # All fields left in the metadata dict are unrecognized.
            unrecognized_fields=metadata,
        )

    @classmethod
    def from_file(
        cls,
        filename: str,
        deserializer: Optional[MetadataDeserializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> "Metadata[T]":
        """Loads TUF metadata from file storage.

        Args:
            filename: Path to read the file from.
            deserializer: ``MetadataDeserializer`` subclass instance that
                implements the desired wireline format deserialization. Per
                default a ``JSONDeserializer`` is used.
            storage_backend: Object that implements
                ``securesystemslib.storage.StorageBackendInterface``.
                Default is ``FilesystemBackend`` (i.e. a local file).
        Raises:
            exceptions.StorageError: The file cannot be read.
            tuf.api.serialization.DeserializationError:
                The file cannot be deserialized.

        Returns:
            TUF ``Metadata`` object.
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

        Args:
            data: Metadata content.
            deserializer: ``MetadataDeserializer`` implementation to use.
                Default is ``JSONDeserializer``.

        Raises:
            tuf.api.serialization.DeserializationError:
                The file cannot be deserialized.

        Returns:
            TUF ``Metadata`` object.
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

        Note that if bytes are first deserialized into ``Metadata`` and then
        serialized with ``to_bytes()``, the two are not required to be
        identical even though the signatures are guaranteed to stay valid. If
        byte-for-byte equivalence is required (which is the case when content
        hashes are used in other metadata), the original content should be used
        instead of re-serializing.

        Args:
            serializer: ``MetadataSerializer`` instance that implements the
                desired serialization format. Default is ``JSONSerializer``.

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

        return {
            "signatures": signatures,
            "signed": self.signed.to_dict(),
            **self.unrecognized_fields,
        }

    def to_file(
        self,
        filename: str,
        serializer: Optional[MetadataSerializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> None:
        """Writes TUF metadata to file storage.

        Note that if a file is first deserialized into ``Metadata`` and then
        serialized with ``to_file()``, the two files are not required to be
        identical even though the signatures are guaranteed to stay valid. If
        byte-for-byte equivalence is required (which is the case when file
        hashes are used in other metadata), the original file should be used
        instead of re-serializing.

        Args:
            filename: Path to write the file to.
            serializer: ``MetadataSerializer`` instance that implements the
                desired serialization format. Default is ``JSONSerializer``.
            storage_backend: ``StorageBackendInterface`` implementation. Default
                is ``FilesystemBackend`` (i.e. a local file).

        Raises:
            tuf.api.serialization.SerializationError:
                The metadata object cannot be serialized.
            exceptions.StorageError: The file cannot be written.
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
        """Creates signature over ``signed`` and assigns it to ``signatures``.

        Args:
            signer: A securesystemslib.signer.Signer implementation.
            append: ``True`` if the signature should be appended to
                the list of signatures or replace any existing signatures. The
                default behavior is to replace signatures.
            signed_serializer: ``SignedSerializer`` that implements the desired
                serialization format. Default is ``CanonicalJSONSerializer``.

        Raises:
            tuf.api.serialization.SerializationError:
                ``signed`` cannot be serialized.
            exceptions.UnsignedMetadataError: Signing errors.

        Returns:
            ``securesystemslib.signer.Signature`` object that was added into
            signatures.
        """

        if signed_serializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import CanonicalJSONSerializer

            signed_serializer = CanonicalJSONSerializer()

        bytes_data = signed_serializer.serialize(self.signed)

        try:
            signature = signer.sign(bytes_data)
        except Exception as e:
            raise exceptions.UnsignedMetadataError(
                "Problem signing the metadata"
            ) from e

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
        """Verifies that ``delegated_metadata`` is signed with the required
        threshold of keys for the delegated role ``delegated_role``.

        Args:
            delegated_role: Name of the delegated role to verify
            delegated_metadata: ``Metadata`` object for the delegated role
            signed_serializer: Serializer used for delegate
                serialization. Default is ``CanonicalJSONSerializer``.

        Raises:
            UnsignedMetadataError: ``delegated_role`` was not signed with
                required threshold of keys for ``role_name``.
            ValueError: no delegation was found for ``delegated_role``.
            TypeError: called this function on non-delegating metadata class.
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
            role = self.signed.delegations.roles.get(delegated_role)
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
            )


class Signed(metaclass=abc.ABCMeta):
    """A base class for the signed part of TUF metadata.

    Objects with base class Signed are usually included in a ``Metadata`` object
    on the signed attribute. This class provides attributes and methods that
    are common for all TUF metadata types (roles).

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number.
        spec_version: Supported TUF specification version number.
        expires: Metadata expiry date.
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
        """The metadata expiry date::

        # Use 'datetime' module to e.g. expire in seven days from now
        obj.expires = utcnow() + timedelta(days=7)
        """
        return self._expires

    @expires.setter
    def expires(self, value: datetime) -> None:
        self._expires = value.replace(microsecond=0)

    # NOTE: Signed is a stupid name, because this might not be signed yet, but
    # we keep it to match spec terminology (I often refer to this as "payload",
    # or "inner metadata")
    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
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
        """Returns common fields of ``Signed`` instances from the passed dict
        representation, and returns an ordered list to be passed as leading
        positional arguments to a subclass constructor.

        See ``{Root, Timestamp, Snapshot, Targets}.from_dict`` methods for usage.

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
        expires = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%SZ")

        return version, spec_version, expires

    def _common_fields_to_dict(self) -> Dict[str, Any]:
        """Returns dict representation of common fields of ``Signed`` instances.

        See ``{Root, Timestamp, Snapshot, Targets}.to_dict`` methods for usage.

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
            reference_time: Time to check expiration date against. A naive
                datetime in UTC expected. Default is current UTC date and time.

        Returns:
            ``True`` if expiration time is less than the reference time.
        """
        if reference_time is None:
            reference_time = datetime.utcnow()

        return reference_time >= self.expires


class Key:
    """A container class representing the public portion of a Key.

    Supported key content (type, scheme and keyval) is defined in
    `` Securesystemslib``.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        keyid: Key identifier that is unique within the metadata it is used in.
            Keyid is not verified to be the hash of a specific representation
            of the key.
        keytype: Key type, e.g. "rsa", "ed25519" or "ecdsa-sha2-nistp256".
        scheme: Signature scheme. For example:
            "rsassa-pss-sha256", "ed25519", and "ecdsa-sha2-nistp256".
        keyval: Opaque key content
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        TypeError: Invalid type for an argument.
    """

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: Dict[str, str],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        if not all(
            isinstance(at, str) for at in [keyid, keytype, scheme]
        ) or not isinstance(keyval, dict):
            raise TypeError("Unexpected Key attributes types!")
        self.keyid = keyid
        self.keytype = keytype
        self.scheme = scheme
        self.keyval = keyval
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]) -> "Key":
        """Creates ``Key`` object from its dict representation.

        Raises:
            KeyError, TypeError: Invalid arguments.
        """
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
        """Returns a ``Securesystemslib`` compatible representation of self."""
        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
        }

    @classmethod
    def from_securesystemslib_key(cls, key_dict: Dict[str, Any]) -> "Key":
        """Creates a ``Key`` object from a securesystemlib key dict representation
        removing the private key from keyval.

        Args:
            key_dict: Key in securesystemlib dict representation.

        Raises:
            ValueError: ``key_dict`` value is not following the securesystemslib
                format.
        """
        try:
            key_meta = sslib_keys.format_keyval_to_metadata(
                key_dict["keytype"],
                key_dict["scheme"],
                key_dict["keyval"],
            )
        except sslib_exceptions.FormatError as e:
            raise ValueError(
                "key_dict value is not following the securesystemslib format"
            ) from e

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
        """Verifies that the ``metadata.signatures`` contains a signature made
        with this key, correctly signing ``metadata.signed``.

        Args:
            metadata: Metadata to verify
            signed_serializer: ``SignedSerializer`` to serialize
                ``metadata.signed`` with. Default is ``CanonicalJSONSerializer``.

        Raises:
            UnsignedMetadataError: The signature could not be verified for a
                variety of possible reasons: see error message.
        """
        try:
            signature = metadata.signatures[self.keyid]
        except KeyError:
            raise exceptions.UnsignedMetadataError(
                f"No signature for key {self.keyid} found in metadata"
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
                    f"Failed to verify {self.keyid} signature"
                )
        except (
            sslib_exceptions.CryptoError,
            sslib_exceptions.FormatError,
            sslib_exceptions.UnsupportedAlgorithmError,
            SerializationError,
        ) as e:
            raise exceptions.UnsignedMetadataError(
                f"Failed to verify {self.keyid} signature"
            ) from e


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
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        if len(set(keyids)) != len(keyids):
            raise ValueError(f"Nonunique keyids: {keyids}")
        if threshold < 1:
            raise ValueError("threshold should be at least 1!")
        self.keyids = keyids
        self.threshold = threshold
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, role_dict: Dict[str, Any]) -> "Role":
        """Creates ``Role`` object from its dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
        """
        keyids = role_dict.pop("keyids")
        threshold = role_dict.pop("threshold")
        # All fields left in the role_dict are unrecognized.
        return cls(keyids, threshold, role_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation of self."""
        return {
            "keyids": self.keyids,
            "threshold": self.threshold,
            **self.unrecognized_fields,
        }


class Root(Signed):
    """A container for the signed part of root metadata.

    Parameters listed below are also instance attributes.

    Args:
        version: Metadata version number.
        spec_version: Supported TUF specification version number.
        expires: Metadata expiry date.
        keys: Dictionary of keyids to Keys. Defines the keys used in ``roles``.
        roles: Dictionary of role names to Roles. Defines which keys are
            required to sign the metadata for a specific role.
        consistent_snapshot: ``True`` if repository supports consistent snapshots.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError: Invalid arguments.
    """

    type = _ROOT

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        keys: Dict[str, Key],
        roles: Mapping[str, Role],
        consistent_snapshot: Optional[bool] = None,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.consistent_snapshot = consistent_snapshot
        self.keys = keys
        if set(roles) != TOP_LEVEL_ROLE_NAMES:
            raise ValueError("Role names must be the top-level metadata roles")

        self.roles = roles

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Root":
        """Creates ``Root`` object from its dict representation.

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

    def add_key(self, role: str, key: Key) -> None:
        """Adds new signing key for delegated role ``role``.

        Args:
            role: Name of the role, for which ``key`` is added.
            key: Signing key to be added for ``role``.

        Raises:
            ValueError: If ``role`` doesn't exist.
        """
        if role not in self.roles:
            raise ValueError(f"Role {role} doesn't exist")
        if key.keyid not in self.roles[role].keyids:
            self.roles[role].keyids.append(key.keyid)
        self.keys[key.keyid] = key

    def remove_key(self, role: str, keyid: str) -> None:
        """Removes key from ``role`` and updates the key store.

        Args:
            role: Name of the role, for which a signing key is removed.
            keyid: Identifier of the key to be removed for ``role``.

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


class BaseFile:
    """A base class of ``MetaFile`` and ``TargetFile``.

    Encapsulates common static methods for length and hash verification.
    """

    @staticmethod
    def _verify_hashes(
        data: Union[bytes, IO[bytes]], expected_hashes: Dict[str, str]
    ) -> None:
        """Verifies that the hash of ``data`` matches ``expected_hashes``"""
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
                    f"Observed hash {observed_hash} does not match "
                    f"expected hash {exp_hash}"
                )

    @staticmethod
    def _verify_length(
        data: Union[bytes, IO[bytes]], expected_length: int
    ) -> None:
        """Verifies that the length of ``data`` matches ``expected_length``"""
        if isinstance(data, bytes):
            observed_length = len(data)
        else:
            # if data is not bytes, assume it is a file object
            data.seek(0, io.SEEK_END)
            observed_length = data.tell()

        if observed_length != expected_length:
            raise exceptions.LengthOrHashMismatchError(
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
        if length <= 0:
            raise ValueError(f"Length must be > 0, got {length}")


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
        version: int,
        length: Optional[int] = None,
        hashes: Optional[Dict[str, str]] = None,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
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
        self.unrecognized_fields: Mapping[str, Any] = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, meta_dict: Dict[str, Any]) -> "MetaFile":
        """Creates ``MetaFile`` object from its dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
        """
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
        """Verifies that the length and hashes of ``data`` match expected values.

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
    this is not the case with ``Timestamp.snapshot_meta`` which is a ``MetaFile``.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number.
        spec_version: Supported TUF specification version number.
        expires: Metadata expiry date.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API
        snapshot_meta: Meta information for snapshot metadata.

    Raises:
        ValueError: Invalid arguments.
    """

    type = _TIMESTAMP

    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        snapshot_meta: MetaFile,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.snapshot_meta = snapshot_meta

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Timestamp":
        """Creates ``Timestamp`` object from its dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
        """
        common_args = cls._common_fields_from_dict(signed_dict)
        meta_dict = signed_dict.pop("meta")
        snapshot_meta = MetaFile.from_dict(meta_dict["snapshot.json"])
        # All fields left in the timestamp_dict are unrecognized.
        return cls(*common_args, snapshot_meta, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""
        res_dict = self._common_fields_to_dict()
        res_dict["meta"] = {"snapshot.json": self.snapshot_meta.to_dict()}
        return res_dict


class Snapshot(Signed):
    """A container for the signed part of snapshot metadata.

    Snapshot contains information about all target Metadata files.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number.
        spec_version: Supported TUF specification version number.
        expires: Metadata expiry date.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API
        meta: Dictionary of target metadata filenames to ``MetaFile`` objects.

    Raises:
        ValueError: Invalid arguments.
    """

    type = _SNAPSHOT

    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        meta: Dict[str, MetaFile],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        super().__init__(version, spec_version, expires, unrecognized_fields)
        self.meta = meta

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Snapshot":
        """Creates ``Snapshot`` object from its dict representation.

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
        """Returns the dict representation of self."""
        snapshot_dict = self._common_fields_to_dict()
        meta_dict = {}
        for meta_path, meta_info in self.meta.items():
            meta_dict[meta_path] = meta_info.to_dict()

        snapshot_dict["meta"] = meta_dict
        return snapshot_dict


class DelegatedRole(Role):
    """A container with information about a delegated role.

    A delegation can happen in two ways:

        - ``paths`` is set: delegates targets matching any path pattern in ``paths``
        - ``path_hash_prefixes`` is set: delegates targets whose target path hash
          starts with any of the prefixes in ``path_hash_prefixes``

        ``paths`` and ``path_hash_prefixes`` are mutually exclusive: both cannot be
        set, at least one of them must be set.

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
            by TUF Metadata API

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
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        super().__init__(keyids, threshold, unrecognized_fields)
        self.name = name
        self.terminating = terminating
        if paths is not None and path_hash_prefixes is not None:
            raise ValueError("Either paths or path_hash_prefixes can be set")

        if paths is None and path_hash_prefixes is None:
            raise ValueError("One of paths or path_hash_prefixes must be set")

        if paths is not None and any(not isinstance(p, str) for p in paths):
            raise ValueError("Paths must be strings")
        if path_hash_prefixes is not None and any(
            not isinstance(p, str) for p in path_hash_prefixes
        ):
            raise ValueError("Path_hash_prefixes must be strings")

        self.paths = paths
        self.path_hash_prefixes = path_hash_prefixes

    @classmethod
    def from_dict(cls, role_dict: Dict[str, Any]) -> "DelegatedRole":
        """Creates ``DelegatedRole`` object from its dict representation.

        Raises:
            ValueError, KeyError: Invalid arguments.
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
        """Determines whether ``targetpath`` matches the ``pathpattern``."""
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
        """Determines whether the given ``target_filepath`` is in one of
        the paths that ``DelegatedRole`` is trusted to provide.

        The ``target_filepath`` and the ``DelegatedRole`` paths are expected to be
        in their canonical forms, so e.g. "a/b" instead of "a//b" . Only "/" is
        supported as target path separator. Leading separators are not handled
        as special cases (see `TUF specification on targetpath
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
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError: Invalid arguments.
    """

    def __init__(
        self,
        keys: Dict[str, Key],
        roles: Dict[str, DelegatedRole],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):
        self.keys = keys

        for role in roles:
            if not role or role in TOP_LEVEL_ROLE_NAMES:
                raise ValueError(
                    "Delegated roles cannot be empty or use top-level role names"
                )

        self.roles = roles
        self.unrecognized_fields = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, delegations_dict: Dict[str, Any]) -> "Delegations":
        """Creates ``Delegations`` object from its dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
        keys = delegations_dict.pop("keys")
        keys_res = {}
        for keyid, key_dict in keys.items():
            keys_res[keyid] = Key.from_dict(keyid, key_dict)
        roles = delegations_dict.pop("roles")
        roles_res: Dict[str, DelegatedRole] = {}
        for role_dict in roles:
            new_role = DelegatedRole.from_dict(role_dict)
            if new_role.name in roles_res:
                raise ValueError(f"Duplicate role {new_role.name}")
            roles_res[new_role.name] = new_role
        # All fields left in the delegations_dict are unrecognized.
        return cls(keys_res, roles_res, delegations_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""
        keys = {keyid: key.to_dict() for keyid, key in self.keys.items()}
        roles = [role_obj.to_dict() for role_obj in self.roles.values()]
        return {
            "keys": keys,
            "roles": roles,
            **self.unrecognized_fields,
        }


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
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ):

        self._validate_length(length)
        self._validate_hashes(hashes)

        self.length = length
        self.hashes = hashes
        self.path = path
        self.unrecognized_fields = unrecognized_fields or {}

    @property
    def custom(self) -> Any:
        """Can be used to provide implementation specific data related to the
        target. python-tuf does not use or validate this data."""
        return self.unrecognized_fields.get("custom")

    @classmethod
    def from_dict(cls, target_dict: Dict[str, Any], path: str) -> "TargetFile":
        """Creates ``TargetFile`` object from its dict representation.

        Raises:
            ValueError, KeyError, TypeError: Invalid arguments.
        """
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

    @classmethod
    def from_file(
        cls,
        target_file_path: str,
        local_path: str,
        hash_algorithms: Optional[List[str]] = None,
    ) -> "TargetFile":
        """Creates ``TargetFile`` object from a file.

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
        """Creates ``TargetFile`` object from bytes.

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

        return cls(length, hashes, target_file_path)

    def verify_length_and_hashes(self, data: Union[bytes, IO[bytes]]) -> None:
        """Verifies that length and hashes of ``data`` match expected values.

        Args:
            data: Target file object or its content in bytes.

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

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        version: Metadata version number.
        spec_version: Supported TUF specification version number.
        expires: Metadata expiry date.
        targets: Dictionary of target filenames to TargetFiles
        delegations: Defines how this Targets delegates responsibility to other
            Targets Metadata files.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API

    Raises:
        ValueError: Invalid arguments.
    """

    type = _TARGETS

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
        """Creates ``Targets`` object from its dict representation.

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
        """Returns the dict representation of self."""
        targets_dict = self._common_fields_to_dict()
        targets = {}
        for target_path, target_file_obj in self.targets.items():
            targets[target_path] = target_file_obj.to_dict()
        targets_dict[_TARGETS] = targets
        if self.delegations is not None:
            targets_dict["delegations"] = self.delegations.to_dict()
        return targets_dict

    def add_key(self, role: str, key: Key) -> None:
        """Adds new signing key for delegated role ``role``.

        Args:
            role: Name of the role, for which ``key`` is added.
            key: Signing key to be added for ``role``.

        Raises:
            ValueError: If there are no delegated roles or if ``role`` is not
                delegated by this Target.
        """
        if self.delegations is None or role not in self.delegations.roles:
            raise ValueError(f"Delegated role {role} doesn't exist")
        if key.keyid not in self.delegations.roles[role].keyids:
            self.delegations.roles[role].keyids.append(key.keyid)
        self.delegations.keys[key.keyid] = key

    def remove_key(self, role: str, keyid: str) -> None:
        """Removes key from delegated role ``role`` and updates the delegations
        key store.

        Args:
            role: Name of the role, for which a signing key is removed.
            keyid: Identifier of the key to be removed for ``role``.

        Raises:
            ValueError: If there are no delegated roles or if ``role`` is not
                delegated by this ``Target`` or if key is not used by ``role``.
        """
        if self.delegations is None or role not in self.delegations.roles:
            raise ValueError(f"Delegated role {role} doesn't exist")
        if keyid not in self.delegations.roles[role].keyids:
            raise ValueError(f"Key with id {keyid} is not used by {role}")
        self.delegations.roles[role].keyids.remove(keyid)
        for keyinfo in self.delegations.roles.values():
            if keyid in keyinfo.keyids:
                return

        del self.delegations.keys[keyid]
