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
import tempfile
from datetime import datetime, timedelta
from typing import Any, ClassVar, Dict, List, Mapping, Optional, Tuple, Type

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

# Disable the "C0302: Too many lines in module" warning which warns for modules
# with more 1000 lines, because all of the code here is logically connected
# and currently, we are above 1000 lines by a small margin.
# pylint: disable=C0302


class Metadata:
    """A container for signed TUF metadata.

    Provides methods to convert to and from dictionary, read and write to and
    from file and to create and verify metadata signatures.

    Attributes:
        signed: A subclass of Signed, which has the actual metadata payload,
            i.e. one of Targets, Snapshot, Timestamp or Root.

        signatures: A list of Securesystemslib Signature objects, each signing
            the canonical serialized representation of 'signed'.

    """

    def __init__(self, signed: "Signed", signatures: List[Signature]) -> None:
        self.signed = signed
        self.signatures = signatures

    @classmethod
    def from_dict(cls, metadata: Dict[str, Any]) -> "Metadata":
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

        signatures = []
        for signature in metadata.pop("signatures"):
            signature_obj = Signature.from_dict(signature)
            signatures.append(signature_obj)

        return cls(
            signed=inner_cls.from_dict(metadata.pop("signed")),
            signatures=signatures,
        )

    @classmethod
    def from_file(
        cls,
        filename: str,
        deserializer: Optional[MetadataDeserializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> "Metadata":
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

    @staticmethod
    def from_bytes(
        data: bytes,
        deserializer: Optional[MetadataDeserializer] = None,
    ) -> "Metadata":
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

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""

        signatures = []
        for sig in self.signatures:
            signatures.append(sig.to_dict())

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
            serializer: A MetadataSerializer subclass instance that implements
                the desired wireline format serialization. Per default a
                JSONSerializer is used.
            storage_backend: An object that implements
                securesystemslib.storage.StorageBackendInterface. Per default
                a (local) FilesystemBackend is used.

        Raises:
            tuf.api.serialization.SerializationError:
                The metadata object cannot be serialized.
            securesystemslib.exceptions.StorageError:
                The file cannot be written.

        """
        if serializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import JSONSerializer

            serializer = JSONSerializer(compact=True)

        with tempfile.TemporaryFile() as temp_file:
            temp_file.write(serializer.serialize(self))
            persist_temp_file(temp_file, filename, storage_backend)

    # Signatures.
    def sign(
        self,
        signer: Signer,
        append: bool = False,
        signed_serializer: Optional[SignedSerializer] = None,
    ) -> Dict[str, Any]:
        """Creates signature over 'signed' and assigns it to 'signatures'.

        Arguments:
            signer: An object implementing the securesystemslib.signer.Signer
                interface.
            append: A boolean indicating if the signature should be appended to
                the list of signatures or replace any existing signatures. The
                default behavior is to replace signatures.
            signed_serializer: A SignedSerializer subclass instance that
                implements the desired canonicalization format. Per default a
                CanonicalJSONSerializer is used.

        Raises:
            tuf.api.serialization.SerializationError:
                'signed' cannot be serialized.
            securesystemslib.exceptions.CryptoError, \
                    securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            A securesystemslib-style signature object.

        """
        if signed_serializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import CanonicalJSONSerializer

            signed_serializer = CanonicalJSONSerializer()

        signature = signer.sign(signed_serializer.serialize(self.signed))

        if append:
            self.signatures.append(signature)
        else:
            self.signatures = [signature]

        return signature


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
    def _type(self):
        return self._signed_type

    @property
    def type(self):
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
        self.spec_version = spec_version
        self.expires = expires

        # TODO: Should we separate data validation from constructor?
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

    def is_expired(self, reference_time: datetime = None) -> bool:
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

    Attributes:
        keyid: An identifier string that must uniquely identify a key within
            the metadata it is used in. This implementation does not verify
            that keyid is the hash of a specific representation of the key.
        keytype: A string denoting a public key signature system,
            such as "rsa", "ed25519", and "ecdsa-sha2-nistp256".
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
        public_val = keyval.get("public")
        if not public_val or not isinstance(public_val, str):
            raise ValueError("keyval doesn't follow the specification format!")
        if not isinstance(scheme, str):
            raise ValueError("scheme should be a string!")
        if not isinstance(keytype, str):
            raise ValueError("keytype should be a string!")
        if not isinstance(keyid, str):
            raise ValueError("keyid should be a string!")
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

    def verify_signature(
        self,
        metadata: Metadata,
        signed_serializer: Optional[SignedSerializer] = None,
    ):
        """Verifies that the 'metadata.signatures' contains a signature made
        with this key, correctly signing 'metadata.signed'.

        Arguments:
            metadata: Metadata to verify
            signed_serializer: Optional; SignedSerializer to serialize
                'metadata.signed' with. Default is CanonicalJSONSerializer.

        Raises:
            UnsignedMetadataError: The signature could not be verified for a
                variety of possible reasons: see error message.
            TODO: Various other errors currently bleed through from lower
                level components: Issue #1351
        """
        try:
            sigs = metadata.signatures
            signature = next(sig for sig in sigs if sig.keyid == self.keyid)
        except StopIteration:
            raise exceptions.UnsignedMetadataError(
                f"no signature for key {self.keyid} found in metadata",
                metadata.signed,
            ) from None

        if signed_serializer is None:
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import CanonicalJSONSerializer

            signed_serializer = CanonicalJSONSerializer()

        if not sslib_keys.verify_signature(
            self.to_securesystemslib_key(),
            signature.to_dict(),
            signed_serializer.serialize(metadata.signed),
        ):
            raise exceptions.UnsignedMetadataError(
                f"Failed to verify {self.keyid} signature for metadata",
                metadata.signed,
            )


class Role:
    """A container class containing the set of keyids and threshold associated
    with a particular role.

    Attributes:
        keyids: A set of strings each of which represents a given key.
        threshold: An integer representing the required number of keys for that
            particular role.
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
            "keyids": list(self.keyids),
            "threshold": self.threshold,
            **self.unrecognized_fields,
        }


class Root(Signed):
    """A container for the signed part of root metadata.

    Attributes:
        consistent_snapshot: An optional boolean indicating whether the
            repository supports consistent snapshots.
        keys: A dictionary that contains a public key store used to verify
            top level roles metadata signatures::

                {
                    '<KEYID>': <Key instance>,
                    ...
                },

        roles: A dictionary that contains a list of signing keyids and
            a signature threshold for each top level role::

                {
                    '<ROLE>': <Role istance>,
                    ...
                }

    """

    _signed_type = "root"

    # TODO: determine an appropriate value for max-args and fix places where
    # we violate that. This __init__ function takes 7 arguments, whereas the
    # default max-args value for pylint is 5
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


class MetaFile:
    """A container with information about a particular metadata file.

    Attributes:
        version: An integer indicating the version of the metadata file.
        length: An optional integer indicating the length of the metadata file.
        hashes: An optional dictionary mapping hash algorithms to the
            hashes resulting from applying them over the metadata file
            contents.::

                'hashes': {
                    '<HASH ALGO 1>': '<METADATA FILE HASH 1>',
                    '<HASH ALGO 2>': '<METADATA FILE HASH 2>',
                    ...
                }

        unrecognized_fields: Dictionary of all unrecognized fields.

    """

    def __init__(
        self,
        version: int,
        length: Optional[int] = None,
        hashes: Optional[Dict[str, str]] = None,
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
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


class Timestamp(Signed):
    """A container for the signed part of timestamp metadata.

    Attributes:
        meta: A dictionary that contains information about snapshot metadata::

            {
                'snapshot.json': <MetaFile INSTANCE>
            }

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

    Attributes:
        meta: A dictionary that contains information about targets metadata::

            {
                'targets.json': <MetaFile INSTANCE>,
                '<DELEGATED TARGETS ROLE 1>.json': <MetaFile INSTANCE>,
                '<DELEGATED TARGETS ROLE 2>.json': <MetaFile INSTANCE>,
            }

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
    """A container with information about particular delegated role.

    Attributes:
        name: A string giving the name of the delegated role.
        keyids: A set of strings each of which represents a given key.
        threshold: An integer representing the required number of keys for that
            particular role.
        terminating: A boolean indicating whether subsequent delegations
            should be considered.
        paths: An optional list of strings, where each string describes
            a path that the role is trusted to provide.
        path_hash_prefixes: An optional list of HEX_DIGESTs used to succinctly
            describe a set of target paths. Only one of the attributes "paths"
            and "path_hash_prefixes" is allowed to be set.
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
            raise ValueError(
                "Only one of the attributes 'paths' and"
                "'path_hash_prefixes' can be set!"
            )
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


class Delegations:
    """A container object storing information about all delegations.

    Attributes:
        keys: A dictionary of keyids and key objects containing information
            about the corresponding key.
        roles: A list of DelegatedRole instances containing information about
            all delegated roles.
        unrecognized_fields: Dictionary of all unrecognized fields.

    """

    def __init__(
        self,
        keys: Mapping[str, Key],
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


class TargetFile:
    """A container with information about a particular target file.

    Attributes:
        length: An integer indicating the length of the target file.
        hashes: A dictionary mapping hash algorithms to the
            hashes resulting from applying them over the metadata file
            contents::

              'hashes': {
                    '<HASH ALGO 1>': '<TARGET FILE HASH 1>',
                    '<HASH ALGO 2>': '<TARGET FILE HASH 2>',
                    ...
                }
        unrecognized_fields: Dictionary of all unrecognized fields.

    """

    @property
    def custom(self):
        if self.unrecognized_fields is None:
            return None
        return self.unrecognized_fields.get("custom", None)

    def __init__(
        self,
        length: int,
        hashes: Dict[str, str],
        unrecognized_fields: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.length = length
        self.hashes = hashes
        self.unrecognized_fields = unrecognized_fields or {}

    @classmethod
    def from_dict(cls, target_dict: Dict[str, Any]) -> "TargetFile":
        """Creates TargetFile object from its dict representation."""
        length = target_dict.pop("length")
        hashes = target_dict.pop("hashes")
        # All fields left in the target_dict are unrecognized.
        return cls(length, hashes, target_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the JSON-serializable dictionary representation of self."""
        return {
            "length": self.length,
            "hashes": self.hashes,
            **self.unrecognized_fields,
        }


class Targets(Signed):
    """A container for the signed part of targets metadata.

    Attributes:
        targets: A dictionary that contains information about target files::

            {
                '<TARGET FILE NAME>': <TargetFile INSTANCE>,
                ...
            }

        delegations: An optional object containing a list of delegated target
            roles and public key store used to verify their metadata
            signatures.

    """

    _signed_type = "targets"

    # TODO: determine an appropriate value for max-args and fix places where
    # we violate that. This __init__ function takes 7 arguments, whereas the
    # default max-args value for pylint is 5
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
            res_targets[target_path] = TargetFile.from_dict(target_info)
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
    def update(self, filename: str, fileinfo: TargetFile) -> None:
        """Assigns passed target file info to meta dict."""
        self.targets[filename] = fileinfo
