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
import tempfile
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Optional

from securesystemslib.keys import verify_signature
from securesystemslib.signer import Signature, Signer
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface
from securesystemslib.util import persist_temp_file

import tuf.exceptions
import tuf.formats
from tuf.api.serialization import (
    MetadataDeserializer,
    MetadataSerializer,
    SignedSerializer,
)


class Metadata:
    """A container for signed TUF metadata.

    Provides methods to convert to and from dictionary, read and write to and
    from file and to create and verify metadata signatures.

    Attributes:
        signed: A subclass of Signed, which has the actual metadata payload,
            i.e. one of Targets, Snapshot, Timestamp or Root.

        signatures: A list of signatures over the canonical representation of
            the value of the signed attribute::

            [
                {
                    'keyid': '<SIGNING KEY KEYID>',
                    'sig':' '<SIGNATURE HEX REPRESENTATION>'
                },
                ...
            ]

    """

    def __init__(self, signed: "Signed", signatures: list) -> None:
        self.signed = signed
        self.signatures = signatures

    @classmethod
    def from_dict(cls, metadata: Mapping[str, Any]) -> "Metadata":
        """Creates Metadata object from its dict representation.

        Arguments:
            metadata: TUF metadata in dict representation.

        Raises:
            KeyError: The metadata dict format is invalid.
            ValueError: The metadata has an unrecognized signed._type field.

        Side Effect:
            Destroys the metadata Mapping passed by reference.

        Returns:
            A TUF Metadata object.

        """
        # Dispatch to contained metadata class on metadata _type field.
        _type = metadata["signed"]["_type"]

        if _type == "targets":
            inner_cls = Targets
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
        if deserializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import JSONDeserializer

            deserializer = JSONDeserializer()

        if storage_backend is None:
            storage_backend = FilesystemBackend()

        with storage_backend.get(filename) as file_obj:
            raw_data = file_obj.read()

        return deserializer.deserialize(raw_data)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self. """

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

    def verify(
        self,
        key: Mapping[str, Any],
        signed_serializer: Optional[SignedSerializer] = None,
    ) -> bool:
        """Verifies 'signatures' over 'signed' that match the passed key by id.

        Arguments:
            key: A securesystemslib-style public key object.
            signed_serializer: A SignedSerializer subclass instance that
                implements the desired canonicalization format. Per default a
                CanonicalJSONSerializer is used.

        Raises:
            # TODO: Revise exception taxonomy
            tuf.exceptions.Error: None or multiple signatures found for key.
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            tuf.api.serialization.SerializationError:
                'signed' cannot be serialized.
            securesystemslib.exceptions.CryptoError, \
                    securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            A boolean indicating if the signature is valid for the passed key.

        """
        signatures_for_keyid = list(
            filter(lambda sig: sig.keyid == key["keyid"], self.signatures)
        )

        if not signatures_for_keyid:
            raise tuf.exceptions.Error(f'no signature for key {key["keyid"]}.')

        if len(signatures_for_keyid) > 1:
            raise tuf.exceptions.Error(
                f"{len(signatures_for_keyid)} signatures for key "
                f'{key["keyid"]}, not sure which one to verify.'
            )

        if signed_serializer is None:
            # Use local scope import to avoid circular import errors
            # pylint: disable=import-outside-toplevel
            from tuf.api.serialization.json import CanonicalJSONSerializer

            signed_serializer = CanonicalJSONSerializer()

        return verify_signature(
            key,
            signatures_for_keyid[0].to_dict(),
            signed_serializer.serialize(self.signed),
        )


class Signed:
    """A base class for the signed part of TUF metadata.

    Objects with base class Signed are usually included in a Metadata object
    on the signed attribute. This class provides attributes and methods that
    are common for all TUF metadata types (roles).

    Attributes:
        _type: The metadata type string.
        version: The metadata version number.
        spec_version: The TUF specification version number (semver) the
            metadata format adheres to.
        expires: The metadata expiration datetime object.

    """

    # NOTE: Signed is a stupid name, because this might not be signed yet, but
    # we keep it to match spec terminology (I often refer to this as "payload",
    # or "inner metadata")
    def __init__(
        self, _type: str, version: int, spec_version: str, expires: datetime
    ) -> None:

        self._type = _type
        self.version = version
        self.spec_version = spec_version
        self.expires = expires

        # TODO: Should we separate data validation from constructor?
        if version < 0:
            raise ValueError(f"version must be < 0, got {version}")
        self.version = version

    @staticmethod
    def _common_fields_from_dict(signed_dict: Mapping[str, Any]) -> list:
        """Returns common fields of 'Signed' instances from the passed dict
        representation, and returns an ordered list to be passed as leading
        positional arguments to a subclass constructor.

        See '{Root, Timestamp, Snapshot, Targets}.from_dict' methods for usage.

        """
        _type = signed_dict.pop("_type")
        version = signed_dict.pop("version")
        spec_version = signed_dict.pop("spec_version")
        expires_str = signed_dict.pop("expires")
        # Convert 'expires' TUF metadata string to a datetime object, which is
        # what the constructor expects and what we store. The inverse operation
        # is implemented in '_common_fields_to_dict'.
        expires = tuf.formats.expiry_string_to_datetime(expires_str)
        return [_type, version, spec_version, expires]

    def _common_fields_to_dict(self) -> Dict[str, Any]:
        """Returns dict representation of common fields of 'Signed' instances.

        See '{Root, Timestamp, Snapshot, Targets}.to_dict' methods for usage.

        """
        return {
            "_type": self._type,
            "version": self.version,
            "spec_version": self.spec_version,
            "expires": self.expires.isoformat() + "Z",
        }

    # Modification.
    def bump_expiration(self, delta: timedelta = timedelta(days=1)) -> None:
        """Increments the expires attribute by the passed timedelta. """
        self.expires += delta

    def bump_version(self) -> None:
        """Increments the metadata version number by 1."""
        self.version += 1


class Root(Signed):
    """A container for the signed part of root metadata.

    Attributes:
        consistent_snapshot: A boolean indicating whether the repository
            supports consistent snapshots.
        keys: A dictionary that contains a public key store used to verify
            top level roles metadata signatures::
            {
                '<KEYID>': {
                    'keytype': '<KEY TYPE>',
                    'scheme': '<KEY SCHEME>',
                    'keyid_hash_algorithms': [
                        '<HASH ALGO 1>',
                        '<HASH ALGO 2>'
                        ...
                    ],
                    'keyval': {
                        'public': '<PUBLIC KEY HEX REPRESENTATION>'
                    }
                },
                ...
            },
        roles: A dictionary that contains a list of signing keyids and
            a signature threshold for each top level role::
            {
                '<ROLE>': {
                    'keyids': ['<SIGNING KEY KEYID>', ...],
                    'threshold': <SIGNATURE THRESHOLD>,
                },
                ...
            }

    """

    # TODO: determine an appropriate value for max-args and fix places where
    # we violate that. This __init__ function takes 7 arguments, whereas the
    # default max-args value for pylint is 5
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        _type: str,
        version: int,
        spec_version: str,
        expires: datetime,
        consistent_snapshot: bool,
        keys: Mapping[str, Any],
        roles: Mapping[str, Any],
    ) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add classes for keys and roles
        self.consistent_snapshot = consistent_snapshot
        self.keys = keys
        self.roles = roles

    @classmethod
    def from_dict(cls, root_dict: Mapping[str, Any]) -> "Root":
        """Creates Root object from its dict representation. """
        common_args = cls._common_fields_from_dict(root_dict)
        consistent_snapshot = root_dict.pop("consistent_snapshot")
        keys = root_dict.pop("keys")
        roles = root_dict.pop("roles")
        return cls(*common_args, consistent_snapshot, keys, roles)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self. """
        root_dict = self._common_fields_to_dict()
        root_dict.update(
            {
                "consistent_snapshot": self.consistent_snapshot,
                "keys": self.keys,
                "roles": self.roles,
            }
        )
        return root_dict

    # Update key for a role.
    def add_key(
        self, role: str, keyid: str, key_metadata: Mapping[str, Any]
    ) -> None:
        """Adds new key for 'role' and updates the key store. """
        if keyid not in self.roles[role]["keyids"]:
            self.roles[role]["keyids"].append(keyid)
            self.keys[keyid] = key_metadata

    # Remove key for a role.
    def remove_key(self, role: str, keyid: str) -> None:
        """Removes key for 'role' and updates the key store. """
        if keyid in self.roles[role]["keyids"]:
            self.roles[role]["keyids"].remove(keyid)
            for keyinfo in self.roles.values():
                if keyid in keyinfo["keyids"]:
                    return

            del self.keys[keyid]


class Timestamp(Signed):
    """A container for the signed part of timestamp metadata.

    Attributes:
        meta: A dictionary that contains information about snapshot metadata::

            {
                'snapshot.json': {
                    'version': <SNAPSHOT METADATA VERSION NUMBER>,
                    'length': <SNAPSHOT METADATA FILE SIZE>, // optional
                    'hashes': {
                        '<HASH ALGO 1>': '<SNAPSHOT METADATA FILE HASH 1>',
                        '<HASH ALGO 2>': '<SNAPSHOT METADATA FILE HASH 2>',
                        ...
                    }
                }
            }

    """

    def __init__(
        self,
        _type: str,
        version: int,
        spec_version: str,
        expires: datetime,
        meta: Mapping[str, Any],
    ) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add class for meta
        self.meta = meta

    @classmethod
    def from_dict(cls, timestamp_dict: Mapping[str, Any]) -> "Timestamp":
        """Creates Timestamp object from its dict representation. """
        common_args = cls._common_fields_from_dict(timestamp_dict)
        meta = timestamp_dict.pop("meta")
        return cls(*common_args, meta)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self. """
        timestamp_dict = self._common_fields_to_dict()
        timestamp_dict.update({"meta": self.meta})
        return timestamp_dict

    # Modification.
    def update(
        self, version: int, length: int, hashes: Mapping[str, Any]
    ) -> None:
        """Assigns passed info about snapshot metadata to meta dict. """
        self.meta["snapshot.json"] = {
            "version": version,
            "length": length,
            "hashes": hashes,
        }


class Snapshot(Signed):
    """A container for the signed part of snapshot metadata.

    Attributes:
        meta: A dictionary that contains information about targets metadata::

            {
                'targets.json': {
                    'version': <TARGETS METADATA VERSION NUMBER>,
                    'length': <TARGETS METADATA FILE SIZE>, // optional
                    'hashes': {
                        '<HASH ALGO 1>': '<TARGETS METADATA FILE HASH 1>',
                        '<HASH ALGO 2>': '<TARGETS METADATA FILE HASH 2>',
                        ...
                    } // optional
                },
                '<DELEGATED TARGETS ROLE 1>.json': {
                    ...
                },
                '<DELEGATED TARGETS ROLE 2>.json': {
                    ...
                },
                ...
            }

    """

    def __init__(
        self,
        _type: str,
        version: int,
        spec_version: str,
        expires: datetime,
        meta: Mapping[str, Any],
    ) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add class for meta
        self.meta = meta

    @classmethod
    def from_dict(cls, snapshot_dict: Mapping[str, Any]) -> "Snapshot":
        """Creates Snapshot object from its dict representation. """
        common_args = cls._common_fields_from_dict(snapshot_dict)
        meta = snapshot_dict.pop("meta")
        return cls(*common_args, meta)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self. """
        snapshot_dict = self._common_fields_to_dict()
        snapshot_dict.update({"meta": self.meta})
        return snapshot_dict

    # Modification.
    def update(
        self,
        rolename: str,
        version: int,
        length: Optional[int] = None,
        hashes: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Assigns passed (delegated) targets role info to meta dict. """
        metadata_fn = f"{rolename}.json"

        self.meta[metadata_fn] = {"version": version}
        if length is not None:
            self.meta[metadata_fn]["length"] = length

        if hashes is not None:
            self.meta[metadata_fn]["hashes"] = hashes


class Targets(Signed):
    """A container for the signed part of targets metadata.

    Attributes:
        targets: A dictionary that contains information about target files::

            {
                '<TARGET FILE NAME>': {
                    'length': <TARGET FILE SIZE>,
                    'hashes': {
                        '<HASH ALGO 1>': '<TARGET FILE HASH 1>',
                        '<HASH ALGO 2>': '<TARGETS FILE HASH 2>',
                        ...
                    },
                    'custom': <CUSTOM OPAQUE DICT> // optional
                },
                ...
            }

        delegations: A dictionary that contains a list of delegated target
            roles and public key store used to verify their metadata
            signatures::

            {
                'keys' : {
                    '<KEYID>': {
                        'keytype': '<KEY TYPE>',
                        'scheme': '<KEY SCHEME>',
                        'keyid_hash_algorithms': [
                            '<HASH ALGO 1>',
                            '<HASH ALGO 2>'
                            ...
                        ],
                        'keyval': {
                            'public': '<PUBLIC KEY HEX REPRESENTATION>'
                        }
                    },
                    ...
                },
                'roles': [
                    {
                        'name': '<ROLENAME>',
                        'keyids': ['<SIGNING KEY KEYID>', ...],
                        'threshold': <SIGNATURE THRESHOLD>,
                        'terminating': <TERMINATING BOOLEAN>,
                        'path_hash_prefixes': ['<HEX DIGEST>', ... ], // or
                        'paths' : ['PATHPATTERN', ... ],
                    },
                ...
                ]
            }

    """

    # TODO: determine an appropriate value for max-args and fix places where
    # we violate that. This __init__ function takes 7 arguments, whereas the
    # default max-args value for pylint is 5
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        _type: str,
        version: int,
        spec_version: str,
        expires: datetime,
        targets: Mapping[str, Any],
        delegations: Mapping[str, Any],
    ) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add class for meta
        self.targets = targets
        self.delegations = delegations

    @classmethod
    def from_dict(cls, targets_dict: Mapping[str, Any]) -> "Targets":
        """Creates Targets object from its dict representation. """
        common_args = cls._common_fields_from_dict(targets_dict)
        targets = targets_dict.pop("targets")
        delegations = targets_dict.pop("delegations")
        return cls(*common_args, targets, delegations)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self. """
        targets_dict = self._common_fields_to_dict()
        targets_dict.update(
            {
                "targets": self.targets,
                "delegations": self.delegations,
            }
        )
        return targets_dict

    # Modification.
    def update(self, filename: str, fileinfo: Mapping[str, Any]) -> None:
        """Assigns passed target file info to meta dict. """
        self.targets[filename] = fileinfo
