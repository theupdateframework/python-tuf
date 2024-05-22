# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""The low-level Metadata API.

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
four top level signed classes (``Root``, ``Timestamp``, ``Snapshot`` and
``Targets``). To make Python type annotations useful ``Metadata`` can be
type constrained: e.g. the signed attribute of ``Metadata[Root]``
is known to be ``Root``.

Currently Metadata API supports JSON as the file format.

A basic example of repository implementation using the Metadata is available in
`examples/repository <https://github.com/theupdateframework/python-tuf/tree/develop/examples/repository>`_.
"""

import logging
import tempfile
from typing import Any, Dict, Generic, Optional, Type, cast

from securesystemslib.signer import Signature, Signer
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface

# Expose payload classes via ``tuf.api.metadata`` to maintain the API,
# even if they are unused in the local scope.
from tuf.api._payload import (  # noqa: F401
    _ROOT,
    _SNAPSHOT,
    _TARGETS,
    _TIMESTAMP,
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    BaseFile,
    DelegatedRole,
    Delegations,
    Key,
    LengthOrHashMismatchError,
    MetaFile,
    Role,
    Root,
    RootVerificationResult,
    Signed,
    Snapshot,
    SuccinctRoles,
    T,
    TargetFile,
    Targets,
    Timestamp,
    VerificationResult,
)
from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.serialization import (
    MetadataDeserializer,
    MetadataSerializer,
    SignedSerializer,
)

logger = logging.getLogger(__name__)


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
    ``[Root]`` is not validated at runtime (as pure annotations are not
    available then).

    New Metadata instances can be created from scratch with::

        one_day = datetime.now(timezone.utc) + timedelta(days=1)
        timestamp = Metadata(Timestamp(expires=one_day))

    Apart from ``expires`` all of the arguments to the inner constructors have
    reasonable default values for new metadata.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        signed: Actual metadata payload, i.e. one of ``Targets``,
            ``Snapshot``, ``Timestamp`` or ``Root``.
        signatures: Ordered dictionary of keyids to ``Signature`` objects, each
            signing the canonical serialized representation of ``signed``.
            Default is an empty dictionary.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by TUF Metadata API. These fields are NOT signed and it's preferable
            if unrecognized fields are added to the Signed derivative classes.
    """

    def __init__(
        self,
        signed: T,
        signatures: Optional[Dict[str, Signature]] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        self.signed: T = signed
        self.signatures = signatures if signatures is not None else {}
        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Metadata):
            return False

        return (
            self.signatures == other.signatures
            # Order of the signatures matters (see issue #1788).
            and list(self.signatures.items()) == list(other.signatures.items())
            and self.signed == other.signed
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @property
    def signed_bytes(self) -> bytes:
        """Default canonical json byte representation of ``self.signed``."""

        # Use local scope import to avoid circular import errors
        from tuf.api.serialization.json import CanonicalJSONSerializer

        return CanonicalJSONSerializer().serialize(self.signed)

    @classmethod
    def from_dict(cls, metadata: Dict[str, Any]) -> "Metadata[T]":
        """Create ``Metadata`` object from its json/dict representation.

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
        """Load TUF metadata from file storage.

        Args:
            filename: Path to read the file from.
            deserializer: ``MetadataDeserializer`` subclass instance that
                implements the desired wireline format deserialization. Per
                default a ``JSONDeserializer`` is used.
            storage_backend: Object that implements
                ``securesystemslib.storage.StorageBackendInterface``.
                Default is ``FilesystemBackend`` (i.e. a local file).

        Raises:
            StorageError: The file cannot be read.
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
        """Load TUF metadata from raw data.

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
            from tuf.api.serialization.json import JSONSerializer

            serializer = JSONSerializer(compact=True)

        return serializer.serialize(self)

    def to_dict(self) -> Dict[str, Any]:
        """Return the dict representation of self."""

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
        """Write TUF metadata to file storage.

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
            StorageError: The file cannot be written.
        """

        if storage_backend is None:
            storage_backend = FilesystemBackend()

        bytes_data = self.to_bytes(serializer)

        with tempfile.TemporaryFile() as temp_file:
            temp_file.write(bytes_data)
            storage_backend.put(temp_file, filename)

    # Signatures.
    def sign(
        self,
        signer: Signer,
        append: bool = False,
        signed_serializer: Optional[SignedSerializer] = None,
    ) -> Signature:
        """Create signature over ``signed`` and assigns it to ``signatures``.

        Args:
            signer: A ``securesystemslib.signer.Signer`` object that provides a
                signing implementation to generate the signature.
            append: ``True`` if the signature should be appended to
                the list of signatures or replace any existing signatures. The
                default behavior is to replace signatures.
            signed_serializer: ``SignedSerializer`` that implements the desired
                serialization format. Default is ``CanonicalJSONSerializer``.

        Raises:
            tuf.api.serialization.SerializationError:
                ``signed`` cannot be serialized.
            UnsignedMetadataError: Signing errors.

        Returns:
            ``securesystemslib.signer.Signature`` object that was added into
            signatures.
        """

        if signed_serializer is None:
            bytes_data = self.signed_bytes
        else:
            bytes_data = signed_serializer.serialize(self.signed)

        try:
            signature = signer.sign(bytes_data)
        except Exception as e:
            raise UnsignedMetadataError(f"Failed to sign: {e}") from e

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
        """Verify that ``delegated_metadata`` is signed with the required
        threshold of keys for ``delegated_role``.

        .. deprecated:: 3.1.0
           Please use ``Root.verify_delegate()`` or
           ``Targets.verify_delegate()``.
        """

        if self.signed.type not in ["root", "targets"]:
            raise TypeError("Call is valid only on delegator metadata")

        if signed_serializer is None:
            payload = delegated_metadata.signed_bytes

        else:
            payload = signed_serializer.serialize(delegated_metadata.signed)

        self.signed.verify_delegate(
            delegated_role, payload, delegated_metadata.signatures
        )
