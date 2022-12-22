# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""``tuf.api.serialization.json`` module provides concrete implementations to
serialize and deserialize TUF role metadata to and from the JSON wireline
format for transportation, and to serialize the 'signed' part of TUF role
metadata to the OLPC Canonical JSON format for signature generation and
verification.
"""
from typing import Optional, Type

from securesystemslib.formats import encode_canonical
from securesystemslib.serialization import (
    JSONDeserializer as BaseJSONDeserializer,
)
from securesystemslib.serialization import JSONSerializer as BaseJSONSerializer

# pylint: disable=cyclic-import
# ... to allow de/serializing Metadata and Signed objects here, while also
# creating default de/serializers there (see metadata local scope imports).
# NOTE: A less desirable alternative would be to add more abstraction layers.
from tuf.api.metadata import (
    BaseMetadata,
    Envelope,
    Metadata,
    Root,
    Signed,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.api.serialization import (
    DeserializationError,
    SerializationError,
    SignedSerializer,
)


class JSONDeserializer(BaseJSONDeserializer):
    """Provides JSON to ``BaseMetadata`` deserialize method."""

    def deserialize(self, raw_data: bytes) -> BaseMetadata:
        """Deserialize utf-8 encoded JSON bytes into ``BaseMetadata`` instance.

        Creates ``Metadata`` or ``Envelope`` instance based on presence of
        ``payload`` or ``signed`` field."""

        try:
            json_dict = super().deserialize(raw_data)

            if "payload" in json_dict:
                return Envelope.from_dict(json_dict)

            if "signed" in json_dict:
                return Metadata.from_dict(json_dict)

            raise ValueError("unrecognized metadata")

        except Exception as e:
            raise DeserializationError("Failed to deserialize JSON") from e


class JSONSerializer(BaseJSONSerializer):
    """Provides ``BaseMetadata`` to JSON serialize method.

    Args:
        compact: A boolean indicating if the JSON bytes generated in
            'serialize' should be compact by excluding whitespace.
        validate: Check that the metadata object can be deserialized again
            without change of contents and thus find common mistakes.
            This validation might slow down serialization significantly.

    """

    def __init__(self, compact: bool = False, validate: Optional[bool] = False):
        super().__init__(compact)
        self.validate = validate

    def serialize(self, obj: BaseMetadata) -> bytes:
        """Serialize ``BaseMetadata`` object into utf-8 encoded JSON bytes."""

        try:
            json_bytes = BaseJSONSerializer.serialize(self, obj)

            if self.validate:
                try:
                    new_md_obj = JSONDeserializer().deserialize(json_bytes)
                    if obj != new_md_obj:
                        raise ValueError(
                            "Metadata changes if you serialize and deserialize."
                        )
                except Exception as e:
                    raise ValueError("Metadata cannot be validated!") from e

        except Exception as e:
            raise SerializationError("Failed to serialize JSON") from e

        return json_bytes


class SignedJSONDeserializer(BaseJSONDeserializer):
    """Provides JSON to ``Signed`` deserialize method."""

    def deserialize(self, raw_data: bytes) -> Signed:
        """Deserialize utf-8 encoded JSON bytes into ``Signed`` instance.

        Creates ``Targets``, ``Snapshot``, ``Timestamp`` or ``Root`` instance
        based on value in ``_type`` field."""
        try:
            json_dict = super().deserialize(raw_data)

            _type = json_dict["_type"]

            if _type == Targets.type:
                _cls: Type[Signed] = Targets
            elif _type == Snapshot.type:
                _cls = Snapshot
            elif _type == Timestamp.type:
                _cls = Timestamp
            elif _type == Root.type:
                _cls = Root
            else:
                raise ValueError(f'unrecognized metadata type "{_type}"')

        except Exception as e:
            raise SerializationError("Failed to serialize JSON") from e

        return _cls.from_dict(json_dict)


class CanonicalJSONSerializer(SignedSerializer):
    """Provides Signed to OLPC Canonical JSON serialize method."""

    def serialize(self, obj: Signed) -> bytes:
        """Serialize Signed object into utf-8 encoded OLPC Canonical JSON
        bytes.
        """
        try:
            signed_dict = obj.to_dict()
            canonical_bytes = encode_canonical(signed_dict).encode("utf-8")

        except Exception as e:
            raise SerializationError from e

        return canonical_bytes
