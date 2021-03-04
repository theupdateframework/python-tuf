"""TUF role metadata JSON serialization and deserialization.

This module provides concrete implementations to serialize and deserialize TUF
role metadata to and from the JSON wireline format for transportation, and
to serialize the 'signed' part of TUF role metadata to the OLPC Canonical JSON
format for signature generation and verification.

"""
import json

from securesystemslib.formats import encode_canonical

# pylint: disable=cyclic-import
# ... to allow de/serializing the correct metadata class here, while also
# creating default de/serializers there (see metadata function scope imports).
from tuf.api.metadata import Metadata, Signed
from tuf.api.serialization import (MetadataSerializer,
                                   MetadataDeserializer,
                                   SignedSerializer)


class JSONDeserializer(MetadataDeserializer):
    """Provides JSON-to-Metadata deserialize method. """

    def deserialize(self, raw_data: bytes) -> Metadata:
        """Deserialize utf-8 encoded JSON bytes into Metadata object. """
        _dict = json.loads(raw_data.decode("utf-8"))
        return Metadata.from_dict(_dict)


class JSONSerializer(MetadataSerializer):
    """A Metadata-to-JSON serialize method.

    Attributes:
        compact: A boolean indicating if the JSON bytes generated in
                'serialize' should be compact by excluding whitespace.

    """
    def __init__(self, compact: bool = False) -> None:
        self.compact = compact

    def serialize(self, metadata_obj: Metadata) -> bytes:
        """Serialize Metadata object into utf-8 encoded JSON bytes. """
        indent = (None if self.compact else 1)
        separators=((',', ':') if self.compact else (',', ': '))
        return json.dumps(metadata_obj.to_dict(),
                          indent=indent,
                          separators=separators,
                          sort_keys=True).encode("utf-8")


class CanonicalJSONSerializer(SignedSerializer):
    """A Signed-to-Canonical JSON 'serialize' method. """

    def serialize(self, signed_obj: Signed) -> bytes:
        """Serialize Signed object into utf-8 encoded Canonical JSON bytes. """
        signed_dict = signed_obj.to_dict()
        return encode_canonical(signed_dict).encode("utf-8")
