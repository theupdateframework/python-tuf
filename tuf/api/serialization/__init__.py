# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF role metadata de/serialization.

This sub-package provides abstract base classes and concrete implementations to
serialize and deserialize TUF role metadata and metadata parts.

Any custom de/serialization implementations should inherit from the abstract
base classes defined in this __init__.py module.

- Metadata de/serializers are used to convert to and from wireline formats.
- Signed serializers are used to canonicalize data for cryptographic signatures
  generation and verification.

"""
import abc


# TODO: Should these be in tuf.exceptions or inherit from tuf.exceptions.Error?
class SerializationError(Exception):
    """Error during serialization. """


class DeserializationError(Exception):
    """Error during deserialization. """


class MetadataDeserializer():
    """Abstract base class for deserialization of Metadata objects. """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def deserialize(self, raw_data: bytes) -> "Metadata":
        """Deserialize passed bytes to Metadata object. """
        raise NotImplementedError


class MetadataSerializer():
    """Abstract base class for serialization of Metadata objects. """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def serialize(self, metadata_obj: "Metadata") -> bytes:
        """Serialize passed Metadata object to bytes. """
        raise NotImplementedError


class SignedSerializer():
    """Abstract base class for serialization of Signed objects. """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def serialize(self, signed_obj: "Signed") -> bytes:
        """Serialize passed Signed object to bytes. """
        raise NotImplementedError
