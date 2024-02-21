# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""``tuf.api.serialization`` module provides abstract base classes and concrete
implementations to serialize and deserialize TUF metadata.

Any custom de/serialization implementations should inherit from the abstract
base classes defined in this module. The implementations can use the
``to_dict()``/``from_dict()`` implementations available in the Metadata
API objects.

- Metadata de/serializers are used to convert to and from wireline formats.
- Signed serializers are used to canonicalize data for cryptographic signatures
  generation and verification.
"""

import abc
from typing import TYPE_CHECKING

from tuf.api.exceptions import RepositoryError

if TYPE_CHECKING:
    from tuf.api.metadata import Metadata, Signed


class SerializationError(RepositoryError):
    """Error during serialization."""


class DeserializationError(RepositoryError):
    """Error during deserialization."""


class MetadataDeserializer(metaclass=abc.ABCMeta):
    """Abstract base class for deserialization of Metadata objects."""

    @abc.abstractmethod
    def deserialize(self, raw_data: bytes) -> "Metadata":
        """Deserialize bytes to Metadata object."""
        raise NotImplementedError


class MetadataSerializer(metaclass=abc.ABCMeta):
    """Abstract base class for serialization of Metadata objects."""

    @abc.abstractmethod
    def serialize(self, metadata_obj: "Metadata") -> bytes:
        """Serialize Metadata object to bytes."""
        raise NotImplementedError


class SignedSerializer(metaclass=abc.ABCMeta):
    """Abstract base class for serialization of Signed objects."""

    @abc.abstractmethod
    def serialize(self, signed_obj: "Signed") -> bytes:
        """Serialize Signed object to bytes."""
        raise NotImplementedError
