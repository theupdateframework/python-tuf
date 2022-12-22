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
from typing import TYPE_CHECKING, TypeAlias

from securesystemslib.serialization import (
    BaseDeserializer,
    BaseSerializer,
    SerializationMixin,
)

from tuf.api.exceptions import RepositoryError

if TYPE_CHECKING:
    # pylint: disable=cyclic-import
    from tuf.api.metadata import Metadata, Signed

MetadataSerializer: TypeAlias = BaseSerializer
MetadataDeserializer: TypeAlias = BaseDeserializer
SignedSerializer: TypeAlias = BaseSerializer


class SerializationError(RepositoryError):
    """Error during serialization."""


class DeserializationError(RepositoryError):
    """Error during deserialization."""
