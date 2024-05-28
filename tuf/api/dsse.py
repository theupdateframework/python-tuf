"""Low-level TUF DSSE API. (experimental!)"""

import json
from typing import Generic, Type, cast

from securesystemslib.dsse import Envelope as BaseSimpleEnvelope

# Expose all payload classes to use API independently of ``tuf.api.metadata``.
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
from tuf.api.serialization import DeserializationError, SerializationError


class SimpleEnvelope(Generic[T], BaseSimpleEnvelope):
    """Dead Simple Signing Envelope (DSSE) for TUF payloads.

    * Sign with ``self.sign()`` (inherited).
    * Verify with ``verify_delegate`` on a ``Root`` or ``Targets``
      object::

        delegator.verify_delegate(
            role_name,
            envelope.pae(),  # Note, how we don't pass ``envelope.payload``!
            envelope.signatures,
            )

    Attributes:
        payload: Serialized payload bytes.
        payload_type: Payload string identifier.
        signatures: Ordered dictionary of keyids to ``Signature`` objects.

    """

    DEFAULT_PAYLOAD_TYPE = "application/vnd.tuf+json"

    @classmethod
    def from_bytes(cls, data: bytes) -> "SimpleEnvelope[T]":
        """Load envelope from JSON bytes.

        NOTE: Unlike ``tuf.api.metadata.Metadata.from_bytes``, this method
        does not deserialize the contained payload. Use ``self.get_signed`` to
        deserialize the payload into a ``Signed`` object.

        Args:
            data: envelope JSON bytes.

        Raises:
            tuf.api.serialization.DeserializationError:
                data cannot be deserialized.

        Returns:
            TUF ``SimpleEnvelope`` object.
        """
        try:
            envelope_dict = json.loads(data.decode())
            envelope = SimpleEnvelope.from_dict(envelope_dict)

        except Exception as e:
            raise DeserializationError from e

        return envelope

    def to_bytes(self) -> bytes:
        """Return envelope as JSON bytes.

        NOTE: Unlike ``tuf.api.metadata.Metadata.to_bytes``, this method does
        not serialize the payload. Use ``SimpleEnvelope.from_signed`` to
        serialize a ``Signed`` object and wrap it in an SimpleEnvelope.

        Raises:
            tuf.api.serialization.SerializationError:
                self cannot be serialized.
        """
        try:
            envelope_dict = self.to_dict()
            json_bytes = json.dumps(envelope_dict).encode()

        except Exception as e:
            raise SerializationError from e

        return json_bytes

    @classmethod
    def from_signed(cls, signed: T) -> "SimpleEnvelope[T]":
        """Serialize payload as JSON bytes and wrap in envelope.

        Args:
            signed: ``Signed`` object.

        Raises:
            tuf.api.serialization.SerializationError:
                The signed object cannot be serialized.
        """
        try:
            signed_dict = signed.to_dict()
            json_bytes = json.dumps(signed_dict).encode()

        except Exception as e:
            raise SerializationError from e

        return cls(json_bytes, cls.DEFAULT_PAYLOAD_TYPE, {})

    def get_signed(self) -> T:
        """Extract and deserialize payload JSON bytes from envelope.

        Raises:
            tuf.api.serialization.DeserializationError:
                The signed object cannot be deserialized.
        """

        try:
            payload_dict = json.loads(self.payload.decode())

            # TODO: can we move this to tuf.api._payload?
            _type = payload_dict["_type"]
            if _type == _TARGETS:
                inner_cls: Type[Signed] = Targets
            elif _type == _SNAPSHOT:
                inner_cls = Snapshot
            elif _type == _TIMESTAMP:
                inner_cls = Timestamp
            elif _type == _ROOT:
                inner_cls = Root
            else:
                raise ValueError(f'unrecognized role type "{_type}"')

        except Exception as e:
            raise DeserializationError from e

        return cast(T, inner_cls.from_dict(payload_dict))
