"""Low-level TUF Envelope API.

"""
import json
from typing import Generic, Type, cast

from securesystemslib.dsse import Envelope as BaseEnvelope

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


class Envelope(Generic[T], BaseEnvelope):
    """TODO: doc"""

    _DEFAULT_PAYLOAD_TYPE = "application/vnd.tuf+json"

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope[T]":
        """TODO: doc"""
        try:
            envelope_dict = json.loads(data.decode())
            envelope = Envelope.from_dict(envelope_dict)

        except Exception as e:
            raise SerializationError from e

        return envelope

    def to_bytes(self) -> bytes:
        """TODO: doc"""
        try:
            envelope_dict = self.to_dict()
            json_bytes = json.dumps(envelope_dict).encode()

        except Exception as e:
            raise SerializationError from e

        return json_bytes

    @classmethod
    def from_signed(cls, signed: T) -> "Envelope[T]":
        """TODO: doc"""
        try:
            signed_dict = signed.to_dict()
            json_bytes = json.dumps(signed_dict).encode()

        except Exception as e:
            raise SerializationError from e

        return cls(json_bytes, cls._DEFAULT_PAYLOAD_TYPE, [])

    def get_signed(self) -> T:
        """TODO: doc"""
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
                raise ValueError(f'unrecognized metadata type "{_type}"')

        except Exception as e:
            raise DeserializationError from e

        return cast(T, inner_cls.from_dict(payload_dict))
