"""Signature container class"""

from __future__ import annotations

import logging
from typing import Any

from securesystemslib._internal.utils import make_hashable

logger = logging.getLogger(__name__)


class Signature:
    """A container class containing information about a signature.

    Contains a signature and the keyid uniquely identifying the key used
    to generate the signature.

    Provides utility methods to easily create an object from a dictionary
    and return the dictionary representation of the object.

    Args:
        keyid: HEX string used as a unique identifier of the key.
        sig: HEX string representing the signature.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by securesystemslib.

    Attributes:
        keyid: HEX string used as a unique identifier of the key.
        signature: HEX string representing the signature.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by securesystemslib.

    """

    def __init__(
        self,
        keyid: str,
        sig: str,
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        self.keyid = keyid
        self.signature = sig

        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Signature):
            return False

        return (
            self.keyid == other.keyid
            and self.signature == other.signature
            and self.unrecognized_fields == other.unrecognized_fields
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.keyid,
                self.signature,
                make_hashable(self.unrecognized_fields),
            )
        )

    @classmethod
    def from_dict(cls, signature_dict: dict) -> Signature:
        """Creates a Signature object from its JSON/dict representation.

        Arguments:
            signature_dict:
                A dict containing a valid keyid and a signature.
                Note that the fields in it should be named "keyid" and "sig"
                respectively.

        Raises:
            KeyError: If any of the "keyid" and "sig" fields are missing from
                the signature_dict.

        Side Effect:
            Destroys the metadata dict passed by reference.

        Returns:
            A "Signature" instance.
        """

        keyid = signature_dict.pop("keyid")
        sig = signature_dict.pop("sig")
        # All fields left in the signature_dict are unrecognized.
        return cls(keyid, sig, signature_dict)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "keyid": self.keyid,
            "sig": self.signature,
            **self.unrecognized_fields,
        }
