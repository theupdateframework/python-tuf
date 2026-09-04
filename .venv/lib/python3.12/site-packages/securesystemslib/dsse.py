"""Dead Simple Signing Envelope"""

from __future__ import annotations

import logging
from typing import Any

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64dec, b64enc, make_hashable
from securesystemslib.signer import Key, Signature, Signer

logger = logging.getLogger(__name__)


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: dict of Signature key id and Signatures.

    """

    def __init__(
        self,
        payload: bytes,
        payload_type: str,
        signatures: dict[str, Signature],
    ):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.payload,
                self.payload_type,
                make_hashable(self.signatures),
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> Envelope:
        """Creates a DSSE Envelope from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = {}
        for signature in data["signatures"]:
            signature["sig"] = b64dec(signature["sig"]).hex()
            sig = Signature.from_dict(signature)
            if sig.keyid in signatures:
                raise ValueError(f"Multiple signatures found for keyid {sig.keyid}")
            signatures[sig.keyid] = sig
        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        signatures = []
        for signature in self.signatures.values():
            sig_dict = signature.to_dict()
            sig_dict["sig"] = b64enc(bytes.fromhex(sig_dict["sig"]))
            signatures.append(sig_dict)

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": signatures,
        }

    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        return b"DSSEv1 %d %b %d %b" % (
            len(self.payload_type),
            self.payload_type.encode("utf-8"),
            len(self.payload),
            self.payload,
        )

    def sign(self, signer: Signer) -> Signature:
        """Sign the payload and create the signature.

        Arguments:
            signer: A "Signer" class instance.

        Returns:
            A "Signature" instance.
        """

        signature = signer.sign(self.pae())
        self.signatures[signature.keyid] = signature

        return signature

    def verify(self, keys: list[Key], threshold: int) -> dict[str, Key]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of public keys to verify the signatures.
            threshold: Number of signatures needed to pass the verification.

        Raises:
            ValueError: If "threshold" is not valid.
            VerificationError: If the enclosed signatures do not pass the
                verification.

        Note:
            Mandating keyid in signatures and matching them with keyid of Key
            in order to consider them for verification, is not DSSE spec
            compliant (Issue #416).

        Returns:
            A dict of the threshold of unique public keys that verified a
            signature.
        """

        accepted_keys = {}
        pae = self.pae()

        # checks for threshold value.
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if len(keys) < threshold:
            raise ValueError("Number of keys can't be less than threshold")

        for signature in self.signatures.values():
            for key in keys:
                # If Signature keyid doesn't match with Key, skip.
                if not key.keyid == signature.keyid:
                    continue

                # If a key verifies the signature, we exit and use the result.
                try:
                    key.verify_signature(signature, pae)
                    accepted_keys[key.keyid] = key
                    break
                except exceptions.UnverifiedSignatureError:
                    continue

            # Break, if amount of accepted_keys are more than threshold.
            if len(accepted_keys) >= threshold:
                break

        if threshold > len(accepted_keys):
            raise exceptions.VerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(accepted_keys)}, Expected {threshold}"
            )

        return accepted_keys
