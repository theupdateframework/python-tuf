"""Signer utils for internal use."""

from __future__ import annotations

import hashlib
from typing import Any

from securesystemslib.exceptions import FormatError
from securesystemslib.formats import encode_canonical


def compute_default_keyid(keytype: str, scheme: str, keyval: dict[str, Any]) -> str:
    """Return sha256 hexdigest of the canonical json of the key."""
    data: str | None = encode_canonical(
        {
            "keytype": keytype,
            "scheme": scheme,
            "keyval": keyval,
        }
    )
    if isinstance(data, str):
        byte_data: bytes = data.encode("utf-8")
    else:
        raise FormatError("Failed to encode data into canonical json")

    return hashlib.sha256(byte_data).hexdigest()


def get_mldsa_payload(data: bytes, version: int) -> bytes:
    """Compute and format ML-DSA payload per TAP 21 spec."""
    if version != 1:
        raise ValueError(f"Unsupported ml-dsa key version {version}")

    # Version 1 uses SHA-512
    return b"tuf" + bytes([version]) + hashlib.sha512(data).digest()
