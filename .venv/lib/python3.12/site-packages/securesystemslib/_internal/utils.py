"""Internal utilities"""

import base64
import binascii
from typing import Any


def make_hashable(value: Any) -> Any:
    """Return a hashable equivalent of a dict or list, for use in __hash__

    Dicts become frozensets of their items and lists become tuples, both
    recursively. Values that are already hashable are returned as they are, so
    the result compares equal whenever the input does, which is what __hash__
    needs.

    Arguments:
        value: Value to convert

    Returns:
        A hashable equivalent of the value
    """

    if isinstance(value, dict):
        return frozenset((k, make_hashable(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return tuple(make_hashable(v) for v in value)
    return value


def b64enc(data: bytes) -> str:
    """To encode byte sequence into base64 string

    Arguments:
        data: Byte sequence to encode

    Exceptions:
        TypeError: If "data" is not byte sequence

    Returns:
        base64 string
    """

    return base64.standard_b64encode(data).decode("utf-8")


def b64dec(string: str) -> bytes:
    """To decode byte sequence from base64 string

    Arguments:
        string: base64 string to decode

    Raises:
        binascii.Error: If invalid base64-encoded string

    Returns:
        A byte sequence
    """

    data = string.encode("utf-8")
    try:
        return base64.b64decode(data, validate=True)
    except binascii.Error:
        # altchars for urlsafe encoded base64 - instead of + and _ instead of /
        return base64.b64decode(data, altchars=b"-_", validate=True)
