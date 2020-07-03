# Imports.

# 2nd-party.

from abc import ABC, abstractmethod
from typing import Any, List, Optional

import logging
import os

# 3rd-party.
from securesystemslib.interface import (
    import_ecdsa_privatekey_from_file,
    import_ed25519_privatekey_from_file,
    import_rsa_privatekey_from_file,
)
from securesystemslib.keys import (
    create_signature,
    verify_signature,
)

# Generic classes.

Algorithm = {
    'ECDSA': import_ecdsa_privatekey_from_file,
    'ED25519': import_ed25519_privatekey_from_file,
    'RSA': import_rsa_privatekey_from_file
    }

class Threshold:

    def __init__(self, min_: int = 1, max_: int = 1):
        assert min_ > 0, f'{min_} <= 0'
        assert max_ > 0, f'{max_} <= 0'
        assert min_ <= max_, f'{min_} > {max_}'
        self.min = min_
        self.max = max_

class Key(ABC):

    @abstractmethod
    def __init__(self) -> None:
        raise NotImplementedError()

    @property
    @abstractmethod
    def keyid(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def sign(self, signed: str) -> str:
        raise NotImplementedError()

    @abstractmethod
    def verify(self, signed: str, signature: str) -> bool:
        raise NotImplementedError()

Keys = List[Key]

class KeyRing:

    def __init__(self, threshold: Threshold, keys: Keys):
        if len(keys) >= threshold.min:
            logging.warning(f'{len(keys)} >= {threshold.min}')
        if len(keys) <= threshold.max:
            logging.warning(f'{len(keys)} <= {threshold.max}')
        self.threshold = threshold
        self.keys = keys

# Specific types of keys, such as those in RAM, or on HSMs (TODO).

class RAMKey(Key):

    def __init__(self, obj: Any) -> None: # pylint: disable=super-init-not-called
        self.__obj = obj

    def keyid(self) -> str:
        return self.__obj['keyid']

    def sign(self, signed: str) -> str:
        return create_signature(self.__obj, signed)

    def verify(self, signed: str, signature: str) -> bool:
        return verify_signature(self.__obj, signature, signed)


# Utility functions.

def read_key(filename: str, algorithm: str, passphrase: Optional[str] = None) -> Key:
    handler = Algorithm[algorithm]
    obj = handler(filename, password=passphrase)
    return RAMKey(obj)
