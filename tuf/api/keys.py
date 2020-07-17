# Imports.

# 2nd-party.

from abc import ABC, abstractmethod
from typing import Any, List, Optional

import logging

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

    def __init__(self, least: int = 1, most: int = 1):
        if least <= 0:
            raise ValueError(f'{least} <= 0')
        if most <= 0:
            raise ValueError(f'{most} <= 0')
        if least > most:
            raise ValueError(f'{least} > {most}')
        self.least = least
        self.most = most

class Key(ABC):

    @abstractmethod
    def __init__(self) -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def keyid(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def sign(self, signed: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def verify(self, signed: str, signature: str) -> bool:
        raise NotImplementedError

Keys = List[Key]

class KeyRing:

    def __init__(self, threshold: Threshold, keys: Keys):
        if len(keys) >= threshold.least:
            logging.warning(f'{len(keys)} >= {threshold.least}')
        if len(keys) <= threshold.most:
            logging.warning(f'{len(keys)} <= {threshold.most}')
        self.threshold = threshold
        self.keys = keys

# Specific types of keys, such as those in RAM, or on HSMs (TODO).

class RAMKey(Key):

    def __init__(self, obj: Any) -> None: # pylint: disable=super-init-not-called
        self.__obj = obj

    @classmethod
    def read_from_file(cls, filename: str,  algorithm: str, passphrase: Optional[str] = None) -> Key:
        handler = Algorithm[algorithm]
        obj = handler(filename, password=passphrase)
        return cls(obj)

    @property
    def keyid(self) -> str:
        return self.__obj['keyid']

    def sign(self, signed: str) -> str:
        return create_signature(self.__obj, signed)

    def verify(self, signed: str, signature: str) -> bool:
        return verify_signature(self.__obj, signature, signed)
