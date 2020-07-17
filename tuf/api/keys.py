# Imports.

# 2nd-party.

from abc import ABC, abstractmethod
from enum import Enum, unique
from typing import Any, List, Optional, Union

import base64
import logging
import sys

# 3rd-party.
from securesystemslib.hash import digest
from securesystemslib.formats import encode_canonical
from securesystemslib.interface import (
    import_ecdsa_privatekey_from_file,
    import_ed25519_privatekey_from_file,
    import_rsa_privatekey_from_file,
)
from securesystemslib.keys import (
    create_signature,
    format_keyval_to_metadata,
    verify_signature,
)

import hvac

# Generic classes.

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

    @property
    @abstractmethod
    def public_key(self) -> str:
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

    # FIXME: Need a way to load *either* private or public keys.
    KEY_TYPES = {
        'ECDSA': import_ecdsa_privatekey_from_file,
        'ED25519': import_ed25519_privatekey_from_file,
        'RSA': import_rsa_privatekey_from_file
    }

    def __init__(self, obj: Any) -> None: # pylint: disable=super-init-not-called
        self.__obj = obj

    @classmethod
    def read_from_file(cls, filename: str, key_type: str, passphrase: Optional[str] = None) -> 'RAMKey':
        handler = cls.KEY_TYPES.get(key_type)
        if not handler:
            return ValueError(key_type)
        obj = handler(filename, password=passphrase)
        return cls(obj)

    @property
    def keyid(self) -> str:
        return self.__obj['keyid']

    @property
    def public_key(self) -> str:
        return self.__obj['keyval']['public']

    def sign(self, signed: str) -> str:
        return create_signature(self.__obj, signed)

    def verify(self, signed: str, signature: str) -> bool:
        return verify_signature(self.__obj, signature, signed)

class VaultKey(Key):

    class AuthenticationError(Exception): pass

    @unique
    class KeyTypes(Enum):
        ED25519 = 'ed25519'
        P_256 = 'ecdsa-p256'
        RSA_2048 = 'rsa-2048'
        RSA_4096 = 'rsa-4096'

    @unique
    class HashAlgorithms(Enum):
        SHA2_224 = 'sha2-224'
        SHA2_256 = 'sha2-256'
        SHA2_384 = 'sha2-384'
        SHA2_512 = 'sha2-512'

    @unique
    class SignatureAlgorithms(Enum):
        PSS = 'pss'
        PKCS1 = 'pkcs1v15'

    @unique
    class MarshalingAlgorithms(Enum):
        ANS1 = 'asn1'
        JWS = 'jws'

    def __init__(
        self,
        url: str,
        token: str,
        name: str,
        hash_algorithm: Optional[str] = None,
        marshaling_algorithm: Optional[str] = None,
        signature_algorithm: Optional[str] = None,
    ) -> None: # pylint: disable=super-init-not-called
        """Reads the key using the Transit Secrets Engine as a side effect."""

        self.__client = hvac.Client(url=url, token=token)
        if not self.__client.is_authenticated():
            raise self.AuthenticationError

        # Guess why this isn't a requests.Response?
        # https://github.com/hvac/hvac/pull/537#issuecomment-660304707
        response = self.__client.secrets.transit.read_key(name=name)
        self.__name = name

        # Get public key.
        data = response['data']

        key_type = data['type']
        if key_type not in {k.value for k in self.KeyTypes}:
            return ValueError(key_type)
        self.__key_type = data['type']

        # NOTE: The documentation is not clear, but presumably the returned
        # keys are different versions of keys under the same name. Therefore,
        # we shall select the one with the latest version number.
        # NOTE: We are also taking it for granted that Vault will generate
        # public keys in formats TUF will recognize out of the box.
        keys = data['keys']
        latest_version = data['latest_version']
        key = keys.get(str(latest_version))
        self.__public_key = key['public_key']

        # A valid hash algorithm is only good for ECDSA or RSA.
        if  hash_algorithm is not None:
            if hash_algorithm not in {h.value for h in self.HashAlgorithms}:
                raise ValueError(hash_algorithm)
            if key_type == self.KeyTypes.ED25519.value:
                raise ValueError(hash_algorithm)
            # P-256 only takes SHA2-256.
            # https://tools.ietf.org/html/rfc5656#section-6.2.1
            if  key_type == self.KeyTypes.P_256.value and hash_algorithm != self.HashAlgorithms.SHA2_256.value:
                raise ValueError(hash_algorithm)
        self.__hash_algorithm = hash_algorithm

        # A valid marshaling algorithm is only good for P-256.
        if  marshaling_algorithm is not None:
            if marshaling_algorithm not in {m.value for m in self.MarshalingAlgorithms}:
                raise ValueError(marshaling_algorithm)
            if key_type != self.KeyTypes.P_256.value:
                raise ValueError(marshaling_algorithm)
        self.__marshaling_algorithm = marshaling_algorithm

        # A signature algorithm is good only for RSA.
        if  signature_algorithm is not None:
            if signature_algorithm not in {s.value for s in self.SignatureAlgorithms}:
                raise ValueError(signature_algorithm)
            if key_type not in {self.KeyTypes.RSA_2048.value, self.KeyTypes.RSA_4096.value}:
                raise ValueError(signature_algorithm)
        self.__signature_algorithm = signature_algorithm

    @classmethod
    def create_key(cls, url: str, token: str, name: str,  key_type: str, **kwargs) -> 'VaultKey':
        if key_type not in {k.value for k in cls.KeyTypes}:
            return ValueError(key_type)

        client = hvac.Client(url=url, token=token)
        if not client.is_authenticated():
            raise cls.AuthenticationError

        response = client.secrets.transit.create_key(name=name, key_type=key_type)
        response.raise_for_status()
        return cls(url, token, name, **kwargs)

    @property
    def public_key(self) -> str:
        if self.__key_type == self.KeyTypes.ED25519.value:
            keytype = self.__key_type
            scheme = keytype
        elif self.__key_type == self.KeyTypes.P_256.value:
            keytype = 'ecdsa-sha2-nistp256'
            scheme = keytype
        elif self.__key_type in {self.KeyTypes.RSA_2048.value, self.KeyTypes.RSA_4096.value}:
            keytype = 'rsa'

            if self.__signature_algorithm == self.SignatureAlgorithms.PSS.value:
                scheme = 'rsassa-pss'
            elif self.__signature_algorithm == self.SignatureAlgorithms.PKCS1.value:
                scheme = 'rsa-pkcs1v15'
            else:
                raise ValueError(self.__key_type)

            _, size = self.__hash_algorithm.split('-')
            scheme += f'-sha{size}'
        else:
            raise ValueError(self.__key_type)

        key_meta = format_keyval_to_metadata(keytype, scheme, self.__public_key, private=False)
        return encode_canonical(key_meta)

    @property
    def keyid(self) -> str:
        digest_object = digest('sha256')
        digest_object.update(self.public_key.encode('utf-8'))
        return digest_object.hexdigest()

    # https://hvac.readthedocs.io/en/stable/usage/secrets_engines/transit.html#create-key
    def __base64ify(self, bytes_or_str: Union[bytes, str]) -> str:
        """Helper method to perform base64 encoding across Python 2.7 and Python 3.X"""

        if sys.version_info[0] >= 3 and isinstance(bytes_or_str, str):
            input_bytes = bytes_or_str.encode('utf8')
        else:
            input_bytes = bytes_or_str

        output_bytes = base64.urlsafe_b64encode(input_bytes)
        if sys.version_info[0] >= 3:
            return output_bytes.decode('ascii')
        else:
            return output_bytes

    # TODO: Consider passing prehashed input.
    # TODO: Translate signature into something py-TUF understands...
    def sign(self, signed: str) -> str:
        response = self.__client.secrets.transit.sign_data(
            name=self.__name,
            hash_input=self.__base64ify(signed),
            hash_algorithm=self.__hash_algorithm,
            marshaling_algorithm=self.__marshaling_algorithm,
            signature_algorithm=self.__signature_algorithm,
        )
        return response['data']['signature']

    # TODO: Consider passing prehashed input.
    # TODO: Translate signature into something Vault understands...
    def verify(self, signed: str, signature: str) -> bool:
        response = self.__client.secrets.transit.verify_signed_data(
            name=self.__name,
            hash_input=self.__base64ify(signed),
            hash_algorithm=self.__hash_algorithm,
            marshaling_algorithm=self.__marshaling_algorithm,
            signature_algorithm=self.__signature_algorithm,
            signature=signature,
        )
        return response['data']['valid']
