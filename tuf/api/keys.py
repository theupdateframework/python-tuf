# Imports.

# 2nd-party.

from abc import ABC, abstractmethod
from enum import Enum, unique
from typing import Dict, List, Optional, Union

import base64
import binascii
import logging
import sys

# 3rd-party.
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from securesystemslib.interface import (
    import_ecdsa_privatekey_from_file,
    import_ed25519_privatekey_from_file,
    import_rsa_privatekey_from_file,
)
from securesystemslib.keys import (
    create_signature,
    format_keyval_to_metadata,
    format_metadata_to_key,
    verify_signature,
)
from securesystemslib.rsa_keys import (
    HashSaltLengthType,
    MaxSaltLengthType,
    SaltLengthType,
    verify_rsa_signature,
)
from securesystemslib.storage import StorageBackendInterface

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

BytesOrStr = Union[bytes, str]

# FIXME: what complicates implementation are the following issues:
# 1. Coupling hashing/signature schemes within the key format itself instead of
# during signature time, which is a bad idea for various reasons.
# 2. Allowing schemes to be passed when importing RSA but not ECDSA or Ed25519
# files. This is inconsistent writing of keys to disk (RSA keys are written as
# naked PEM files w/o accompanying information such as keyid, keytype or
# scheme, but not ECDSA or Ed25519).
# 3. Ignoring schemes when passed anyway (e.g., hardcoding P-256 in
# import_ecdsakey_from_pem).
# 4. Confusing keytype with scheme. With RSA, there is a meaningful
# distinction, but not with ECDSA or Ed25519.

class Key(ABC):

    @abstractmethod
    def __init__(self) -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def keyid(self) -> str:
        raise NotImplementedError

    def _encode(self, bytes_or_str: BytesOrStr, encoding='utf-8') -> bytes:
        if sys.version_info[0] >= 3 and isinstance(bytes_or_str, str):
            return bytes_or_str.encode(encoding=encoding)
        else:
            return bytes_or_str

    @abstractmethod
    def sign(self, signed: BytesOrStr) -> Dict:
        raise NotImplementedError

    @abstractmethod
    def verify(self, signed: BytesOrStr, signature: Dict) -> bool:
        raise NotImplementedError

Keys = List[Key]

class KeyRing:

    def __init__(self, threshold: Threshold, keys: Keys):
        if len(keys) < threshold.least:
            logging.warning(f'{len(keys)} < {threshold.least}')
        if len(keys) > threshold.most:
            logging.warning(f'{len(keys)} > {threshold.most}')
        self.threshold = threshold
        self.keys = keys

# Specific types of keys, such as those in RAM, Hashicorp Vault,
# AWS KMS (TODO), Azure Key Vault (TODO),
# Google Cloud Key Management Service (TODO), or on HSMs (TODO).

class RAMKey(Key):

    # In practice, these are the only schemes used in py-TUF.
    FileHandlers = {
        'ecdsa-sha2-nistp256': import_ecdsa_privatekey_from_file,
        'ed25519': import_ed25519_privatekey_from_file,
        'rsassa-pss-sha256': import_rsa_privatekey_from_file,
    }

    def __init__(self, obj: Dict) -> None: # pylint: disable=super-init-not-called
        self.__obj = obj

    @classmethod
    def read_from_file(
        cls,
        filename: str,
        scheme: str,
        passphrase: Optional[str] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> 'RAMKey':
        handler = cls.FileHandlers.get(scheme)
        if not handler:
            return ValueError(scheme)
        obj = handler(
            filename,
            password=passphrase,
            storage_backend=storage_backend
        )
        return cls(obj)

    @property
    def keyid(self) -> str:
        return self.__obj['keyid']

    def sign(self, signed: BytesOrStr) -> Dict:
        signed_bytes = self._encode(signed)
        return create_signature(self.__obj, signed_bytes)

    def _verify_rsa_signature(
        self,
        signed: BytesOrStr,
        signature: Dict,
        salt_length_type: SaltLengthType = HashSaltLengthType
    ) -> bool:
        sig = signature['sig']
        sig = binascii.unhexlify(sig.encode('utf-8'))
        scheme = self.__obj['scheme']
        public = self.__obj['keyval']['public']
        signed_bytes = self._encode(signed)
        return verify_rsa_signature(
            sig,
            scheme,
            public,
            signed_bytes,
            salt_length_type=salt_length_type
        )

    def verify(self, signed: BytesOrStr, signature: Dict) -> bool:
        signed_bytes = self._encode(signed)
        return verify_signature(self.__obj, signature, signed_bytes)

class VaultKey(Key):

    class AuthenticationError(Exception): pass

    @unique
    class KeyTypes(Enum):
        ED25519 = 'ed25519'
        P_256 = 'ecdsa-p256'
        P_384 = 'ecdsa-p384'
        P_521 = 'ecdsa-p521'
        RSA_2048 = 'rsa-2048'
        RSA_3072 = 'rsa-3072'
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
        ASN1 = 'asn1'
        JWS = 'jws'

    def __set_algorithms(
        self,
        hash_algorithm: Optional[str] = None,
        marshaling_algorithm: Optional[str] = None,
        signature_algorithm: Optional[str] = None,
    ) -> None:
        # A valid hash algorithm is only good for ECDSA or RSA.
        if  hash_algorithm is not None:
            if hash_algorithm not in {h.value for h in self.HashAlgorithms}:
                raise ValueError(hash_algorithm)
            if self.__key_type == self.KeyTypes.ED25519.value:
                raise ValueError(hash_algorithm)
            # https://tools.ietf.org/html/rfc5656#section-6.2.1
            # P-256 only takes SHA2-256.
            if self.__key_type == self.KeyTypes.P_256.value and \
                hash_algorithm != self.HashAlgorithms.SHA2_256.value:
                raise ValueError(hash_algorithm)
            # P-384 only takes SHA2-384.
            if self.__key_type == self.KeyTypes.P_384.value and \
                hash_algorithm != self.HashAlgorithms.SHA2_384.value:
                raise ValueError(hash_algorithm)
            # P-521 only takes SHA2-512.
            if self.__key_type == self.KeyTypes.P_521.value and \
                hash_algorithm != self.HashAlgorithms.SHA2_512.value:
                raise ValueError(hash_algorithm)
        self.__hash_algorithm = hash_algorithm

        # A valid marshaling algorithm is only good for the NIST P-curves.
        if  marshaling_algorithm is not None:
            if marshaling_algorithm not in {m.value for m in self.MarshalingAlgorithms}:
                raise ValueError(marshaling_algorithm)
            if self.__key_type not in {
                self.KeyTypes.P_256.value,
                self.KeyTypes.P_384.value,
                self.KeyTypes.P_521.value,
            }:
                raise ValueError(marshaling_algorithm)
        self.__marshaling_algorithm = marshaling_algorithm

        # A signature algorithm is good only for RSA.
        if  signature_algorithm is not None:
            if signature_algorithm not in {s.value for s in self.SignatureAlgorithms}:
                raise ValueError(signature_algorithm)
            if self.__key_type not in {
                self.KeyTypes.RSA_2048.value,
                self.KeyTypes.RSA_3072.value,
                self.KeyTypes.RSA_4096.value
            }:
                raise ValueError(signature_algorithm)
        self.__signature_algorithm = signature_algorithm

    def __get_tuf_public_key(self, vault_public_key: str) -> Dict:
        if self.__key_type == self.KeyTypes.ED25519.value:
            keytype = self.__key_type
            scheme = keytype
            # Vault encodes Ed25519 public keys in standard base64,
            # so decode it into a format py-TUF understands.
            key_value = base64.standard_b64decode(vault_public_key)
            key_value = binascii.hexlify(key_value).decode()
        elif self.__key_type == self.KeyTypes.P_256.value:
            keytype = 'ecdsa-sha2-nistp256'
            scheme = keytype
            key_value = vault_public_key
        elif self.__key_type == self.KeyTypes.P_384.value:
            keytype = 'ecdsa-sha2-nistp384'
            scheme = keytype
            key_value = vault_public_key
        elif self.__key_type == self.KeyTypes.P_521.value:
            keytype = 'ecdsa-sha2-nistp521'
            scheme = keytype
            key_value = vault_public_key
        elif self.__key_type in {
            self.KeyTypes.RSA_2048.value,
            self.KeyTypes.RSA_3072.value,
            self.KeyTypes.RSA_4096.value
        }:
            keytype = 'rsa'

            if self.__signature_algorithm == self.SignatureAlgorithms.PSS.value:
                scheme = 'rsassa-pss'
            elif self.__signature_algorithm == self.SignatureAlgorithms.PKCS1.value:
                scheme = 'rsa-pkcs1v15'
            else:
                raise ValueError(self.__key_type)

            _, size = self.__hash_algorithm.split('-')
            scheme += f'-sha{size}'
            key_value = vault_public_key
        else:
            raise ValueError(self.__key_type)

        key_meta = format_keyval_to_metadata(
            keytype,
            scheme,
            {'public': key_value},
            private=False
        )
        key_dict, _ = format_metadata_to_key(key_meta)
        return key_dict

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

        # https://github.com/hvac/hvac/issues/604
        response = self.__client.secrets.transit.read_key(name=name)
        self.__name = name

        # Get public key.
        data = response['data']
        key_type = data['type']
        if key_type not in {k.value for k in self.KeyTypes}:
            return ValueError(key_type)
        self.__key_type = data['type']
        self.__set_algorithms(hash_algorithm, marshaling_algorithm, signature_algorithm)

        # NOTE: The documentation is not clear, but presumably the returned
        # keys are different versions of keys under the same name. Therefore,
        # we shall select the one with the latest version number.
        keys = data['keys']
        latest_version = data['latest_version']
        key = keys.get(str(latest_version))
        vault_public_key = key['public_key']
        tuf_public_key = self.__get_tuf_public_key(vault_public_key)
        self.__ram_key = RAMKey(tuf_public_key)

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
    def keyid(self) -> str:
        return self.__ram_key.keyid

    # https://hvac.readthedocs.io/en/stable/usage/secrets_engines/transit.html#create-key
    def __base64ify(self, bytes_or_str: BytesOrStr) -> str:
        """Helper method to perform base64 encoding across Python 2.7 and Python 3.X"""

        input_bytes = self._encode(bytes_or_str)

        output_bytes = base64.urlsafe_b64encode(input_bytes)
        if sys.version_info[0] >= 3:
            return output_bytes.decode('ascii')
        else:
            return output_bytes

    # https://github.com/matrix-org/python-unpaddedbase64/blob/c804b5753f4805cf3d129fa4e7febef5c032b6ca/unpaddedbase64.py#L29-L40
    def __rawurl_b64decode(self, input_string: str) -> bytes:
        """Decode a base64 string to bytes inferring padding from the length of the
        string."""

        input_bytes = input_string.encode("ascii")
        input_len = len(input_bytes)
        padding = b"=" * (3 - ((input_len + 3) % 4))
        decode = base64.b64decode
        if u'-' in input_string or u'_' in input_string:
            decode = base64.urlsafe_b64decode
        output_bytes = decode(input_bytes + padding)
        return output_bytes

    def __decode_sig(self, sig: str) -> str:
        # https://github.com/hashicorp/vault/blob/f6547fa8e820b6ebbfa15018477a138b38707d91/sdk/helper/keysutil/policy.go#L1217-L1224
        if self.__marshaling_algorithm == self.MarshalingAlgorithms.JWS.value:
            # https://github.com/golang/go/blob/11f92e9dae96939c2d784ae963fa7763c300660b/src/encoding/base64/base64.go#L110-L113
            sig = self.__rawurl_b64decode(sig)
        else:
            sig = base64.standard_b64decode(sig)

        sig = binascii.hexlify(sig).decode()

        # https://github.com/hashicorp/vault/blob/f6547fa8e820b6ebbfa15018477a138b38707d91/sdk/helper/keysutil/policy.go#L1303-L1311
        if self.__marshaling_algorithm == self.MarshalingAlgorithms.JWS.value:
            sig_len = len(sig) // 2
            rb = int(sig[:sig_len], 16)
            sb = int(sig[sig_len:], 16)
            # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature
            sig = encode_dss_signature(rb, sb)
            sig = binascii.hexlify(sig).decode()

        return sig

    # TODO: Allow passing prehashed input.
    def sign(self, signed: BytesOrStr) -> Dict:
        response = self.__client.secrets.transit.sign_data(
            name=self.__name,
            hash_input=self.__base64ify(signed),
            hash_algorithm=self.__hash_algorithm,
            marshaling_algorithm=self.__marshaling_algorithm,
            signature_algorithm=self.__signature_algorithm,
        )
        # vault:key-version-number:standard-base64-encoded-signature
        _, _, sig = response['data']['signature'].split(':')
        return {
            'keyid': self.keyid,
            'sig': self.__decode_sig(sig)
        }

    # TODO: Allow passing prehashed input.
    def verify(self, signed: BytesOrStr, signature: Dict) -> bool:
        if self.__key_type in {
            self.KeyTypes.RSA_2048.value,
            self.KeyTypes.RSA_3072.value,
            self.KeyTypes.RSA_4096.value
        } and self.__signature_algorithm == self.SignatureAlgorithms.PSS.value:
            # https://github.com/secure-systems-lab/securesystemslib/pull/262
            return self.__ram_key._verify_rsa_signature(
                signed,
                signature,
                salt_length_type=MaxSaltLengthType
            )
        else:
            return self.__ram_key.verify(signed, signature)
