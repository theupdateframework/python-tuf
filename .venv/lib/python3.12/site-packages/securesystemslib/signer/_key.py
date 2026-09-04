"""Key interface and the default implementations"""

from __future__ import annotations

import logging
import warnings
from abc import ABCMeta, abstractmethod
from typing import Any, cast

from securesystemslib._internal.utils import make_hashable
from securesystemslib._vendor.ed25519.ed25519 import (
    SignatureMismatch,
    checkvalid,
)
from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer._constants import (
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    ED25519,
    KEY_TYPE_ECDSA,
    KEY_TYPE_ED25519,
    KEY_TYPE_MLDSA,
    KEY_TYPE_RSA,
    MLDSA_44_1,
    MLDSA_65_1,
    MLDSA_87_1,
    RSA_PKCS1V15_SHA224,
    RSA_PKCS1V15_SHA256,
    RSA_PKCS1V15_SHA384,
    RSA_PKCS1V15_SHA512,
    RSASSA_PSS_SHA224,
    RSASSA_PSS_SHA256,
    RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512,
)
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._utils import compute_default_keyid, get_mldsa_payload

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        EllipticCurve,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA44PublicKey,
        MLDSA65PublicKey,
        MLDSA87PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import (
        MGF1,
        PSS,
        PKCS1v15,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        AsymmetricPadding,
        RSAPublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
    from cryptography.hazmat.primitives.hashes import (
        SHA256,
        SHA384,
        SHA512,
        HashAlgorithm,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    from securesystemslib.signer._crypto_utils import get_hash_algorithm

except ImportError:
    CRYPTO_IMPORT_ERROR = "'pyca/cryptography' library required"


logger = logging.getLogger(__name__)

# NOTE Key dispatch table is defined here so it's usable by Key,
# but is populated in __init__.py (and can be appended by users).
KEY_FOR_TYPE_AND_SCHEME: dict[tuple[str, str], type] = {}
"""Key dispatch table for ``Key.from_dict()``

See ``securesystemslib.signer.KEY_FOR_TYPE_AND_SCHEME`` for default key types
and schemes, and how to register custom implementations.
"""


class Key(metaclass=ABCMeta):
    """Abstract class representing the public portion of a key.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Args:
        keyid: Key identifier that is unique within the metadata it is used in.
            Keyid is not verified to be the hash of a specific representation
            of the key.
        keytype: Key type, e.g. ``KEY_TYPE_RSA``, ``KEY_TYPE_ED25519`` or
            ``KEY_TYPE_ECDSA``.
        scheme: Signature scheme. For example:
            ``RSASSA_PSS_SHA256``, ``ED25519``, and ``ECDSA_SHA2_NISTP256``.
        keyval: Opaque key content
        unrecognized_fields: Dictionary of all attributes that are not managed
            by Securesystemslib

    Raises:
        TypeError: Invalid type for an argument.
    """

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: dict[str, Any],
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        if not all(
            isinstance(at, str) for at in [keyid, keytype, scheme]
        ) or not isinstance(keyval, dict):
            raise TypeError("Unexpected Key attributes types!")
        self.keyid = keyid
        self.keytype = keytype
        self.scheme = scheme
        self.keyval = keyval

        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Key):
            return False

        return (
            self.keyid == other.keyid
            and self.keytype == other.keytype
            and self.scheme == other.scheme
            and self.keyval == other.keyval
            and self.unrecognized_fields == other.unrecognized_fields
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.keyid,
                self.keytype,
                self.scheme,
                make_hashable(self.keyval),
                make_hashable(self.unrecognized_fields),
            )
        )

    @classmethod
    @abstractmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> Key:
        """Creates ``Key`` object from a serialization dict

        Key implementations must override this factory constructor that is used
        as a deserialization helper.

        Users should call ``Key.from_dict()``: it dispatches to the actual
        subclass implementation based on supported keys in
        ``KEY_FOR_TYPE_AND_SCHEME``.

        Raises:
            KeyError, TypeError: Invalid arguments.
        """
        keytype = key_dict.get("keytype")
        scheme = key_dict.get("scheme")
        if (keytype, scheme) not in KEY_FOR_TYPE_AND_SCHEME:
            raise ValueError(f"Unsupported public key {keytype}/{scheme}")

        # NOTE: Explicitly not checking the keytype and scheme types to allow
        # intoto to use (None,None) to lookup GPGKey, see issue #450
        key_impl = KEY_FOR_TYPE_AND_SCHEME[(keytype, scheme)]  # type: ignore
        return key_impl.from_dict(keyid, key_dict)  # type: ignore

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Returns a serialization dict.

        Key implementations must override this serialization helper.
        """
        raise NotImplementedError

    def _to_dict(self) -> dict[str, Any]:
        """Serialization helper to add base Key fields to a dict.

        Key implementations may call this in their to_dict, which they must
        still provide, in order to avoid unnoticed serialization accidents.
        """
        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

    @staticmethod
    def _from_dict(key_dict: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        """Deserialization helper to pop base Key fields off the dict.

        Key implementations may call this in their from_dict, in order to parse
        out common fields. But they have to create the Key instance themselves.
        """
        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")

        return keytype, scheme, keyval

    @abstractmethod
    def verify_signature(self, signature: Signature, data: bytes) -> None:
        """Raises if verification of signature over data fails.

        Args:
            signature: Signature object.
            data: Payload bytes.

        Raises:
            UnverifiedSignatureError: Failed to verify signature.
            VerificationError: Signature verification process error. If you
                are only interested in the verify result, just handle
                UnverifiedSignatureError: it contains VerificationError as well
        """
        raise NotImplementedError


class SSlibKey(Key):
    """Key implementation for RSA, Ed25519, ECDSA keys"""

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: dict[str, Any],
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        if "public" not in keyval or not isinstance(keyval["public"], str):
            raise ValueError(f"public key string required for scheme {scheme}")
        super().__init__(keyid, keytype, scheme, keyval, unrecognized_fields)

    def get_hash_algorithm_name(self) -> str:
        """Get hash algorithm name for scheme. Raise
        ValueError if the scheme is not a supported pre-hash scheme."""
        if self.scheme in [
            RSASSA_PSS_SHA224,
            RSASSA_PSS_SHA256,
            RSASSA_PSS_SHA384,
            RSASSA_PSS_SHA512,
            RSA_PKCS1V15_SHA224,
            RSA_PKCS1V15_SHA256,
            RSA_PKCS1V15_SHA384,
            RSA_PKCS1V15_SHA512,
            ECDSA_SHA2_NISTP256,
            ECDSA_SHA2_NISTP384,
        ]:
            return f"sha{self.scheme[-3:]}"

        elif self.scheme in [
            ECDSA_SHA2_NISTP521,
            MLDSA_44_1,
            MLDSA_65_1,
            MLDSA_87_1,
        ]:
            return "sha512"

        raise ValueError(f"method not supported for scheme {self.scheme}")

    def get_padding_name(self) -> str:
        """Get padding name for scheme. Raise
        ValueError if the scheme is not a supported padded rsa scheme."""
        if self.scheme in [
            RSASSA_PSS_SHA224,
            RSASSA_PSS_SHA256,
            RSASSA_PSS_SHA384,
            RSASSA_PSS_SHA512,
            RSA_PKCS1V15_SHA224,
            RSA_PKCS1V15_SHA256,
            RSA_PKCS1V15_SHA384,
            RSA_PKCS1V15_SHA512,
        ]:
            return self.scheme.split("-")[1]

        raise ValueError(f"method not supported for scheme {self.scheme}")

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> SSlibKey:
        keytype, scheme, keyval = cls._from_dict(key_dict)

        # All fields left in the key_dict are unrecognized.
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict[str, Any]:
        return self._to_dict()

    def _crypto_key(self) -> PublicKeyTypes:
        """Helper to get a `cryptography` public key for this SSlibKey."""
        public_bytes = self.keyval["public"].encode("utf-8")
        return load_pem_public_key(public_bytes)

    @staticmethod
    def _from_crypto(public_key: PublicKeyTypes) -> tuple[str, str, str]:
        """Return tuple of keytype, default scheme and serialized public key
        value for the passed public key.

        Raise ValueError if public key is not supported.
        """

        def _raw() -> str:
            return public_key.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            ).hex()

        def _pem() -> str:
            return public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            ).decode()

        if isinstance(public_key, RSAPublicKey):
            ret = (KEY_TYPE_RSA, RSASSA_PSS_SHA256, _pem())
        elif isinstance(public_key, EllipticCurvePublicKey):
            if isinstance(public_key.curve, SECP256R1):
                ret = (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP256, _pem())
            elif isinstance(public_key.curve, SECP384R1):
                ret = (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP384, _pem())
            elif isinstance(public_key.curve, SECP521R1):
                ret = (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP521, _pem())
            else:
                raise ValueError(f"unsupported curve '{public_key.curve.name}'")
        elif isinstance(public_key, Ed25519PublicKey):
            ret = (KEY_TYPE_ED25519, ED25519, _raw())
        elif isinstance(public_key, MLDSA44PublicKey):
            ret = (KEY_TYPE_MLDSA, MLDSA_44_1, _pem())
        elif isinstance(public_key, MLDSA65PublicKey):
            ret = (KEY_TYPE_MLDSA, MLDSA_65_1, _pem())
        elif isinstance(public_key, MLDSA87PublicKey):
            ret = (KEY_TYPE_MLDSA, MLDSA_87_1, _pem())
        else:
            raise ValueError(f"unsupported key '{type(public_key)}'")

        return ret

    @classmethod
    def from_crypto(
        cls,
        public_key: PublicKeyTypes,
        keyid: str | None = None,
        scheme: str | None = None,
    ) -> SSlibKey:
        """Create SSlibKey from pyca/cryptography public key.

        Args:
            public_key: pyca/cryptography public key object.
            keyid: Key identifier. If not passed, a default keyid is computed.
            scheme: SSlibKey signing scheme. Defaults are ``RSASSA_PSS_SHA256``,
                ``ECDSA_SHA2_NISTP256``, ``ECDSA_SHA2_NISTP384`` and ``ED25519``
                according to the keytype.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed
            ValueError: Key type not supported

        Returns:
            SSlibKey

        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        keytype, default_scheme, public_key_value = cls._from_crypto(public_key)

        if not scheme:
            scheme = default_scheme

        keyval = {"public": public_key_value}

        if not keyid:
            keyid = compute_default_keyid(keytype, scheme, keyval)

        return SSlibKey(keyid, keytype, scheme, keyval)

    @staticmethod
    def _get_rsa_padding(name: str, hash_algorithm: HashAlgorithm) -> AsymmetricPadding:
        """Helper to return rsa signature padding for name."""
        padding: AsymmetricPadding
        if name == "pss":
            padding = PSS(mgf=MGF1(hash_algorithm), salt_length=PSS.AUTO)

        if name == "pkcs1v15":
            padding = PKCS1v15()

        return padding

    def _verify_ed25519_fallback(self, signature: bytes, data: bytes) -> None:
        """Helper to verify ed25519 sig if pyca/cryptography is unavailable."""
        try:
            public_bytes = bytes.fromhex(self.keyval["public"])
            checkvalid(signature, data, public_bytes)

        except SignatureMismatch as e:
            raise UnverifiedSignatureError from e

    def _verify(self, signature: bytes, data: bytes) -> None:  # noqa: PLR0912, PLR0915
        """Helper to verify signature using pyca/cryptography (default)."""

        def _validate_type(key: object, type_: type) -> None:
            if not isinstance(key, type_):
                raise ValueError(f"bad key {key} for {self.scheme}")

        def _validate_curve(
            key: EllipticCurvePublicKey, curve: type[EllipticCurve]
        ) -> None:
            if not isinstance(key.curve, curve):
                raise ValueError(f"bad curve {key.curve} for {self.scheme}")

        try:
            key: PublicKeyTypes
            if self.keytype == KEY_TYPE_RSA and self.scheme in [
                RSASSA_PSS_SHA224,
                RSASSA_PSS_SHA256,
                RSASSA_PSS_SHA384,
                RSASSA_PSS_SHA512,
                RSA_PKCS1V15_SHA224,
                RSA_PKCS1V15_SHA256,
                RSA_PKCS1V15_SHA384,
                RSA_PKCS1V15_SHA512,
            ]:
                key = cast(RSAPublicKey, self._crypto_key())
                _validate_type(key, RSAPublicKey)
                hash_name = self.get_hash_algorithm_name()
                hash_algorithm = get_hash_algorithm(hash_name)
                padding_name = self.get_padding_name()
                padding = self._get_rsa_padding(padding_name, hash_algorithm)
                key.verify(signature, data, padding, hash_algorithm)

            elif (
                self.keytype in [KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP256]
                and self.scheme == ECDSA_SHA2_NISTP256
            ):
                if self.keytype == ECDSA_SHA2_NISTP256:
                    warnings.warn(
                        f"keytype '{ECDSA_SHA2_NISTP256}' is deprecated, "
                        f"use '{KEY_TYPE_ECDSA}' instead",
                        DeprecationWarning,
                        stacklevel=2,
                    )
                key = cast(EllipticCurvePublicKey, self._crypto_key())
                _validate_type(key, EllipticCurvePublicKey)
                _validate_curve(key, SECP256R1)
                key.verify(signature, data, ECDSA(SHA256()))

            elif (
                self.keytype in [KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP384]
                and self.scheme == ECDSA_SHA2_NISTP384
            ):
                if self.keytype == ECDSA_SHA2_NISTP384:
                    warnings.warn(
                        f"keytype '{ECDSA_SHA2_NISTP384}' is deprecated, "
                        f"use '{KEY_TYPE_ECDSA}' instead",
                        DeprecationWarning,
                        stacklevel=2,
                    )
                key = cast(EllipticCurvePublicKey, self._crypto_key())
                _validate_type(key, EllipticCurvePublicKey)
                _validate_curve(key, SECP384R1)
                key.verify(signature, data, ECDSA(SHA384()))

            elif (
                self.keytype in [KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP521]
                and self.scheme == ECDSA_SHA2_NISTP521
            ):
                if self.keytype == ECDSA_SHA2_NISTP521:
                    warnings.warn(
                        f"keytype '{ECDSA_SHA2_NISTP521}' is deprecated, "
                        f"use '{KEY_TYPE_ECDSA}' instead",
                        DeprecationWarning,
                        stacklevel=2,
                    )
                key = cast(EllipticCurvePublicKey, self._crypto_key())
                _validate_type(key, EllipticCurvePublicKey)
                _validate_curve(key, SECP521R1)
                key.verify(signature, data, ECDSA(SHA512()))

            elif self.keytype == KEY_TYPE_ED25519 and self.scheme == ED25519:
                public_bytes = bytes.fromhex(self.keyval["public"])
                key = Ed25519PublicKey.from_public_bytes(public_bytes)
                key.verify(signature, data)

            elif self.keytype == KEY_TYPE_MLDSA and self.scheme == MLDSA_44_1:
                key = cast(MLDSA44PublicKey, self._crypto_key())
                _validate_type(key, MLDSA44PublicKey)
                key.verify(signature, get_mldsa_payload(data, 1))

            elif self.keytype == KEY_TYPE_MLDSA and self.scheme == MLDSA_65_1:
                key = cast(MLDSA65PublicKey, self._crypto_key())
                _validate_type(key, MLDSA65PublicKey)
                key.verify(signature, get_mldsa_payload(data, 1))

            elif self.keytype == KEY_TYPE_MLDSA and self.scheme == MLDSA_87_1:
                key = cast(MLDSA87PublicKey, self._crypto_key())
                _validate_type(key, MLDSA87PublicKey)
                key.verify(signature, get_mldsa_payload(data, 1))

            else:
                raise ValueError(f"Unsupported public key {self.keytype}/{self.scheme}")

        except InvalidSignature as e:
            raise UnverifiedSignatureError from e

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            if signature.keyid != self.keyid:
                raise ValueError(
                    f"keyid mismatch: 'key id: {self.keyid}"
                    f" != signature keyid: {signature.keyid}'"
                )

            signature_bytes = bytes.fromhex(signature.signature)

            if CRYPTO_IMPORT_ERROR:
                if self.scheme != ED25519:
                    raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

                return self._verify_ed25519_fallback(signature_bytes, data)

            return self._verify(signature_bytes, data)

        except UnverifiedSignatureError as e:
            raise UnverifiedSignatureError(
                f"Failed to verify signature by {self.keyid}"
            ) from e

        except Exception as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, e)
            raise VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e
