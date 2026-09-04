"""Signer implementation for pyca/cryptography signing."""

from __future__ import annotations

import logging
import os
from dataclasses import astuple, dataclass
from typing import cast
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
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
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer
from securesystemslib.signer._utils import get_mldsa_payload

CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        EllipticCurve,
        EllipticCurvePrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key as generate_ec_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA44PrivateKey,
        MLDSA65PrivateKey,
        MLDSA87PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import (
        MGF1,
        PSS,
        PKCS1v15,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        AsymmetricPadding,
        RSAPrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        generate_private_key as generate_rsa_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
    from cryptography.hazmat.primitives.hashes import (
        SHA256,
        SHA384,
        SHA512,
        HashAlgorithm,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        load_pem_private_key,
    )

    from securesystemslib.signer._crypto_utils import get_hash_algorithm

except ImportError:
    CRYPTO_IMPORT_ERROR = "'pyca/cryptography' library required"

logger = logging.getLogger(__name__)


@dataclass
class _RSASignArgs:
    padding: AsymmetricPadding
    hash_algo: HashAlgorithm


@dataclass
class _ECDSASignArgs:
    sig_algo: ECDSA


@dataclass
class _NoSignArgs:
    pass


# keep in sync with _get_ecdsa_curve_and_hash() below
_ECDSA_SCHEMES = [
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
]


def _get_ecdsa_curve_and_hash(
    scheme: str,
) -> tuple[type[EllipticCurve], HashAlgorithm]:
    """Helper to return curve and hash algorithm for an ecdsa scheme.

    An ecdsa scheme fixes both, and the pairs must agree with the ones
    SSlibKey._verify() uses, or signatures will not verify.
    """
    # built here and not at module scope, so that importing this module
    # still works when pyca/cryptography is not installed
    curves_and_hashes: dict[str, tuple[type[EllipticCurve], HashAlgorithm]] = {
        ECDSA_SHA2_NISTP256: (SECP256R1, SHA256()),
        ECDSA_SHA2_NISTP384: (SECP384R1, SHA384()),
        ECDSA_SHA2_NISTP521: (SECP521R1, SHA512()),
    }

    return curves_and_hashes[scheme]


def _get_rsa_padding(name: str, hash_algorithm: HashAlgorithm) -> AsymmetricPadding:
    """Helper to return rsa signature padding for name."""
    padding: AsymmetricPadding
    if name == "pss":
        padding = PSS(mgf=MGF1(hash_algorithm), salt_length=PSS.DIGEST_LENGTH)

    if name == "pkcs1v15":
        padding = PKCS1v15()

    return padding


class CryptoSigner(Signer):
    """File-based signer using the cryptography (pyca/cryptography) library.

    Supports signing with RSA, ECDSA, Ed25519, and ML-DSA keys.

    The private key URI scheme is: ``file2:<PATH>``, where ``<PATH>`` is the filesystem
    path to a PEM-encoded PKCS#8 private key file. If the ``CRYPTO_SIGNER_PATH_PREFIX``
    environment variable is set, the path will be resolved relative to that prefix.

    A CryptoSigner can be instantiated with:

    * ``Signer.from_priv_key_uri("file2:<PATH>", public_key)``:
      Generic way to load from an existing private key file.
    * ``CryptoSigner.generate_*()`` factory methods generate new key pairs
    * ``CryptoSigner(privkey, pubkey)``: Direct instantiation using existing
      pyca/cryptography private key objects.
    """

    SCHEME = "file2"
    PREFIX_ENV_VAR = "CRYPTO_SIGNER_PATH_PREFIX"

    def __init__(
        self,
        private_key: PrivateKeyTypes,
        public_key: SSlibKey | None = None,
    ):
        def assert_type(
            name: str, key: PrivateKeyTypes, typ: type[PrivateKeyTypes]
        ) -> None:
            if not isinstance(key, typ):
                raise ValueError(f"invalid {name} key: {type(key)}")

        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if public_key is None:
            public_key = SSlibKey.from_crypto(private_key.public_key())

        self._private_key: PrivateKeyTypes
        self._sign_args: _RSASignArgs | _ECDSASignArgs | _NoSignArgs

        if public_key.keytype == KEY_TYPE_RSA and public_key.scheme in [
            RSASSA_PSS_SHA224,
            RSASSA_PSS_SHA256,
            RSASSA_PSS_SHA384,
            RSASSA_PSS_SHA512,
            RSA_PKCS1V15_SHA224,
            RSA_PKCS1V15_SHA256,
            RSA_PKCS1V15_SHA384,
            RSA_PKCS1V15_SHA512,
        ]:
            assert_type(KEY_TYPE_RSA, private_key, RSAPrivateKey)

            hash_name = public_key.get_hash_algorithm_name()
            hash_algo = get_hash_algorithm(hash_name)

            padding_name = public_key.get_padding_name()
            padding = _get_rsa_padding(padding_name, hash_algo)

            self._sign_args = _RSASignArgs(padding, hash_algo)

        # for backwards compat the spec-deprecated ecdsa keytypes (which are
        # named after the scheme) are accepted in addition to "ecdsa"
        elif (
            public_key.keytype in [KEY_TYPE_ECDSA, public_key.scheme]
            and public_key.scheme in _ECDSA_SCHEMES
        ):
            assert_type(KEY_TYPE_ECDSA, private_key, EllipticCurvePrivateKey)
            ec_key = cast(EllipticCurvePrivateKey, private_key)

            curve, hash_algo = _get_ecdsa_curve_and_hash(public_key.scheme)
            if not isinstance(ec_key.curve, curve):
                raise ValueError(
                    f"bad curve {ec_key.curve.name} for {public_key.scheme}"
                )

            self._sign_args = _ECDSASignArgs(ECDSA(hash_algo))

        elif public_key.keytype == KEY_TYPE_ED25519 and public_key.scheme == ED25519:
            assert_type(KEY_TYPE_ED25519, private_key, Ed25519PrivateKey)
            self._sign_args = _NoSignArgs()

        elif public_key.keytype == KEY_TYPE_MLDSA and public_key.scheme == MLDSA_44_1:
            assert_type(KEY_TYPE_MLDSA, private_key, MLDSA44PrivateKey)
            self._sign_args = _NoSignArgs()

        elif public_key.keytype == KEY_TYPE_MLDSA and public_key.scheme == MLDSA_65_1:
            assert_type(KEY_TYPE_MLDSA, private_key, MLDSA65PrivateKey)
            self._sign_args = _NoSignArgs()

        elif public_key.keytype == KEY_TYPE_MLDSA and public_key.scheme == MLDSA_87_1:
            assert_type(KEY_TYPE_MLDSA, private_key, MLDSA87PrivateKey)
            self._sign_args = _NoSignArgs()

        else:
            raise ValueError(
                f"unsupported public key {public_key.keytype}/{public_key.scheme}"
            )

        self._private_key = private_key
        self._public_key = public_key

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @property
    def private_bytes(self) -> bytes:
        """Return the PEM encoded PKCS8 format private key as bytes

        The return value can be used as file content when a Signer is loaded with
        `Signer.from_priv_key_uri('file2:<FILEPATH>')`."""
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> CryptoSigner:
        """Constructor for Signer to call

        Please refer to Signer.from_priv_key_uri() documentation.

        NOTE: pyca/cryptography is used to deserialize the key data. The
        expected (and tested) encoding/format is PEM/PKCS8. Other formats may
        but are not guaranteed to work.

        URI has the format "file2:<PATH>", where PATH is a filesystem path to the
        private key file. If CRYPTO_SIGNER_PATH_PREFIX environment variable
        is set, the private key will be read from
        ``CRYPTO_SIGNER_PATH_PREFIX + <SEPARATOR> + PATH``. The purpose of this
        is to allow PATH to only encode an identifier (e.g. filename) while allowing
        the signing system to store the private keys whereever it wants at runtime.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed.
            OSError: File cannot be read.
            ValueError: Invalid passed arguments.
            cryptography.exceptions.UnsupportedAlgorithm: pyca/cryptography
                deserialization failed.
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"CryptoSigner does not support {priv_key_uri}")

        prefix = os.environ.get(cls.PREFIX_ENV_VAR)
        path = os.path.join(prefix, uri.path) if prefix else uri.path
        try:
            with open(path, "rb") as f:
                private_pem = f.read()
        except FileNotFoundError as e:
            raise FileNotFoundError(
                f"Private key not found in '{path}' (with ",
                f"{cls.PREFIX_ENV_VAR}: {prefix}, path: {uri.path})",
            ) from e

        private_key = load_pem_private_key(private_pem, None)
        return CryptoSigner(private_key, public_key)

    @staticmethod
    def generate_ed25519(
        keyid: str | None = None,
    ) -> CryptoSigner:
        """Generate new key pair as "ed25519" signer.

        Args:
            keyid: Key identifier. If not passed, a default keyid is computed.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        private_key = Ed25519PrivateKey.generate()
        public_key = SSlibKey.from_crypto(private_key.public_key(), keyid, ED25519)
        return CryptoSigner(private_key, public_key)

    @staticmethod
    def generate_rsa(
        keyid: str | None = None,
        scheme: str | None = RSASSA_PSS_SHA256,
        size: int = 3072,
    ) -> CryptoSigner:
        """Generate new key pair as rsa signer.

        Args:
            keyid: Key identifier. If not passed, a default keyid is computed.
            scheme: RSA signing scheme. Default is "rsassa-pss-sha256".
            size: RSA key size in bits. Default is 3072.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        private_key = generate_rsa_private_key(
            public_exponent=65537,
            key_size=size,
        )
        public_key = SSlibKey.from_crypto(private_key.public_key(), keyid, scheme)
        return CryptoSigner(private_key, public_key)

    @staticmethod
    def generate_ecdsa(
        keyid: str | None = None,
        scheme: str | None = None,
    ) -> CryptoSigner:
        """Generate new key pair for an ecdsa signer.

        Args:
            keyid: Key identifier. If not passed, a default keyid is computed.
            scheme: A valid ecdsa scheme, which also selects the curve. If not
                passed, "ecdsa-sha2-nistp256" is used.

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed
            ValueError: Invalid scheme
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        scheme = ECDSA_SHA2_NISTP256 if scheme is None else scheme
        if scheme not in _ECDSA_SCHEMES:
            raise ValueError(f"Invalid scheme for ecdsa: {scheme}")

        curve, _ = _get_ecdsa_curve_and_hash(scheme)
        private_key = generate_ec_private_key(curve())
        public_key = SSlibKey.from_crypto(private_key.public_key(), keyid, scheme)
        return CryptoSigner(private_key, public_key)

    @staticmethod
    def generate_mldsa(
        keyid: str | None = None,
        scheme: str | None = None,
    ) -> CryptoSigner:
        """Generate new key pair for a ML-DSA signer.

        Args:
            keyid: Key identifier. If not passed, a default keyid is computed.
            scheme: A valid key scheme for ml-dsa. If not passed, "ml-dsa-65/1" is used

        Raises:
            UnsupportedLibraryError: pyca/cryptography not installed
        """
        if CRYPTO_IMPORT_ERROR:
            raise UnsupportedLibraryError(CRYPTO_IMPORT_ERROR)

        scheme = MLDSA_65_1 if scheme is None else scheme
        if scheme == MLDSA_44_1:
            private_key: PrivateKeyTypes = MLDSA44PrivateKey.generate()
        elif scheme == MLDSA_65_1:
            private_key = MLDSA65PrivateKey.generate()
        elif scheme == MLDSA_87_1:
            private_key = MLDSA87PrivateKey.generate()
        else:
            raise ValueError(f"Invalid scheme for ML-DSA: {scheme}")

        public_key = SSlibKey.from_crypto(private_key.public_key(), keyid, scheme)
        return CryptoSigner(private_key, public_key)

    def sign(self, payload: bytes) -> Signature:
        if self.public_key.keytype == KEY_TYPE_MLDSA:
            # ml-dsa keytype specifies a domain-specific hash prefixing scheme
            payload = get_mldsa_payload(payload, 1)

        sig = self._private_key.sign(payload, *astuple(self._sign_args))  # type: ignore

        return Signature(self.public_key.keyid, sig.hex())
