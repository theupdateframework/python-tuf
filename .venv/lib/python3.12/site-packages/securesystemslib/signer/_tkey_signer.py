"""ML-DSA-44 Signer for Tillitis TKey"""

from __future__ import annotations

import logging
from urllib import parse

from securesystemslib.exceptions import KeyMismatchError, UnsupportedLibraryError
from securesystemslib.signer._constants import MLDSA_44_1
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer
from securesystemslib.signer._utils import get_mldsa_payload

TKEY_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey
    from keylet import SignApp, TKeySign
except ImportError as e:
    TKEY_IMPORT_ERROR = f"TKeySigner: {e}"


logger = logging.getLogger(__name__)


class TKeySigner(Signer):
    """Post-Quantum signer for the Tillitis TKey security token.

    Supports signing scheme MLDSA_44_1.

    The private key URI is: ``tkey:[device_path]?digest=<hex_prefix>&[passphrase=true]``

        * ``digest`` is required in the URI: The device binary (identified by its
          digest hash prefix) is part of the private key seed. A key can only
          be used with the same exact binary.
        * ``device_path`` is optional and not typically needed as device detection is
          automatic.
        * If ``passphrase=true`` is present in the URI, a ``secrets_handler`` must be
          provided to ``Signer.from_priv_key_uri()`` to supply the passphrase secret.

    Examples:
        * ``tkey:?digest=7c75714``
        * ``tkey:?digest=7c75714&passphrase=true``
        * ``tkey:/dev/ttyACM0?digest=7c75714&passphrase=true``
    """

    SCHEME = "tkey"

    def __init__(
        self,
        device_path: str | None,
        public_key: SSlibKey,
        passphrase: str | None,
        digest: str | None,
    ) -> None:
        if TKEY_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEY_IMPORT_ERROR)

        self._public_key = public_key

        app = SignApp.load_mldsa(digest=digest)
        self._tkey = TKeySign(app, device_path, passphrase)

        # key derivation depends on passphrase: compare keys to make sure
        raw_pubkey = self._tkey.get_pubkey()
        if public_key.scheme == MLDSA_44_1:
            key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))
        else:
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        if key.keyval != self.public_key.keyval:
            raise KeyMismatchError(
                "TKey public key does not match: This could mean incorrect Passphrase."
            )

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> TKeySigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)
        if uri.scheme != cls.SCHEME:
            raise ValueError(f"TKeySigner does not support {priv_key_uri}")

        # Extract device path (empty or "/" triggers auto-detect)
        device_path = uri.path if uri.path not in ("", "/") else None

        # Extract query parameters
        query_params = parse.parse_qs(uri.query)

        digest = None
        if "digest" in query_params:
            digest = query_params["digest"][0]

        if not digest:
            raise ValueError("TKey URI must include 'digest'")

        pass_str = query_params.get("passphrase", ["false"])[0]
        if pass_str.lower() != "true":
            passphrase = None
        elif secrets_handler is not None:
            passphrase = secrets_handler("passphrase")
        else:
            raise ValueError(
                "TKey URI has 'passphrase' but no secrets_handler was given"
            )

        return cls(
            device_path,
            public_key=public_key,
            passphrase=passphrase,
            digest=digest,
        )

    @classmethod
    def import_(
        cls,
        digest: str | None = None,
        device_path: str | None = None,
        passphrase: str | None = None,
    ) -> tuple[str, SSlibKey]:
        """Import public key and signer details from a TKey device.

        Args:
            digest: Optional digest or digest prefix of device binary. If not given,
                the current default device binary is used.
            device_path: Optional COM port path. Typically not useful as the port may
                be dynamic
            passphrase: Optional "User Supplied Secret". Will be used as part of the
                seed for the private key

        Returns:
            Tuple of private key URI string and public key
        """
        if TKEY_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEY_IMPORT_ERROR)

        app = SignApp.load_mldsa(digest=digest)
        with TKeySign(app, device_path, passphrase) as tk:
            raw_pubkey = tk.get_pubkey()

        # Build URI with digest prefix and optional passphrase boolean
        query = {"digest": app.digest[:7]}

        if passphrase is not None:
            query["passphrase"] = "true"  # noqa: S105

        key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))

        # Only encode path if it was explicitly passed as argument
        path = device_path if device_path is not None else ""
        uri = f"{cls.SCHEME}:{path}?{parse.urlencode(query)}"

        return uri, key

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Tillitis TKey."""

        # Provide the pub key bytes for mu calculation
        pk_pem = self.public_key.keyval["public"].encode("utf-8")
        public_key = serialization.load_pem_public_key(pk_pem)
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Use TUF-specific message prefix and digest as payload
        sig_bytes = self._tkey.sign(get_mldsa_payload(payload, 1), key_bytes)
        return Signature(self.public_key.keyid, sig_bytes.hex())
