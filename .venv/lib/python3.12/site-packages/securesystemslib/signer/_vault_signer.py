"""Signer implementation for HashiCorp Vault (Transit secrets engine)"""

from __future__ import annotations

from base64 import b64decode, b64encode
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer

VAULT_IMPORT_ERROR = None
try:
    import hvac
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

except ImportError:
    VAULT_IMPORT_ERROR = "Signing with HashiCorp Vault requires hvac and cryptography."


class VaultSigner(Signer):
    """Signer for HashiCorp Vault Transit secrets engine.

    The signer uses ambient credentials to connect to Vault, most notably
    the environment variables ``VAULT_ADDR`` and ``VAULT_TOKEN`` must be set:
    https://developer.hashicorp.com/vault/docs/commands#environment-variables

    The private key URI scheme is: ``hv:<KEY NAME>/<KEY VERSION>``.

    Raises:
        UnsupportedLibraryError: If hvac or cryptography are not installed.
    """

    SCHEME = "hv"

    def __init__(self, hv_key_name: str, public_key: SSlibKey, hv_key_version: int):
        if VAULT_IMPORT_ERROR:
            raise UnsupportedLibraryError(VAULT_IMPORT_ERROR)

        self.hv_key_name = hv_key_name
        self._public_key = public_key
        self.hv_key_version = hv_key_version

        # Client caches ambient settings in __init__. This means settings are
        # stable for subsequent calls to sign, also if the environment changes.
        self._client = hvac.Client()

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with HashiCorp Vault Transit secrets engine.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from hvac.

        Returns:
            Signature.
        """
        resp = self._client.secrets.transit.sign_data(
            self.hv_key_name,
            hash_input=b64encode(payload).decode(),
            key_version=self.hv_key_version,
        )

        sig_b64 = resp["data"]["signature"].split(":")[2]
        sig = b64decode(sig_b64).hex()

        return Signature(self.public_key.keyid, sig)

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> VaultSigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"VaultSigner does not support {priv_key_uri}")

        name, version = uri.path.split("/")

        return cls(name, public_key, int(version))

    @classmethod
    def import_(cls, hv_key_name: str) -> tuple[str, SSlibKey]:
        """Load key and signer details from HashiCorp Vault.

        If multiple keys exist in the vault under the passed name, only the
        newest key is returned. Supported key type is: ed25519

        See class documentation for details about settings and uri format.

        Arguments:
            hv_key_name: Name of vault key to import.

        Raises:
            UnsupportedLibraryError: hvac or cryptography are not installed.
            Various errors from hvac.

        Returns:
            Private key uri and public key.

        """
        if VAULT_IMPORT_ERROR:
            raise UnsupportedLibraryError(VAULT_IMPORT_ERROR)

        client = hvac.Client()
        resp = client.secrets.transit.read_key(hv_key_name)

        # Pick key with highest version number
        version, key_info = sorted(resp["data"]["keys"].items())[-1]

        crypto_key = Ed25519PublicKey.from_public_bytes(
            b64decode(key_info["public_key"])
        )

        key = SSlibKey.from_crypto(crypto_key)
        uri = f"{VaultSigner.SCHEME}:{hv_key_name}/{version}"

        return uri, key
