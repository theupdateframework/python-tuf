"""Signer implementation for Azure Key Vault"""

from __future__ import annotations

import hashlib
import logging
from urllib import parse

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._constants import (
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    KEY_TYPE_ECDSA,
)
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer
from securesystemslib.signer._utils import compute_default_keyid

AZURE_IMPORT_ERROR = None
try:
    from azure.core.exceptions import HttpResponseError
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.keys import KeyClient, KeyCurveName, KeyVaultKey
    from azure.keyvault.keys.crypto import (
        CryptographyClient,
        SignatureAlgorithm,
    )
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    KEYTYPES_AND_SCHEMES = {
        KeyCurveName.p_256: (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP256),
        KeyCurveName.p_384: (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP384),
        KeyCurveName.p_521: (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP521),
    }

    SIGNATURE_ALGORITHMS = {
        ECDSA_SHA2_NISTP256: SignatureAlgorithm.es256,
        ECDSA_SHA2_NISTP384: SignatureAlgorithm.es384,
        ECDSA_SHA2_NISTP521: SignatureAlgorithm.es512,
    }


except ImportError:
    AZURE_IMPORT_ERROR = (
        "Signing with Azure Key Vault requires azure-identity, "
        "azure-keyvault-keys and cryptography."
    )

logger = logging.getLogger(__name__)


class UnsupportedKeyType(Exception):  # noqa: N818
    pass


class AzureSigner(Signer):
    """Azure Key Vault Signer.

    This Signer uses Azure Key Vault to sign.
    Currently this signer supports signing with EC keys (NIST curves P-256, P-384,
    and P-521).

    The private key URI scheme is:
    ``azurekms://<vault-name>.vault.azure.net/keys/<key-name>/<version>``

    Authentication uses ambient credentials via
    ``azure.identity.DefaultAzureCredential`` (such as environment variables
    ``AZURE_CLIENT_ID``, ``AZURE_CLIENT_SECRET``, ``AZURE_TENANT_ID``, managed
    identities, or Azure CLI login).

    The specific permissions that AzureSigner needs are:

    * "Key Vault Crypto User" (or equivalent custom RBAC role) for
      ``AzureSigner.import_()`` and ``Signer.sign()``

    See `Azure Key Vault RBAC guide
    <https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli>`_
    for a list of all built-in Azure Key Vault roles.

    Raises:
        UnsupportedLibraryError: If azure-identity, azure-keyvault-keys, or
            cryptography are not installed.
    """

    SCHEME = "azurekms"

    def __init__(self, az_key_uri: str, public_key: SSlibKey):
        if AZURE_IMPORT_ERROR:
            raise UnsupportedLibraryError(AZURE_IMPORT_ERROR)

        if (public_key.keytype, public_key.scheme) not in KEYTYPES_AND_SCHEMES.values():
            logger.info("only EC keys are supported for now")
            raise UnsupportedKeyType(
                "Supplied key must be an EC key on curve "
                "nistp256, nistp384, or nistp521"
            )

        cred = DefaultAzureCredential()
        self.crypto_client = CryptographyClient(
            az_key_uri,
            credential=cred,
        )
        self.signature_algorithm = SIGNATURE_ALGORITHMS[public_key.scheme]
        self.hash_algorithm = public_key.get_hash_algorithm_name()
        self._public_key = public_key

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @staticmethod
    def _get_key_vault_key(
        cred: DefaultAzureCredential,
        vault_name: str,
        key_name: str,
    ) -> KeyVaultKey:
        """Return KeyVaultKey created from the Vault name and key name"""
        vault_url = f"https://{vault_name}.vault.azure.net/"

        try:
            key_client = KeyClient(vault_url=vault_url, credential=cred)
            return key_client.get_key(key_name)
        except (HttpResponseError,) as e:
            logger.info(
                "Key %s/%s failed to create key client from credentials, "
                "key ID, and Vault URL: %s",
                vault_name,
                key_name,
                str(e),
            )
            raise e

    @staticmethod
    def _create_crypto_client(
        cred: DefaultAzureCredential,
        kv_key: KeyVaultKey,
    ) -> CryptographyClient:
        """Return CryptographyClient created Azure credentials and a KeyVaultKey"""
        try:
            return CryptographyClient(kv_key, credential=cred)
        except (HttpResponseError,) as e:
            logger.info(
                "Key %s failed to create crypto client from "
                "credentials and KeyVaultKey: %s",
                kv_key,
                str(e),
            )
            raise e

    @staticmethod
    def _get_keytype_and_scheme(crv: str) -> tuple[str, str]:
        try:
            return KEYTYPES_AND_SCHEMES[crv]
        except KeyError:
            raise UnsupportedKeyType("Unsupported curve supplied by key")

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> AzureSigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"AzureSigner does not support {priv_key_uri}")

        az_key_uri = priv_key_uri.replace("azurekms:", "https:")
        return cls(az_key_uri, public_key)

    @classmethod
    def import_(cls, az_vault_name: str, az_key_name: str) -> tuple[str, SSlibKey]:
        """Load key and signer details from KMS

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.
        """
        if AZURE_IMPORT_ERROR:
            raise UnsupportedLibraryError(AZURE_IMPORT_ERROR)

        credential = DefaultAzureCredential()
        key_vault_key = cls._get_key_vault_key(credential, az_vault_name, az_key_name)

        if not key_vault_key.key.kty.startswith("EC"):
            raise UnsupportedKeyType(f"Unsupported key type {key_vault_key.key.kty}")

        if key_vault_key.key.crv == KeyCurveName.p_256:
            crv: ec.EllipticCurve = ec.SECP256R1()
        elif key_vault_key.key.crv == KeyCurveName.p_384:
            crv = ec.SECP384R1()
        elif key_vault_key.key.crv == KeyCurveName.p_521:
            crv = ec.SECP521R1()
        else:
            raise UnsupportedKeyType(f"Unsupported curve type {key_vault_key.key.crv}")

        # Key is in JWK format, create a curve from it with the parameters
        x = int.from_bytes(key_vault_key.key.x, byteorder="big")
        y = int.from_bytes(key_vault_key.key.y, byteorder="big")

        cpub = ec.EllipticCurvePublicNumbers(x, y, crv)
        pub_key = cpub.public_key()
        pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        keytype, scheme = cls._get_keytype_and_scheme(key_vault_key.key.crv)
        keyval = {"public": pem.decode("utf-8")}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        public_key = SSlibKey(keyid, keytype, scheme, keyval)
        priv_key_uri = key_vault_key.key.kid.replace("https:", "azurekms:")

        return priv_key_uri, public_key

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Azure Key Vault.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from azure.keyvault.keys.

        Returns:
            Signature.
        """

        hasher = hashlib.new(self.hash_algorithm)
        hasher.update(payload)
        digest = hasher.digest()
        response = self.crypto_client.sign(self.signature_algorithm, digest)

        # This code is copied from:
        # https://github.com/secure-systems-lab/securesystemslib/blob/135567fa04f10d0c6a4cd32eb45ce736e1f50a93/securesystemslib/signer/_hsm_signer.py#L379
        #
        # The PKCS11 signature octets correspond to the concatenation of the
        # ECDSA values r and s, both represented as an octet string of equal
        # length of at most nLen with the most significant byte first (i.e.
        # big endian)
        # https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html#_Toc30061178
        r_s_len = int(len(response.signature) / 2)
        r = int.from_bytes(response.signature[:r_s_len], byteorder="big")
        s = int.from_bytes(response.signature[r_s_len:], byteorder="big")

        # Create an ASN.1 encoded Dss-Sig-Value to be used with
        # pyca/cryptography
        dss_sig_value = encode_dss_signature(r, s).hex()

        return Signature(self.public_key.keyid, dss_sig_value)
