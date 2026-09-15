"""Signer implementation for Google Cloud KMS"""

from __future__ import annotations

import hashlib
import logging
from typing import Any
from urllib import parse

from securesystemslib import exceptions
from securesystemslib.signer._constants import (
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    KEY_TYPE_ECDSA,
    KEY_TYPE_MLDSA,
    KEY_TYPE_RSA,
    MLDSA_44_1,
    MLDSA_65_1,
    MLDSA_87_1,
    RSA_PKCS1V15_SHA256,
    RSA_PKCS1V15_SHA512,
    RSASSA_PSS_SHA256,
    RSASSA_PSS_SHA512,
)
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer
from securesystemslib.signer._utils import compute_default_keyid, get_mldsa_payload

logger = logging.getLogger(__name__)

GCP_IMPORT_ERROR = None
try:
    from google.cloud import kms
    from google.cloud.kms_v1.types import CryptoKeyVersion

    KEYTYPES_AND_SCHEMES = {
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256: (
            KEY_TYPE_ECDSA,
            ECDSA_SHA2_NISTP256,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384: (
            KEY_TYPE_ECDSA,
            ECDSA_SHA2_NISTP384,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256: (
            KEY_TYPE_RSA,
            RSASSA_PSS_SHA256,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256: (
            KEY_TYPE_RSA,
            RSASSA_PSS_SHA256,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256: (
            KEY_TYPE_RSA,
            RSASSA_PSS_SHA256,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA512: (
            KEY_TYPE_RSA,
            RSASSA_PSS_SHA512,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256: (
            KEY_TYPE_RSA,
            RSA_PKCS1V15_SHA256,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256: (
            KEY_TYPE_RSA,
            RSA_PKCS1V15_SHA256,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256: (
            KEY_TYPE_RSA,
            RSA_PKCS1V15_SHA256,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512: (
            KEY_TYPE_RSA,
            RSA_PKCS1V15_SHA512,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_44: (
            KEY_TYPE_MLDSA,
            MLDSA_44_1,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65: (
            KEY_TYPE_MLDSA,
            MLDSA_65_1,
        ),
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_87: (
            KEY_TYPE_MLDSA,
            MLDSA_87_1,
        ),
    }
except ImportError:
    GCP_IMPORT_ERROR = (
        "google-cloud-kms library required to sign with Google Cloud keys."
    )


class GCPSigner(Signer):
    """Google Cloud KMS Signer.

    This Signer uses Google Cloud KMS to sign. The payload is hashed locally,
    but the signature is created on the KMS.

    The private key URI scheme is: ``gcpkms:<gcp_keyid>``, where ``<gcp_keyid>``
    is the fully qualified GCP KMS key name:
    ``projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<key>/cryptoKeyVersions/<version>``.

    Authentication uses ambient credentials (typically the environment variable
    ``GOOGLE_APPLICATION_CREDENTIALS`` pointing to a service account key file,
    or Google Application Default Credentials):
    https://cloud.google.com/docs/authentication/getting-started.

    The specific Google Cloud IAM roles that GCPSigner needs are:

    * ``roles/cloudkms.publicKeyViewer`` for ``GCPSigner.import_()``
    * ``roles/cloudkms.signer`` for ``Signer.sign()``
    """

    SCHEME = "gcpkms"

    def __init__(self, gcp_keyid: str, public_key: SSlibKey):
        if GCP_IMPORT_ERROR:
            raise exceptions.UnsupportedLibraryError(GCP_IMPORT_ERROR)

        if (public_key.keytype, public_key.scheme) not in KEYTYPES_AND_SCHEMES.values():
            raise exceptions.UnsupportedAlgorithmError(
                f"Unsupported key ({public_key.keytype}/{public_key.scheme}) "
                f"in key {public_key.keyid}"
            )

        self.hash_algorithm = public_key.get_hash_algorithm_name()
        self.gcp_keyid = gcp_keyid
        self._public_key = public_key
        self.client = kms.KeyManagementServiceClient()

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> GCPSigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"GCPSigner does not support {priv_key_uri}")

        return cls(uri.path, public_key)

    @classmethod
    def import_(cls, gcp_keyid: str) -> tuple[str, SSlibKey]:
        """Load key and signer details from KMS

        This method should only be called once per key: the uri and
        Key should be stored for later use.

        Requires ``roles/cloudkms.publicKeyViewer`` role on Google Cloud.

        Args:
            gcp_id: Fully qualified GCP KMS key name
                (``projects/<P>/locations/<L>/keyRings/<R>/cryptoKeys/<K>/cryptoKeyVersions/<V>``).
        Returns:
            Tuple with private key URI and the public key
        """
        if GCP_IMPORT_ERROR:
            raise exceptions.UnsupportedLibraryError(GCP_IMPORT_ERROR)

        client = kms.KeyManagementServiceClient()
        request = {
            "name": gcp_keyid,
            "public_key_format": kms.PublicKey.PublicKeyFormat.PEM,
        }
        kms_pubkey = client.get_public_key(request)
        try:
            keytype, scheme = KEYTYPES_AND_SCHEMES[kms_pubkey.algorithm]
        except KeyError as e:
            raise exceptions.UnsupportedAlgorithmError(
                f"{kms_pubkey.algorithm} is not a supported signing algorithm"
            ) from e

        keyval = {"public": kms_pubkey.public_key.data.decode("utf-8")}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        public_key = SSlibKey(keyid, keytype, scheme, keyval)

        return f"{cls.SCHEME}:{gcp_keyid}", public_key

    def sign(self, payload: bytes) -> Signature:
        # NOTE: request and response can contain CRC32C of the digest/sig:
        # Verifying could be useful but would require another dependency...

        request: dict[str, Any] = {"name": self.gcp_keyid}
        if self.public_key.keytype == KEY_TYPE_MLDSA:
            request["data"] = get_mldsa_payload(payload, 1)
        else:
            hasher = hashlib.new(self.hash_algorithm)
            hasher.update(payload)
            request["digest"] = {self.hash_algorithm: hasher.digest()}

        logger.debug("signing request %s", request)
        response = self.client.asymmetric_sign(request)
        logger.debug("signing response %s", response)

        return Signature(self.public_key.keyid, response.signature.hex())
