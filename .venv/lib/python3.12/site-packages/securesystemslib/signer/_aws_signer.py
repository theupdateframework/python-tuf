"""Signer implementation for AWS Key Management Service"""

from __future__ import annotations

import hashlib
import logging
from urllib import parse

from securesystemslib.exceptions import (
    UnsupportedAlgorithmError,
    UnsupportedLibraryError,
)
from securesystemslib.signer._constants import (
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    KEY_TYPE_ECDSA,
    KEY_TYPE_RSA,
    RSA_PKCS1V15_SHA256,
    RSA_PKCS1V15_SHA384,
    RSA_PKCS1V15_SHA512,
    RSASSA_PSS_SHA256,
    RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512,
)
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer
from securesystemslib.signer._utils import compute_default_keyid

logger = logging.getLogger(__name__)

AWS_IMPORT_ERROR = None
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    from cryptography.hazmat.primitives import serialization
except ImportError:
    AWS_IMPORT_ERROR = "Signing with AWS KMS requires aws-kms and cryptography."


class AWSSigner(Signer):
    """AWS Key Management Service Signer.

    This Signer uses AWS KMS to sign, supporting RSA and EC keys.
    The signer computes hash digests locally and sends only the digest to AWS KMS.

    The private key URI scheme is: ``awskms:<AWS_KEY_ID>``, where ``<AWS_KEY_ID>``
    can be a key ID, key ARN, alias name, or alias ARN.

    Authentication uses ambient credentials (typically environment variables such as
    ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, and ``AWS_SESSION_TOKEN``)
    recognized by the boto3 SDK.

    For more details on AWS authentication, refer to the `AWS Command Line
    Interface User Guide
    <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html>`_.

    The specific IAM permissions that AWSSigner needs are:

    * ``kms:GetPublicKey`` for ``AWSSigner.import_()``
    * ``kms:Sign`` for ``Signer.sign()``

    Raises:
        UnsupportedLibraryError: If boto3 or cryptography are not installed.
    """

    SCHEME = "awskms"

    # Ordered dict of securesystemslib schemes to aws signing algorithms
    # NOTE: the order matters when choosing a default (see _get_default_scheme)
    aws_algos = {
        ECDSA_SHA2_NISTP256: "ECDSA_SHA_256",
        ECDSA_SHA2_NISTP384: "ECDSA_SHA_384",
        # "ecdsa-sha2-nistp521": "ECDSA_SHA_512", # FIXME: needs SSlibKey support
        RSASSA_PSS_SHA256: "RSASSA_PSS_SHA_256",
        RSASSA_PSS_SHA384: "RSASSA_PSS_SHA_384",
        RSASSA_PSS_SHA512: "RSASSA_PSS_SHA_512",
        RSA_PKCS1V15_SHA256: "RSASSA_PKCS1_V1_5_SHA_256",
        RSA_PKCS1V15_SHA384: "RSASSA_PKCS1_V1_5_SHA_384",
        RSA_PKCS1V15_SHA512: "RSASSA_PKCS1_V1_5_SHA_512",
    }

    def __init__(self, aws_key_id: str, public_key: SSlibKey):
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        self.aws_key_id = aws_key_id
        self._public_key = public_key
        self.client = boto3.client("kms")
        self.aws_algo = self.aws_algos[self.public_key.scheme]

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> AWSSigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"Expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"AWSSigner does not support {priv_key_uri}")

        return cls(uri.path, public_key)

    @classmethod
    def _get_default_scheme(cls, supported_by_key: list[str]) -> str | None:
        # Iterate over supported AWS algorithms, pick the **first** that is also
        # supported by the key, and return the related securesystemslib scheme.
        for scheme, algo in cls.aws_algos.items():
            if algo in supported_by_key:
                return scheme
        return None

    @staticmethod
    def _get_keytype_for_scheme(scheme: str) -> str:
        if scheme.startswith(KEY_TYPE_ECDSA):
            return KEY_TYPE_ECDSA
        if scheme.startswith(KEY_TYPE_RSA):
            return KEY_TYPE_RSA
        raise RuntimeError

    @classmethod
    def import_(
        cls, aws_key_id: str, local_scheme: str | None = None
    ) -> tuple[str, SSlibKey]:
        """Loads a key and signer details from AWS KMS.

        Returns the private key uri and the public key. This method should only
        be called once per key: the uri and Key should be stored for later use.

        Arguments:
            aws_key_id: AWS KMS key ID.
            local_scheme: securesystemslib key scheme.
                Defaults to 'rsassa-pss-sha256' if not provided.

        Raises:
            UnsupportedAlgorithmError: If the AWS KMS signing algorithm is
                unsupported.
            BotoCoreError: Errors from the botocore library.
            ClientError: Errors related to AWS KMS client.

        Returns:
            A tuple of private key URI string and public key.
        """
        if AWS_IMPORT_ERROR:
            raise UnsupportedLibraryError(AWS_IMPORT_ERROR)

        if local_scheme:
            if local_scheme not in cls.aws_algos:
                raise ValueError(f"Unsupported scheme '{local_scheme}'")

        client = boto3.client("kms")
        request = client.get_public_key(KeyId=aws_key_id)
        key_algos = request["SigningAlgorithms"]

        if local_scheme:
            if cls.aws_algos[local_scheme] not in key_algos:
                raise UnsupportedAlgorithmError(
                    f"Unsupported scheme '{local_scheme}' for AWS key"
                )

        else:
            local_scheme = cls._get_default_scheme(key_algos)
            if not local_scheme:
                raise UnsupportedAlgorithmError(
                    f"Unsupported AWS key algorithms: {key_algos}"
                )

        keytype = cls._get_keytype_for_scheme(local_scheme)

        kms_pubkey = serialization.load_der_public_key(request["PublicKey"])

        public_key_pem = kms_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        keyval = {"public": public_key_pem}
        keyid = compute_default_keyid(keytype, local_scheme, keyval)
        public_key = SSlibKey(keyid, keytype, local_scheme, keyval)
        return f"{cls.SCHEME}:{aws_key_id}", public_key

    def sign(self, payload: bytes) -> Signature:
        """Sign the payload with the AWS KMS key

        This method computes the hash of the payload locally and sends only the
        digest to AWS KMS for signing.

        Arguments:
            payload (bytes): The payload to be signed.

        Raises:
            BotoCoreError, ClientError: If an error occurs during the signing process.

        Returns:
            Signature: A signature object containing the key ID and the signature.
        """
        try:
            hash_algorithm = self.public_key.get_hash_algorithm_name()
            hasher = hashlib.new(hash_algorithm)
            hasher.update(payload)
            digest = hasher.digest()

            sign_request = self.client.sign(
                KeyId=self.aws_key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm=self.aws_algo,
            )

            logger.debug("Signing response: %s", sign_request)
            response = sign_request["Signature"]
            logger.debug("Signature response: %s", response)

            return Signature(self.public_key.keyid, response.hex())
        except (BotoCoreError, ClientError) as e:
            logger.error(
                "Failed to sign using AWS KMS key ID %s: %s",
                self.aws_key_id,
                str(e),
            )
            raise e
