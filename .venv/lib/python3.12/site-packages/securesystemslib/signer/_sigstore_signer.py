"""Signer implementation for project sigstore."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib import parse

from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer._signer import (
    Key,
    SecretsHandler,
    Signature,
    Signer,
)
from securesystemslib.signer._utils import compute_default_keyid

IMPORT_ERROR = "sigstore library required to use 'sigstore-oidc' keys"

# ruff: noqa: PLC0415

logger = logging.getLogger(__name__)


class SigstoreKey(Key):
    """Sigstore verifier.

    NOTE: The Sigstore key and signature serialization formats are not yet
    considered stable in securesystemslib. They may change in future releases
    and may not be supported by other implementations.
    """

    DEFAULT_KEY_TYPE = "sigstore-oidc"
    DEFAULT_SCHEME = "Fulcio"

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: dict[str, Any],
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        for content in ["identity", "issuer"]:
            if content not in keyval or not isinstance(keyval[content], str):
                raise ValueError(f"{content} string required for scheme {scheme}")
        super().__init__(keyid, keytype, scheme, keyval, unrecognized_fields)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> SigstoreKey:
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            from sigstore.errors import VerificationError as SigstoreVerifyError
            from sigstore.models import Bundle
            from sigstore.verify import Verifier
            from sigstore.verify.policy import Identity
        except ImportError as e:
            raise VerificationError(IMPORT_ERROR) from e

        try:
            verifier = Verifier.production()
            identity = Identity(
                identity=self.keyval["identity"], issuer=self.keyval["issuer"]
            )
            bundle_data = signature.unrecognized_fields["bundle"]
            bundle = Bundle.from_json(json.dumps(bundle_data))

            verifier.verify_artifact(data, bundle, identity)

        except SigstoreVerifyError as e:
            logger.info(
                "Key %s failed to verify sig: %s",
                self.keyid,
                e,
            )
            raise UnverifiedSignatureError(
                f"Failed to verify signature by {self.keyid}"
            ) from e
        except Exception as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e


class SigstoreSigner(Signer):
    """Sigstore signer.

    NOTE: The Sigstore key and signature serialization formats are not yet
    considered stable in securesystemslib. They may change in future releases
    and may not be supported by other implementations.

    All signers should be instantiated with ``Signer.from_priv_key_uri()``.
    Unstable ``SigstoreSigner`` currently requires opt-in via
    ``securesystemslib.signer.SIGNER_FOR_URI_SCHEME``.

    Usage::

        identity = "luk.puehringer@gmail.com"  # change, unless you know pw
        issuer = "https://github.com/login/oauth"

        # Create signer URI and public key for identity and issuer
        uri, public_key = SigstoreSigner.import_(identity, issuer, ambient=False)

        # Load signer from URI -- requires browser login with GitHub
        signer = SigstoreSigner.from_priv_key_uri(uri, public_key)

        # Sign with signer and verify public key
        signature = signer.sign(b"data")
        public_key.verify_signature(signature, b"data")

    The private key URI scheme is ``sigstore:?<PARAMS>``, where PARAMS is
    optional and toggles ambient credential usage. Example URIs:

    * ``sigstore:``:
        Sign with ambient credentials.
    * ``sigstore:?ambient=false``:
        Sign with OAuth2 + OpenID via browser login.

    Raises:
        UnsupportedLibraryError: If sigstore library is not installed.
    """

    SCHEME = "sigstore"

    def __init__(self, token: Any, public_key: Key):
        self._public_key = public_key
        # token is of type sigstore.oidc.IdentityToken but the module should be usable
        # without sigstore so it's not annotated
        self._token = token

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> SigstoreSigner:
        try:
            from sigstore.models import ClientTrustConfig
            from sigstore.oidc import IdentityToken, Issuer, detect_credential
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        if not isinstance(public_key, SigstoreKey):
            raise ValueError(f"expected SigstoreKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"SigstoreSigner does not support {priv_key_uri}")

        params = dict(parse.parse_qsl(uri.query))
        ambient = params.get("ambient", "true") == "true"

        if not ambient:
            # TODO: Restrict oauth flow to use identity/issuer from public_key
            # TODO: Use secrets_handler for identity_token() secret arg
            trust_config = ClientTrustConfig.production()
            issuer = Issuer(trust_config.signing_config.get_oidc_url())
            token = issuer.identity_token()
        else:
            credential = detect_credential()
            if not credential:
                raise RuntimeError("Failed to detect Sigstore credentials")
            token = IdentityToken(credential)

        key_identity = public_key.keyval["identity"]
        key_issuer = public_key.keyval["issuer"]
        if key_issuer != token.federated_issuer:
            raise ValueError(
                f"Signer identity issuer {token.federated_issuer} "
                f"did not match key: {key_issuer}"
            )
        # TODO: should check ambient identity too: unfortunately IdentityToken does
        # not provide access to the expected identity value (cert SAN) in ambient case
        if not ambient and key_identity != token.identity:
            raise ValueError(
                f"Signer identity {token.identity} did not match key: {key_identity}"
            )

        return cls(token, public_key)

    @classmethod
    def _get_uri(cls, ambient: bool) -> str:
        return f"{cls.SCHEME}:{'' if ambient else '?ambient=false'}"

    @classmethod
    def import_(
        cls, identity: str, issuer: str, ambient: bool = True
    ) -> tuple[str, SigstoreKey]:
        """Create public key and signer URI.

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. import_() should be called once and the returned URI and public
        key should be stored for later use.

        Arguments:
            identity: The OIDC identity to use when verifying a signature.
            issuer: The OIDC issuer to use when verifying a signature.
            ambient: Toggle usage of ambient credentials in returned URI.
        """
        keytype = SigstoreKey.DEFAULT_KEY_TYPE
        scheme = SigstoreKey.DEFAULT_SCHEME
        keyval = {"identity": identity, "issuer": issuer}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        key = SigstoreKey(keyid, keytype, scheme, keyval)
        uri = cls._get_uri(ambient)

        return uri, key

    @classmethod
    def import_via_auth(cls) -> tuple[str, SigstoreKey]:
        """Create public key and signer URI by interactive authentication

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. This method always uses the interactive authentication.
        """
        try:
            from sigstore.models import ClientTrustConfig
            from sigstore.oidc import Issuer
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        # authenticate to get the identity and issuer
        trust_config = ClientTrustConfig.production()
        issuer = Issuer(trust_config.signing_config.get_oidc_url())
        token = issuer.identity_token()
        return cls.import_(token.identity, token.federated_issuer, False)

    def sign(self, payload: bytes) -> Signature:
        """Signs payload using the OIDC token on the signer instance.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from sigstore-python.

        Returns:
            Signature.

            NOTE: The relevant data is in `unrecognized_fields["bundle"]`.

        """
        try:
            from sigstore.models import ClientTrustConfig
            from sigstore.sign import SigningContext
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        context = SigningContext.from_trust_config(ClientTrustConfig.production())
        with context.signer(self._token) as sigstore_signer:
            bundle = sigstore_signer.sign_artifact(payload)
        # We want to access the actual signature, see
        # https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
        bundle_json = json.loads(bundle.to_json())
        return Signature(
            self.public_key.keyid,
            bundle_json["messageSignature"]["signature"],
            {"bundle": bundle_json},
        )

    @classmethod
    def import_github_actions(
        cls, project: str, workflow_path: str, ref: str | None = "refs/heads/main"
    ) -> tuple[str, SigstoreKey]:
        """Convenience method to build identity and issuer string for import_() from
        GitHub project and workflow path.

        Args:
            project: GitHub project name (example:
               "secure-systems-lab/securesystemslib")
            workflow_path: GitHub workflow path (example:
               ".github/workflows/online-sign.yml")
            ref: optional GitHub ref, defaults to refs/heads/main

        Returns:
            uri: string
            key: SigstoreKey

        """
        identity = f"https://github.com/{project}/{workflow_path}@{ref}"
        issuer = "https://token.actions.githubusercontent.com"
        uri, key = cls.import_(identity, issuer)

        return uri, key
