"""Signer implementation for OpenPGP"""

from __future__ import annotations

import logging
from typing import Any
from urllib import parse

from securesystemslib import exceptions
from securesystemslib._gpg import constants as gpg_constants
from securesystemslib._gpg import exceptions as gpg_exceptions
from securesystemslib._gpg import functions as gpg
from securesystemslib.signer._key import Key
from securesystemslib.signer._signer import SecretsHandler, Signature, Signer

logger = logging.getLogger(__name__)


class GPGKey(Key):
    """OpenPGP Key.

    *All parameters named below are not just constructor arguments but also
    instance attributes.*

    Attributes:
        keyid: Key identifier that is unique within the metadata it is used in.
                It is also used to identify the GnuPG local user signing key.
        ketytype:  Key type, e.g. "rsa", "dsa" or "eddsa".
        scheme: Signing schemes, e.g. "pgp+rsa-pkcsv1.5", "pgp+dsa-fips-180-2",
                "pgp+eddsa-ed25519".
        keyval: Opaque key content.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by Securesystemslib
    """

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> GPGKey:
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            if not gpg.verify_signature(
                GPGSigner._sig_to_legacy_dict(signature),
                GPGSigner._key_to_legacy_dict(self),
                data,
            ):
                raise exceptions.UnverifiedSignatureError(
                    f"Failed to verify signature by {self.keyid}"
                )
        except (exceptions.UnsupportedLibraryError,) as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise exceptions.VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e


class GPGSigner(Signer):
    """OpenPGP Signer

    Runs command in ``GNUPG`` environment variable to sign. Fallback commands are
    ``gpg2`` and ``gpg``.

    Supported signing schemes are: "pgp+rsa-pkcsv1.5", "pgp+dsa-fips-180-2" and
    "pgp+eddsa-ed25519", with SHA-256 hashing.

    GPGSigner can be instantiated with Signer.from_priv_key_uri(). These private key URI
    schemes are supported:

    * "gnupg:[<GnuPG homedir>]":
        Signs with GnuPG key in keyring in home dir. The signing key is
        identified with the keyid of the passed public key. If homedir is not
        passed, the default homedir is used.

    Arguments:
        public_key: The related public key instance.
        homedir: GnuPG home directory path. If not passed, the default homedir is used.

    """

    SCHEME = "gnupg"

    def __init__(
        self,
        public_key: Key,
        homedir: str | None = None,
    ):
        self.homedir = homedir
        self._public_key = public_key

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> GPGSigner:
        if not isinstance(public_key, GPGKey):
            raise ValueError(f"expected GPGKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"GPGSigner does not support {priv_key_uri}")

        homedir = uri.path or None

        return cls(public_key, homedir)

    @staticmethod
    def _sig_to_legacy_dict(sig: Signature) -> dict:
        """Helper to convert Signature to internal gpg signature dict format."""
        sig_dict = sig.to_dict()
        sig_dict["signature"] = sig_dict.pop("sig")
        return sig_dict

    @staticmethod
    def _sig_from_legacy_dict(sig_dict: dict) -> Signature:
        """Helper to convert internal gpg signature format to Signature."""
        sig_dict["sig"] = sig_dict.pop("signature")
        return Signature.from_dict(sig_dict)

    @staticmethod
    def _key_to_legacy_dict(key: GPGKey) -> dict[str, Any]:
        """Returns legacy dictionary representation of self."""
        return {
            "keyid": key.keyid,
            "type": key.keytype,
            "method": key.scheme,
            "hashes": [gpg_constants.GPG_HASH_ALGORITHM_STRING],
            "keyval": key.keyval,
        }

    @staticmethod
    def _key_from_legacy_dict(key_dict: dict[str, Any]) -> GPGKey:
        """Create GPGKey from legacy dictionary representation."""
        keyid = key_dict["keyid"]
        keytype = key_dict["type"]
        scheme = key_dict["method"]
        keyval = key_dict["keyval"]

        return GPGKey(keyid, keytype, scheme, keyval)

    @classmethod
    def import_(cls, keyid: str, homedir: str | None = None) -> tuple[str, Key]:
        """Load key and signer details from GnuPG keyring.

        NOTE: Information about the key validity (expiration, revocation, etc.)
        is discarded at import and not considered when verifying a signature.

        Args:
            keyid: GnuPG local user signing key id.
            homedir: GnuPG home directory path. If not passed, the default homedir is
                    used.

        Raises:
            UnsupportedLibraryError: The gpg command or pyca/cryptography are
                not available.
            ValueError: No key was found for the passed keyid.

        Returns:
            Tuple of private key uri and the public key.

        """
        uri = f"{cls.SCHEME}:{homedir or ''}"

        try:
            raw_key = gpg.export_pubkey(keyid, homedir)

        except gpg_exceptions.KeyNotFoundError as e:
            raise ValueError(e) from e

        raw_keys = [raw_key] + list(raw_key.pop("subkeys", {}).values())
        keyids = []

        for key in raw_keys:
            if key["keyid"] == keyid:
                # TODO: Raise here if key is expired, revoked, incapable, ...
                public_key = cls._key_from_legacy_dict(key)
                break
            keyids.append(key["keyid"])

        else:
            raise ValueError(
                f"No exact match found for passed keyid {keyid}, found: {keyids}."
            )

        return (uri, public_key)

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with GnuPG.

        Arguments:
            payload: bytes to be signed.

        Raises:
            ValueError: gpg command failed to create a valid signature, e.g.
                because its keyid does not match the public key keyid.
            OSError: gpg command is not present, or non-executable, or returned
                a non-zero exit code.
            securesystemslib.exceptions.UnsupportedLibraryError: gpg command is not
                available, or the cryptography library is not installed.

        Returns:
            Signature.

        """
        try:
            raw_sig = gpg.create_signature(payload, self.public_key.keyid, self.homedir)
        except gpg_exceptions.KeyNotFoundError as e:
            raise ValueError(e) from e

        if raw_sig["keyid"] != self.public_key.keyid:
            raise ValueError(
                f"The signing key {raw_sig['keyid']} does not"
                f" match the attached public key {self.public_key.keyid}."
            )

        return self._sig_from_legacy_dict(raw_sig)
