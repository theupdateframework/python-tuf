"""
The Signer API

This module provides extensible interfaces for public keys and signers:
Some implementations are provided by default but more can be added by users.
"""

# ruff: noqa: F401
from securesystemslib.signer._aws_signer import AWSSigner
from securesystemslib.signer._azure_signer import AzureSigner
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
from securesystemslib.signer._crypto_signer import CryptoSigner
from securesystemslib.signer._gcp_signer import GCPSigner
from securesystemslib.signer._gpg_signer import GPGKey, GPGSigner
from securesystemslib.signer._hsm_signer import HSMSigner
from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME, Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import (
    SIGNER_FOR_URI_SCHEME,
    SecretsHandler,
    Signer,
)
from securesystemslib.signer._sigstore_signer import SigstoreKey, SigstoreSigner
from securesystemslib.signer._spx_signer import (
    SpxKey,
    SpxSigner,
    generate_spx_key_pair,
)
from securesystemslib.signer._tkey_signer import TKeySigner
from securesystemslib.signer._vault_signer import VaultSigner

# Register supported private key uri schemes and the Signers implementing them
SIGNER_FOR_URI_SCHEME.update(
    {
        CryptoSigner.SCHEME: CryptoSigner,
        GCPSigner.SCHEME: GCPSigner,
        HSMSigner.SCHEME: HSMSigner,
        GPGSigner.SCHEME: GPGSigner,
        AzureSigner.SCHEME: AzureSigner,
        AWSSigner.SCHEME: AWSSigner,
        VaultSigner.SCHEME: VaultSigner,
        TKeySigner.SCHEME: TKeySigner,
    }
)

# Signers with currently unstable metadata formats, not supported by default:
#   SigstoreSigner,
#   SpxSigner (also does not yet support private key uri scheme)

# Register supported key types and schemes, and the Keys implementing them
KEY_FOR_TYPE_AND_SCHEME.update(
    {
        (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP256): SSlibKey,
        (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP384): SSlibKey,
        (KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP521): SSlibKey,
        # Deprecated: legacy keytype strings (keytype == scheme), use KEY_TYPE_ECDSA
        (ECDSA_SHA2_NISTP256, ECDSA_SHA2_NISTP256): SSlibKey,
        (ECDSA_SHA2_NISTP384, ECDSA_SHA2_NISTP384): SSlibKey,
        (ECDSA_SHA2_NISTP521, ECDSA_SHA2_NISTP521): SSlibKey,
        (KEY_TYPE_ED25519, ED25519): SSlibKey,
        (KEY_TYPE_RSA, RSASSA_PSS_SHA256): SSlibKey,
        (KEY_TYPE_RSA, RSASSA_PSS_SHA384): SSlibKey,
        (KEY_TYPE_RSA, RSASSA_PSS_SHA512): SSlibKey,
        (KEY_TYPE_RSA, RSA_PKCS1V15_SHA256): SSlibKey,
        (KEY_TYPE_RSA, RSA_PKCS1V15_SHA384): SSlibKey,
        (KEY_TYPE_RSA, RSA_PKCS1V15_SHA512): SSlibKey,
        (KEY_TYPE_RSA, "pgp+rsa-pkcsv1.5"): GPGKey,
        ("dsa", "pgp+dsa-fips-180-2"): GPGKey,
        ("eddsa", "pgp+eddsa-ed25519"): GPGKey,
    }
)

# Keys with currently unstable metadata formats, not supported by default:
#       (KEY_TYPE_MLDSA, MLDSA_44_1): SSlibKey,  # ML-DSA keytype defined in https://github.com/theupdateframework/taps/blob/master/tap21.md
#       (KEY_TYPE_MLDSA, MLDSA_65_1): SSlibKey,
#       (KEY_TYPE_MLDSA, MLDSA_87_1): SSlibKey,
#       ("sphincs", "sphincs-shake-128s"): SpxKey,
#       ("sigstore-oidc", "Fulcio"): SigstoreKey,
