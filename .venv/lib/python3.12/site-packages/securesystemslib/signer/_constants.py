"""Constants for supported key types and signing schemes.

These are used throughout the ``securesystemslib.signer`` package instead of
hardcoded strings. The publicly registered key type and scheme pairs are listed
in ``securesystemslib.signer.KEY_FOR_TYPE_AND_SCHEME``.
"""

#: RSA key type.
KEY_TYPE_RSA = "rsa"

#: ECDSA key type.
KEY_TYPE_ECDSA = "ecdsa"

#: Ed25519 key type. Note that Ed25519 is unsupported on many signer backends:
#: The payload cannot be hashed before signing so hardware tokens and cloud
#: KMSs generally do not support it because of payload size limitations.
KEY_TYPE_ED25519 = "ed25519"

#: ML-DSA key type. Keytype defines pre-signing hashing with SHA-512. See
#: https://github.com/theupdateframework/taps/blob/master/tap21.md
KEY_TYPE_MLDSA = "ml-dsa"

#: ECDSA signature scheme over NIST P-256 with SHA-256. Supported with key type
#: :data:`KEY_TYPE_ECDSA`.
ECDSA_SHA2_NISTP256 = "ecdsa-sha2-nistp256"

#: ECDSA signature scheme over NIST P-384 with SHA-384. Supported with key type
#: :data:`KEY_TYPE_ECDSA`.
ECDSA_SHA2_NISTP384 = "ecdsa-sha2-nistp384"

#: ECDSA signature scheme over NIST P-521 with SHA-512. Supported with key type
#: :data:`KEY_TYPE_ECDSA`.
ECDSA_SHA2_NISTP521 = "ecdsa-sha2-nistp521"

#: RSASSA-PSS signature scheme with SHA-224. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSASSA_PSS_SHA224 = "rsassa-pss-sha224"

#: RSASSA-PSS signature scheme with SHA-256. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSASSA_PSS_SHA256 = "rsassa-pss-sha256"

#: RSASSA-PSS signature scheme with SHA-384. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSASSA_PSS_SHA384 = "rsassa-pss-sha384"

#: RSASSA-PSS signature scheme with SHA-512. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSASSA_PSS_SHA512 = "rsassa-pss-sha512"

#: RSA-PKCS#1 v1.5 signature scheme with SHA-224. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSA_PKCS1V15_SHA224 = "rsa-pkcs1v15-sha224"

#: RSA-PKCS#1 v1.5 signature scheme with SHA-256. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSA_PKCS1V15_SHA256 = "rsa-pkcs1v15-sha256"

#: RSA-PKCS#1 v1.5 signature scheme with SHA-384. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSA_PKCS1V15_SHA384 = "rsa-pkcs1v15-sha384"

#: RSA-PKCS#1 v1.5 signature scheme with SHA-512. Supported with key type
#: :data:`KEY_TYPE_RSA`.
RSA_PKCS1V15_SHA512 = "rsa-pkcs1v15-sha512"

#: Ed25519 pure signature scheme . Supported with key type :data:`KEY_TYPE_ED25519`.
ED25519 = "ed25519"

#: ML-DSA-44 signature scheme. Supported with key type :data:`KEY_TYPE_MLDSA`.
MLDSA_44_1 = "ml-dsa-44/1"

#: ML-DSA-65 signature scheme. Supported with key type :data:`KEY_TYPE_MLDSA`.
MLDSA_65_1 = "ml-dsa-65/1"

#: ML-DSA-87 signature scheme. Supported with key type :data:`KEY_TYPE_MLDSA`.
MLDSA_87_1 = "ml-dsa-87/1"
