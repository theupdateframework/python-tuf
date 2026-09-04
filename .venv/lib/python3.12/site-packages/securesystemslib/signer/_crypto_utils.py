"""Signer utils for internal use that require pyca/cryptography."""

from cryptography.hazmat.primitives.hashes import (
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    HashAlgorithm,
)


def get_hash_algorithm(name: str) -> HashAlgorithm:
    """Helper to return hash algorithm object for name."""
    if name == "sha224":
        return SHA224()
    elif name == "sha256":
        return SHA256()
    elif name == "sha384":
        return SHA384()
    elif name == "sha512":
        return SHA512()

    raise ValueError(f"Unsupported hash algorithm: {name}")
