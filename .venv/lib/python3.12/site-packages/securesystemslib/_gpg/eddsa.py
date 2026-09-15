"""
<Module Name>
  eddsa.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Oct 22, 2019

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  EdDSA/ed25519 algorithm-specific handling routines for pubkey and signature
  parsing and verification.

"""

import binascii

from securesystemslib import exceptions
from securesystemslib._gpg import util as gpg_util
from securesystemslib._gpg.exceptions import PacketParsingError

CRYPTO = True
NO_CRYPTO_MSG = "EdDSA key support for GPG requires the cryptography library"
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import (
        ed25519 as pyca_ed25519,
    )
except ImportError:
    CRYPTO = False

# ECC Curve OID (see RFC4880-bis8 9.2.)
ED25519_PUBLIC_KEY_OID = bytearray.fromhex("2B 06 01 04 01 DA 47 0F 01")

# EdDSA Point Format (see RFC4880-bis8 13.3.)
ED25519_PUBLIC_KEY_LENGTH = 33
ED25519_PUBLIC_KEY_PREFIX = 0x40
# EdDSA signature byte length (see RFC 8032 5.1.6. (6))
ED25519_SIG_LENGTH = 64


def get_pubkey_params(data):
    """
    <Purpose>
      Parse algorithm-specific part for EdDSA public keys

      See RFC4880-bis8 sections 5.6.5. Algorithm-Specific Part for EdDSA Keys,
      9.2. ECC Curve OID and 13.3. EdDSA Point Format for more details.

    <Arguments>
      data:
            The EdDSA public key data AFTER the one-octet number denoting the
            public-key algorithm of this key.

    <Exceptions>
      securesystemslib._gpg.exceptions.PacketParsingError or IndexError:
            if the public key data is malformed.

    <Side Effects>
      None.

    <Returns>
      A dictionary with an element "q" that holds the ascii hex representation
      of the MPI of an EC point representing an EdDSA public key.

    """
    ptr = 0

    curve_oid_len = data[ptr]
    ptr += 1

    curve_oid = data[ptr : ptr + curve_oid_len]
    ptr += curve_oid_len

    # See 9.2. ECC Curve OID
    if curve_oid != ED25519_PUBLIC_KEY_OID:
        raise PacketParsingError(
            f"bad ed25519 curve OID '{curve_oid}', expected {ED25519_PUBLIC_KEY_OID}'"
        )

    # See 13.3. EdDSA Point Format
    public_key_len = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2

    if public_key_len != ED25519_PUBLIC_KEY_LENGTH:
        raise PacketParsingError(
            f"bad ed25519 MPI length '{public_key_len}', "
            f"expected {ED25519_PUBLIC_KEY_LENGTH}'"
        )

    public_key_prefix = data[ptr]
    ptr += 1

    if public_key_prefix != ED25519_PUBLIC_KEY_PREFIX:
        raise PacketParsingError(
            f"bad ed25519 MPI prefix '{public_key_prefix}', "
            f"expected '{ED25519_PUBLIC_KEY_PREFIX}'"
        )

    public_key = data[ptr : ptr + public_key_len - 1]

    return {"q": binascii.hexlify(public_key).decode("ascii")}


def get_signature_params(data):
    """
    <Purpose>
      Parse algorithm-specific fields for EdDSA signatures.

      See RFC4880-bis8 section 5.2.3. Version 4 and 5 Signature Packet Formats
      for more details.

    <Arguments>
      data:
            The EdDSA signature data AFTER the two-octet field holding the
            left 16 bits of the signed hash value.

    <Exceptions>
      IndexError if the signature data is malformed.

    <Side Effects>
      None.

    <Returns>
      The concatenation of the parsed MPI R and S values of the EdDSA signature,
      i.e. ENC(R) || ENC(S) (see RFC8032 3.4 Verify).

    """
    ptr = 0
    r_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])

    ptr += 2
    r = data[ptr : ptr + r_length]
    ptr += r_length

    s_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2
    s = data[ptr : ptr + s_length]

    # Left-zero-pad 'r' and 's' values that are shorter than required by RFC 8032
    # (5.1.6.), to make up for omitted leading zeros in RFC 4880 (3.2.) MPIs.
    # This is especially important for 's', which is little-endian.
    r = r.rjust(ED25519_SIG_LENGTH // 2, b"\x00")
    s = s.rjust(ED25519_SIG_LENGTH // 2, b"\x00")

    return r + s


def create_pubkey(pubkey_info):
    """
    <Purpose>
      Create and return an Ed25519PublicKey object from the passed pubkey_info
      using pyca/cryptography.

    <Arguments>
      pubkey_info:
            The ED25519 public key dict.

    <Exceptions>

      securesystemslib.exceptions.UnsupportedLibraryError if
        the cryptography module is unavailable

    <Returns>
      A cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey based
      on the passed pubkey_info.

    """
    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    public_bytes = binascii.unhexlify(pubkey_info["keyval"]["public"]["q"])
    public_key = pyca_ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

    return public_key


def verify_signature(signature_object, pubkey_info, content, hash_algorithm_id):
    """
    <Purpose>
      Verify the passed signature against the passed content with the passed
      ED25519 public key using pyca/cryptography.

    <Arguments>
      signature_object:
              A signature dict.

      pubkey_info:
              A DSA public key dict.

      hash_algorithm_id:
              one of SHA1, SHA256, SHA512 (see securesystemslib._gpg.constants)
              used to verify the signature
              NOTE: Overrides any hash algorithm specification in "pubkey_info"'s
              "hashes" or "method" fields.

      content:
              The signed bytes against which the signature is verified

    <Exceptions>
      securesystemslib.exceptions.UnsupportedLibraryError if:
        the cryptography module is unavailable

      ValueError:
        if the passed hash_algorithm_id is not supported (see
        securesystemslib._gpg.util.get_hashing_class)

    <Returns>
      True if signature verification passes and False otherwise.

    """
    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    hasher = gpg_util.get_hashing_class(hash_algorithm_id)

    pubkey_object = create_pubkey(pubkey_info)

    # See RFC4880-bis8 14.8. EdDSA and 5.2.4 "Computing Signatures"
    digest = gpg_util.hash_object(
        binascii.unhexlify(signature_object["other_headers"]), hasher(), content
    )

    try:
        pubkey_object.verify(binascii.unhexlify(signature_object["signature"]), digest)
        return True

    except InvalidSignature:
        return False
