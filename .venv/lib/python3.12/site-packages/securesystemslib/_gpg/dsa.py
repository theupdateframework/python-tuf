"""
<Module Name>
  dsa.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  DSA-specific handling routines for signature verification and key parsing
"""

import binascii

CRYPTO = True
NO_CRYPTO_MSG = "DSA key support for GPG requires the cryptography library"
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat import backends
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.hazmat.primitives.asymmetric import utils as dsautils
except ImportError:
    CRYPTO = False

# ruff: noqa: E402
from securesystemslib import exceptions
from securesystemslib._gpg import util as gpg_util
from securesystemslib._gpg.exceptions import PacketParsingError


def create_pubkey(pubkey_info):
    """
    <Purpose>
      Create and return a DSAPublicKey object from the passed pubkey_info
      using pyca/cryptography.

    <Arguments>
      pubkey_info:
              The DSA pubkey dict.

    <Exceptions>
      securesystemslib.exceptions.UnsupportedLibraryError if
        the cryptography module is not available

    <Returns>
      A cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey based on the
      passed pubkey_info.

    """
    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    y = int(pubkey_info["keyval"]["public"]["y"], 16)
    g = int(pubkey_info["keyval"]["public"]["g"], 16)
    p = int(pubkey_info["keyval"]["public"]["p"], 16)
    q = int(pubkey_info["keyval"]["public"]["q"], 16)
    parameter_numbers = dsa.DSAParameterNumbers(p, q, g)
    pubkey = dsa.DSAPublicNumbers(y, parameter_numbers).public_key(
        backends.default_backend()
    )

    return pubkey


def get_pubkey_params(data):
    """
    <Purpose>
      Parse the public-key parameters as multi-precision-integers.

    <Arguments>
      data:
             the RFC4880-encoded public key parameters data buffer as described
             in the fifth paragraph of section 5.5.2.

    <Exceptions>
      securesystemslib._gpg.exceptions.PacketParsingError:
             if the public key parameters are malformed

    <Side Effects>
      None.

    <Returns>
      A DSA public key dict.

    """
    ptr = 0

    prime_p_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2
    prime_p = data[ptr : ptr + prime_p_length]
    if len(prime_p) != prime_p_length:  # pragma: no cover
        raise PacketParsingError("This MPI was truncated!")
    ptr += prime_p_length

    group_order_q_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2
    group_order_q = data[ptr : ptr + group_order_q_length]
    if len(group_order_q) != group_order_q_length:  # pragma: no cover
        raise PacketParsingError("This MPI has been truncated!")
    ptr += group_order_q_length

    generator_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2
    generator = data[ptr : ptr + generator_length]
    if len(generator) != generator_length:  # pragma: no cover
        raise PacketParsingError("This MPI has been truncated!")
    ptr += generator_length

    value_y_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2
    value_y = data[ptr : ptr + value_y_length]
    if len(value_y) != value_y_length:  # pragma: no cover
        raise PacketParsingError("This MPI has been truncated!")

    return {
        "y": binascii.hexlify(value_y).decode("ascii"),
        "p": binascii.hexlify(prime_p).decode("ascii"),
        "g": binascii.hexlify(generator).decode("ascii"),
        "q": binascii.hexlify(group_order_q).decode("ascii"),
    }


def get_signature_params(data):
    """
    <Purpose>
      Parse the signature parameters as multi-precision-integers.

    <Arguments>
      data:
             the RFC4880-encoded signature data buffer as described
             in the fourth paragraph of section 5.2.2

    <Exceptions>
      securesystemslib._gpg.exceptions.PacketParsingError:
             if the public key parameters are malformed

      securesystemslib.exceptions.UnsupportedLibraryError:
             if the cryptography module is not available

    <Side Effects>
      None.

    <Returns>
      The decoded signature buffer
    """
    if not CRYPTO:  # pragma: no cover
        return exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    ptr = 0
    r_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2
    r = data[ptr : ptr + r_length]
    if len(r) != r_length:  # pragma: no cover
        raise PacketParsingError("r-value truncated in signature")
    ptr += r_length

    s_length = gpg_util.get_mpi_length(data[ptr : ptr + 2])
    ptr += 2
    s = data[ptr : ptr + s_length]
    if len(s) != s_length:  # pragma: no cover
        raise PacketParsingError("s-value truncated in signature")

    s = int(binascii.hexlify(s), 16)
    r = int(binascii.hexlify(r), 16)

    signature = dsautils.encode_dss_signature(r, s)

    return signature


def verify_signature(signature_object, pubkey_info, content, hash_algorithm_id):
    """
    <Purpose>
      Verify the passed signature against the passed content with the passed
      DSA public key using pyca/cryptography.

    <Arguments>
      signature_object:
              A signature dict.

      pubkey_info:
              The DSA public key dict.

      hash_algorithm_id:
              one of SHA1, SHA256, SHA512 (see securesystemslib._gpg.constants)
              used to verify the signature
              NOTE: Overrides any hash algorithm specification in "pubkey_info"'s
              "hashes" or "method" fields.

      content:
              The signed bytes against which the signature is verified

    <Exceptions>
      securesystemslib.exceptions.UnsupportedLibraryError if:
        the cryptography module is not available

      ValueError:
        if the passed hash_algorithm_id is not supported (see
        securesystemslib._gpg.util.get_hashing_class)

    <Returns>
      True if signature verification passes and False otherwise

    """
    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    hasher = gpg_util.get_hashing_class(hash_algorithm_id)

    pubkey_object = create_pubkey(pubkey_info)

    digest = gpg_util.hash_object(
        binascii.unhexlify(signature_object["other_headers"]), hasher(), content
    )

    try:
        pubkey_object.verify(
            binascii.unhexlify(signature_object["signature"]),
            digest,
            dsautils.Prehashed(hasher()),
        )
        return True
    except InvalidSignature:
        return False
