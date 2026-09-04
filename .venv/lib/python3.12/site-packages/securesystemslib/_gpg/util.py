"""
<Module Name>
  util.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  general-purpose utilities for binary data handling and pgp data parsing
"""

# ruff: noqa: PLR2004
# (disbales "Magic value used in comparison", like on line 150)

import binascii
import logging
import struct

CRYPTO = True
NO_CRYPTO_MSG = "gpg.utils requires the cryptography library"
try:
    from cryptography.hazmat import backends
    from cryptography.hazmat.primitives import hashes as hashing
except ImportError:
    CRYPTO = False

# ruff: noqa: E402
from securesystemslib import exceptions
from securesystemslib._gpg import constants
from securesystemslib._gpg.exceptions import PacketParsingError

log = logging.getLogger(__name__)


def get_mpi_length(data):
    """
    <Purpose>
      parses an MPI (Multi-Precision Integer) buffer and returns the appropriate
      length. This is mostly done to perform bitwise to byte-wise conversion.

      See RFC4880 section 3.2. Multiprecision Integers for details.

    <Arguments>
      data: The MPI data

    <Exceptions>
      None

    <Side Effects>
      None

    <Returns>
      The length of the MPI contained at the beginning of this data buffer.
    """
    bitlength = int(struct.unpack(">H", data)[0])
    # Notice the /8 at the end, this length is the bitlength, not the length of
    # the data in bytes (as len reports it)
    return int((bitlength - 1) / 8) + 1


def hash_object(headers, algorithm, content):
    """
    <Purpose>
      Hash data prior to signature verification in conformance of the RFC4880
      openPGP standard.

    <Arguments>
      headers: the additional OpenPGP headers as populated from
      gpg_generate_signature

      algorithm: The hash algorithm object defined by the cryptography.io hashes
      module

      content: the signed content

    <Exceptions>
      securesystemslib.exceptions.UnsupportedLibraryError if:
        the cryptography module is unavailable

    <Side Effects>
      None

    <Returns>
      The RFC4880-compliant hashed buffer
    """
    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    # As per RFC4880 Section 5.2.4., we need to hash the content,
    # signature headers and add a very opinionated trailing header
    hasher = hashing.Hash(algorithm, backend=backends.default_backend())
    hasher.update(content)
    hasher.update(headers)
    hasher.update(b"\x04\xff")
    hasher.update(struct.pack(">I", len(headers)))

    return hasher.finalize()


def parse_packet_header(data, expected_type=None):  # noqa: PLR0912
    """
    <Purpose>
      Parse out packet type and header and body lengths from an RFC4880 packet.

    <Arguments>
      data:
              An RFC4880 packet as described in section 4.2 of the rfc.

      expected_type: (optional)
              Used to error out if the packet does not have the expected
              type. See securesystemslib._gpg.constants.PACKET_TYPE_* for
              available types.

    <Exceptions>
      securesystemslib._gpg.exceptions.PacketParsingError
              If the new format packet length encodes a partial body length
              If the old format packet length encodes an indeterminate length
              If header or body length could not be determined
              If the expected_type was passed and does not match the packet type

      IndexError
              If the passed data is incomplete

    <Side Effects>
      None.

    <Returns>
      A tuple of packet type, header length, body length and packet length.
      (see  RFC4880 4.3. for the list of available packet types)

    """
    data = bytearray(data)
    header_len = None
    body_len = None

    # If Bit 6 of 1st octet is set we parse a New Format Packet Length, and
    # an Old Format Packet Lengths otherwise
    if data[0] & 0b01000000:
        # In new format packet lengths the packet type is encoded in Bits 5-0 of
        # the 1st octet of the packet
        packet_type = data[0] & 0b00111111

        # The rest of the packet header is the body length header, which may
        # consist of one, two or five octets. To disambiguate the RFC, the first
        # octet of the body length header is the second octet of the packet.
        if data[1] < 192:
            header_len = 2
            body_len = data[1]

        elif data[1] >= 192 and data[1] <= 223:
            header_len = 3
            body_len = (data[1] - 192 << 8) + data[2] + 192

        elif data[1] >= 224 and data[1] < 255:
            raise PacketParsingError(
                "New length format packets of partial body lengths are not supported"
            )

        elif data[1] == 255:
            header_len = 6
            body_len = data[2] << 24 | data[3] << 16 | data[4] << 8 | data[5]

        else:  # pragma: no cover
            # Unreachable: octet must be between 0 and 255
            raise PacketParsingError("Invalid new length")

    else:
        # In old format packet lengths the packet type is encoded in Bits 5-2 of
        # the 1st octet and the length type in Bits 1-0
        packet_type = (data[0] & 0b00111100) >> 2
        length_type = data[0] & 0b00000011

        # The body length is encoded using one, two, or four octets, starting
        # with the second octet of the packet
        if length_type == 0:
            body_len = data[1]
            header_len = 2

        elif length_type == 1:
            header_len = 3
            body_len = struct.unpack(">H", data[1:header_len])[0]

        elif length_type == 2:
            header_len = 5
            body_len = struct.unpack(">I", data[1:header_len])[0]

        elif length_type == 3:
            raise PacketParsingError(
                "Old length format packets of indeterminate length are not supported"
            )

        else:  # pragma: no cover (unreachable)
            # Unreachable: bits 1-0 must be one of 0 to 3
            raise PacketParsingError("Invalid old length")

    if header_len is None or body_len is None:  # pragma: no cover
        # Unreachable: One of above must have assigned lengths or raised error
        raise PacketParsingError("Could not determine packet length")

    if expected_type is not None and packet_type != expected_type:
        raise PacketParsingError(
            f"Expected packet {expected_type}, but got {packet_type} instead!"
        )

    return packet_type, header_len, body_len, header_len + body_len


def compute_keyid(pubkey_packet_data):
    """
    <Purpose>
      compute a keyid from an RFC4880 public-key buffer

    <Arguments>
      pubkey_packet_data: the public-key packet buffer

    <Exceptions>
      securesystemslib.exceptions.UnsupportedLibraryError if:
        the cryptography module is unavailable

    <Side Effects>
      None

    <Returns>
      The RFC4880-compliant hashed buffer
    """
    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    hasher = hashing.Hash(
        hashing.SHA1(),  # noqa: S303
        backend=backends.default_backend(),
    )
    hasher.update(b"\x99")
    hasher.update(struct.pack(">H", len(pubkey_packet_data)))
    hasher.update(bytes(pubkey_packet_data))
    return binascii.hexlify(hasher.finalize()).decode("ascii")


def parse_subpacket_header(data):
    """Parse out subpacket header as per RFC4880 5.2.3.1. Signature Subpacket
    Specification."""
    # NOTE: Although the RFC does not state it explicitly, the length encoded
    # in the header must be greater equal 1, as it includes the mandatory
    # subpacket type octet.
    # Hence, passed bytearrays like [0] or [255, 0, 0, 0, 0], which encode a
    # subpacket length 0  are invalid.
    # The caller has to deal with the resulting IndexError.
    if data[0] < 192:
        length_len = 1
        length = data[0]

    elif data[0] >= 192 and data[0] < 255:
        length_len = 2
        length = (data[0] - 192 << 8) + (data[1] + 192)

    elif data[0] == 255:
        length_len = 5
        length = struct.unpack(">I", data[1:length_len])[0]

    else:  # pragma: no cover (unreachable)
        raise PacketParsingError("Invalid subpacket header")

    return data[length_len], length_len + 1, length - 1, length_len + length


def parse_subpackets(data):
    """
    <Purpose>
      parse the subpackets fields

    <Arguments>
      data: the unparsed subpacketoctets

    <Exceptions>
      IndexErrorif the subpackets octets are incomplete or malformed

    <Side Effects>
      None

    <Returns>
      A list of tuples with like:
          [ (packet_type, data),
            (packet_type, data),
            ...
          ]
    """
    parsed_subpackets = []
    position = 0

    while position < len(data):
        subpacket_type, header_len, _, subpacket_len = parse_subpacket_header(
            data[position:]
        )

        payload = data[position + header_len : position + subpacket_len]
        parsed_subpackets.append((subpacket_type, payload))

        position += subpacket_len

    return parsed_subpackets


def get_hashing_class(hash_algorithm_id):
    """
    <Purpose>
      Return a pyca/cryptography hashing class reference for the passed RFC4880
      hash algorithm ID.

    <Arguments>
      hash_algorithm_id:
              one of SHA1, SHA256, SHA512 (see securesystemslib._gpg.constants)

    <Exceptions>
      ValueError
              if the passed hash_algorithm_id is not supported.

    <Returns>
      A pyca/cryptography hashing class

    """
    supported_hashing_algorithms = [
        constants.SHA1,
        constants.SHA256,
        constants.SHA512,
    ]
    corresponding_hashing_classes = [
        hashing.SHA1,
        hashing.SHA256,
        hashing.SHA512,
    ]

    # Map supported hash algorithm ids to corresponding hashing classes
    hashing_class = dict(
        zip(supported_hashing_algorithms, corresponding_hashing_classes)
    )

    try:
        return hashing_class[hash_algorithm_id]

    except KeyError:
        raise ValueError(
            f"Hash algorithm '{hash_algorithm_id}' not supported, "
            f"must be one of '{supported_hashing_algorithms}' "
            "(see RFC4880 9.4. Hash Algorithms)."
        )
