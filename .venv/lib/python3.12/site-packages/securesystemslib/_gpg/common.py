"""
<Module Name>
  common.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides algorithm-agnostic gpg public key and signature parsing functions.
  The functions select the appropriate functions for each algorithm and
  call them.

"""

import binascii
import collections
import logging
import struct

from securesystemslib._gpg import util as gpg_util
from securesystemslib._gpg.constants import (
    FULL_KEYID_SUBPACKET,
    GPG_HASH_ALGORITHM_STRING,
    KEY_EXPIRATION_SUBPACKET,
    PACKET_TYPE_PRIMARY_KEY,
    PACKET_TYPE_SIGNATURE,
    PACKET_TYPE_SUB_KEY,
    PACKET_TYPE_USER_ATTR,
    PACKET_TYPE_USER_ID,
    PARTIAL_KEYID_SUBPACKET,
    PRIMARY_USERID_SUBPACKET,
    SHA1,
    SHA256,
    SHA512,
    SIG_CREATION_SUBPACKET,
    SIGNATURE_TYPE_BINARY,
    SIGNATURE_TYPE_CERTIFICATES,
    SIGNATURE_TYPE_SUB_KEY_BINDING,
    SUPPORTED_PUBKEY_PACKET_VERSIONS,
    SUPPORTED_SIGNATURE_PACKET_VERSIONS,
)
from securesystemslib._gpg.exceptions import (
    KeyNotFoundError,
    PacketParsingError,
    PacketVersionNotSupportedError,
    SignatureAlgorithmNotSupportedError,
)
from securesystemslib._gpg.handlers import (
    SIGNATURE_HANDLERS,
    SUPPORTED_SIGNATURE_ALGORITHMS,
)

log = logging.getLogger(__name__)


def parse_pubkey_payload(data):
    """
    <Purpose>
      Parse the passed public-key packet (payload only) and construct a
      public key dictionary.

    <Arguments>
      data:
            An RFC4880 public key packet payload as described in section 5.5.2.
            (version 4) of the RFC.

            NOTE: The payload can be parsed from a full key packet (header +
            payload) by using securesystemslib._gpg.util.parse_packet_header.

            WARNING: this doesn't support armored pubkey packets, so use with
            care. pubkey packets are a little bit more complicated than the
            signature ones

    <Exceptions>
      ValueError
            If the passed public key data is empty.

      securesystemslib._gpg.exceptions.PacketVersionNotSupportedError
            If the packet version does not match
            securesystemslib._gpg.constants.SUPPORTED_PUBKEY_PACKET_VERSIONS

      securesystemslib._gpg.exceptions.SignatureAlgorithmNotSupportedError
            If the signature algorithm does not match one of
            securesystemslib._gpg.constants.SUPPORTED_SIGNATURE_ALGORITHMS

    <Side Effects>
      None.

    <Returns>
      A public key dict.

    """
    if not data:
        raise ValueError("Could not parse empty pubkey payload.")

    ptr = 0
    keyinfo = {}
    version_number = data[ptr]
    ptr += 1
    if version_number not in SUPPORTED_PUBKEY_PACKET_VERSIONS:
        raise PacketVersionNotSupportedError(
            f"Pubkey packet version '{version_number}' not supported, "
            f"must be one of {SUPPORTED_PUBKEY_PACKET_VERSIONS}"
        )

    # NOTE: Uncomment this line to decode the time of creation
    time_of_creation = struct.unpack(">I", data[ptr : ptr + 4])
    ptr += 4

    algorithm = data[ptr]

    ptr += 1

    # TODO: Should we only export keys with signing capabilities?
    # Section 5.5.2 of RFC4880 describes a public-key algorithm octet with one
    # of the values described in section 9.1 that could be used to determine the
    # capabilities. However, in case of RSA subkeys this field doesn't seem to
    # correctly encode the capabilities. It always has the value 1, i.e.
    # RSA (Encrypt or Sign).
    # For RSA public keys we would have to parse the subkey's signature created
    # with the master key, for the signature's key flags subpacket, identified
    # by the value 27 (see section 5.2.3.1.) containing a list of binary flags
    # as described in section 5.2.3.21.
    if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise SignatureAlgorithmNotSupportedError(
            f"Signature algorithm '{algorithm}' not "
            "supported, please verify that your gpg configuration is creating "
            "either DSA, RSA, or EdDSA signatures (see RFC4880 9.1. Public-Key "
            "Algorithms)."
        )

    keyinfo["type"] = SUPPORTED_SIGNATURE_ALGORITHMS[algorithm]["type"]
    keyinfo["method"] = SUPPORTED_SIGNATURE_ALGORITHMS[algorithm]["method"]
    handler = SIGNATURE_HANDLERS[keyinfo["type"]]
    keyinfo["keyid"] = gpg_util.compute_keyid(data)
    key_params = handler.get_pubkey_params(data[ptr:])

    return {
        "method": keyinfo["method"],
        "type": keyinfo["type"],
        "hashes": [GPG_HASH_ALGORITHM_STRING],
        "creation_time": time_of_creation[0],
        "keyid": keyinfo["keyid"],
        "keyval": {"private": "", "public": key_params},
    }


def parse_pubkey_bundle(data):
    """
    <Purpose>
      Parse packets from passed gpg public key data, associating self-signatures
      with the packets they correspond to, based on the structure of V4 keys
      defined in RFC4880 12.1 Key Structures.

      The returned raw key bundle may be used to further enrich the master key,
      with certified information (e.g. key expiration date) taken from
      self-signatures, and/or to verify that the parsed subkeys are bound to the
      primary key via signatures.

    <Arguments>
      data:
            Public key data as written to stdout by gpg_export_pubkey_command.

    <Exceptions>
      securesystemslib._gpg.exceptions.PacketParsingError
            If data is empty.
            If data cannot be parsed.

    <Side Effects>
      None.

    <Returns>
      A raw public key bundle where self-signatures are associated with their
      corresponding packets. See `key_bundle` for details.

    """
    if not data:
        raise PacketParsingError("Cannot parse keys from empty gpg data.")

    # Temporary data structure to hold parsed gpg packets
    key_bundle = {
        PACKET_TYPE_PRIMARY_KEY: {"key": {}, "packet": None, "signatures": []},
        PACKET_TYPE_USER_ID: collections.OrderedDict(),
        PACKET_TYPE_USER_ATTR: collections.OrderedDict(),
        PACKET_TYPE_SUB_KEY: collections.OrderedDict(),
    }

    # Iterate over gpg data and parse out packets of different types
    position = 0
    while position < len(data):
        try:
            (
                packet_type,
                header_len,
                body_len,
                packet_length,
            ) = gpg_util.parse_packet_header(data[position:])

            packet = data[position : position + packet_length]
            payload = packet[header_len:]
            # The first (and only the first) packet in the bundle must be the master
            # key.  See RFC4880 12.1 Key Structures, V4 version keys
            # TODO: Do we need additional key structure assertions? e.g.
            # - there must be least one User ID packet, or
            # - order and type of signatures, or
            # - disallow duplicate packets
            if (
                packet_type != PACKET_TYPE_PRIMARY_KEY
                and not key_bundle[PACKET_TYPE_PRIMARY_KEY]["key"]
            ):
                raise PacketParsingError(
                    "First packet must be a primary key "
                    f"('{PACKET_TYPE_PRIMARY_KEY}'), got '{packet_type}'."
                )

            if (
                packet_type == PACKET_TYPE_PRIMARY_KEY
                and key_bundle[PACKET_TYPE_PRIMARY_KEY]["key"]
            ):
                raise PacketParsingError("Unexpected primary key.")

            # Fully parse master key to fail early, e.g. if key is malformed
            # or not supported, but also retain original packet for subkey binding
            # signature verification
            if packet_type == PACKET_TYPE_PRIMARY_KEY:
                key_bundle[PACKET_TYPE_PRIMARY_KEY] = {
                    "key": parse_pubkey_payload(bytearray(payload)),
                    "packet": packet,
                    "signatures": [],
                }

            # Other non-signature packets in the key bundle include User IDs and User
            # Attributes, required to verify primary key certificates, and subkey
            # packets. For each packet we create a new ordered dictionary entry. We
            # use a dictionary to aggregate signatures by packet below,
            # and it must be ordered because each signature packet belongs to the
            # most recently parsed packet of a type.
            elif packet_type in {
                PACKET_TYPE_USER_ID,
                PACKET_TYPE_USER_ATTR,
                PACKET_TYPE_SUB_KEY,
            }:
                key_bundle[packet_type][packet] = {
                    "header_len": header_len,
                    "body_len": body_len,
                    "signatures": [],
                }

            # The remaining relevant packets are signatures, required to bind subkeys
            # to the primary key, or to gather additional information about the
            # primary key, e.g. expiration date.
            # A signature corresponds to the most recently parsed packet of a type,
            # where the type is given by the availability of respective packets.
            # We test availability and assign accordingly as per the order of packet
            # types defined in RFC4880 12.1 (bottom-up).
            elif packet_type == PACKET_TYPE_SIGNATURE:
                for _type in [
                    PACKET_TYPE_SUB_KEY,
                    PACKET_TYPE_USER_ATTR,
                    PACKET_TYPE_USER_ID,
                ]:
                    if key_bundle[_type]:
                        # Add to most recently added packet's
                        # signatures of matching type
                        key_bundle[_type][next(reversed(key_bundle[_type]))][
                            "signatures"
                        ].append(packet)
                        break

                else:
                    # If no packets are available for any of above types (yet), the
                    # signature belongs to the primary key
                    key_bundle[PACKET_TYPE_PRIMARY_KEY]["signatures"].append(packet)

            else:
                packets_list = [
                    PACKET_TYPE_PRIMARY_KEY,
                    PACKET_TYPE_USER_ID,
                    PACKET_TYPE_USER_ATTR,
                    PACKET_TYPE_SUB_KEY,
                    PACKET_TYPE_SIGNATURE,
                ]
                log.info(
                    f"Ignoring gpg key packet '{packet_type}', "
                    "we only handle packets of "
                    f"types '{packets_list}' (see RFC4880 4.3. Packet Tags)."
                )

        # Both errors might be raised in parse_packet_header and in this loop
        except (PacketParsingError, IndexError) as e:
            raise PacketParsingError(
                f"Invalid public key data at position {position}: {e}."
            )

        # Go to next packet
        position += packet_length

    return key_bundle


def _assign_certified_key_info(bundle):
    """
    <Purpose>
      Helper function to verify User ID certificates corresponding to a gpg
      master key, in order to enrich the master key with additional information
      (e.g. expiration dates). The enriched master key is returned.

      NOTE: Currently we only consider User ID certificates. We can do the same
      for User Attribute certificates by iterating over
      bundle[PACKET_TYPE_USER_ATTR] instead of bundle[PACKET_TYPE_USER_ID], and
      replacing the signed_content constant '\xb4'  with '\xd1' (see RFC4880
      section 5.2.4. paragraph 4).

    <Arguments>
      bundle:
            GPG key bundle as parsed in parse_pubkey_bundle().

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A public key dict.

    """
    # Create handler shortcut
    handler = SIGNATURE_HANDLERS[bundle[PACKET_TYPE_PRIMARY_KEY]["key"]["type"]]

    is_primary_user = False
    validity_period = None
    sig_creation_time = None

    # Verify User ID signatures to gather information about primary key
    # (see Notes about certification signatures in RFC 4880 5.2.3.3.)
    for user_id_packet, packet_data in bundle[PACKET_TYPE_USER_ID].items():
        # Construct signed content (see RFC4880 section 5.2.4. paragraph 4)
        signed_content = (
            bundle[PACKET_TYPE_PRIMARY_KEY]["packet"]
            + b"\xb4\x00\x00\x00"
            + user_id_packet[1:]
        )
        for signature_packet in packet_data["signatures"]:
            try:
                signature = parse_signature_packet(
                    signature_packet,
                    supported_hash_algorithms={SHA1, SHA256, SHA512},
                    supported_signature_types=SIGNATURE_TYPE_CERTIFICATES,
                    include_info=True,
                )
                # verify_signature requires a "keyid" even if it is short.
                # (see parse_signature_packet for more information about keyids)
                signature["keyid"] = signature["keyid"] or signature["short_keyid"]

            # TODO: Revise exception taxonomy:
            # It's okay to ignore some exceptions (unsupported algorithms etc.) but
            # we should blow up if a signature is malformed (missing subpackets).
            except Exception as e:
                log.info(e)
                continue

            if not bundle[PACKET_TYPE_PRIMARY_KEY]["key"]["keyid"].endswith(
                signature["keyid"]
            ):
                log.info(
                    "Ignoring User ID certificate issued by '{}'.".format(
                        signature["keyid"]
                    )
                )
                continue

            is_valid = handler.verify_signature(
                signature,
                bundle[PACKET_TYPE_PRIMARY_KEY]["key"],
                signed_content,
                signature["info"]["hash_algorithm"],
            )

            if not is_valid:
                log.info(
                    "Ignoring invalid User ID self-certificate issued by '{}'.".format(
                        signature["keyid"]
                    )
                )
                continue

            # If the signature is valid, we try to extract subpackets relevant to
            # the primary key, i.e. expiration time.
            # NOTE: There might be multiple User IDs per primary key and multiple
            # certificates per User ID. RFC4880 5.2.3.19. and last paragraph of
            # 5.2.3.3. provides some suggestions about ambiguity, but delegates the
            # responsibility to the implementer.

            # Ambiguity resolution scheme:
            # We take the key expiration time from the most recent certificate, i.e.
            # the certificate with the highest signature creation time. Additionally,
            # we prioritize certificates with primary user id flag set True. Note
            # that, if the ultimately prioritized certificate does not have a key
            # expiration time subpacket, we don't assign one, even if there were
            # certificates of lower priority carrying that subpacket.
            tmp_validity_period = signature["info"]["subpackets"].get(
                KEY_EXPIRATION_SUBPACKET
            )

            # No key expiration time, go to next certificate
            if tmp_validity_period is None:
                continue

            # Create shortcut to mandatory pre-parsed creation time subpacket
            tmp_sig_creation_time = signature["info"]["creation_time"]

            tmp_is_primary_user = signature["info"]["subpackets"].get(
                PRIMARY_USERID_SUBPACKET
            )

            if tmp_is_primary_user is not None:
                tmp_is_primary_user = bool(tmp_is_primary_user[0])

            # If we already have a primary user certified expiration date and this
            # is none, we don't consider it, and go to next certificate
            if is_primary_user and not tmp_is_primary_user:
                continue

            if not sig_creation_time or sig_creation_time < tmp_sig_creation_time:
                # This is the most recent certificate that has a validity_period and
                # doesn't have lower priority in regard to the primary user id flag. We
                # accept it the keys validty_period, until we get a newer value from
                # a certificate with higher priority.
                validity_period = struct.unpack(">I", tmp_validity_period)[0]
                # We also keep track of the used certificate's primary user id flag and
                # the signature creation time, for prioritization.
                is_primary_user = tmp_is_primary_user
                sig_creation_time = tmp_sig_creation_time

    if validity_period is not None:
        bundle[PACKET_TYPE_PRIMARY_KEY]["key"]["validity_period"] = validity_period

    return bundle[PACKET_TYPE_PRIMARY_KEY]["key"]


def _get_verified_subkeys(bundle):
    """
    <Purpose>
      Helper function to verify the subkey binding signature for all subkeys in
      the passed bundle in order to enrich subkeys with additional information
      (e.g. expiration dates). Only valid (i.e. parsable) subkeys that are
      verifiably bound to the the master key of the bundle are returned. All
      other subkeys are discarded.

    <Arguments>
      bundle:
            GPG key bundle as parsed in parse_pubkey_bundle().

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A dict of public keys dicts with keyids as dict keys.

    """
    # Create handler shortcut
    handler = SIGNATURE_HANDLERS[bundle[PACKET_TYPE_PRIMARY_KEY]["key"]["type"]]

    # Verify subkey binding signatures and only keep verified keys
    # See notes about subkey binding signature in RFC4880 5.2.3.3
    verified_subkeys = {}
    for subkey_packet, packet_data in bundle[PACKET_TYPE_SUB_KEY].items():
        try:
            # Parse subkey if possible and skip if invalid (e.g. not-supported)
            subkey = parse_pubkey_payload(
                bytearray(subkey_packet[-packet_data["body_len"] :])
            )

        # TODO: Revise exception taxonomy
        except Exception as e:
            log.info(e)
            continue

        # Construct signed content (see RFC4880 section 5.2.4. paragraph 3)
        signed_content = (
            bundle[PACKET_TYPE_PRIMARY_KEY]["packet"] + b"\x99" + subkey_packet[1:]
        )

        # Filter sub key binding signature from other signatures, e.g. subkey
        # binding revocation signatures
        key_binding_signatures = []
        for signature_packet in packet_data["signatures"]:
            try:
                signature = parse_signature_packet(
                    signature_packet,
                    supported_hash_algorithms={SHA1, SHA256, SHA512},
                    supported_signature_types={SIGNATURE_TYPE_SUB_KEY_BINDING},
                    include_info=True,
                )
                # verify_signature requires a "keyid" even if it is short.
                # (see parse_signature_packet for more information about keyids)
                signature["keyid"] = signature["keyid"] or signature["short_keyid"]
                key_binding_signatures.append(signature)

            # TODO: Revise exception taxonomy
            except Exception as e:
                log.info(e)
                continue
        # NOTE: As per the V4 key structure diagram in RFC4880 section 12.1., a
        # subkey must be followed by exactly one Primary-Key-Binding-Signature.
        # Based on inspection of real-world keys and other parts of the RFC (e.g.
        # the paragraph below the diagram and paragraph 0x18: Subkey Binding
        # Signature in section 5.2.1.) the mandated signature is actually a
        # *subkey binding signature*, which in case of a signing subkey, must have
        # an *embedded primary key binding signature*.
        if len(key_binding_signatures) != 1:
            log.info(
                "Ignoring subkey '{}' due to wrong amount of key binding "
                "signatures ({}), must be exactly 1.".format(
                    subkey["keyid"], len(key_binding_signatures)
                )
            )
            continue
        is_valid = handler.verify_signature(
            signature,
            bundle[PACKET_TYPE_PRIMARY_KEY]["key"],
            signed_content,
            signature["info"]["hash_algorithm"],
        )

        if not is_valid:
            log.info(
                "Ignoring subkey '{}' due to invalid key binding signature.".format(
                    subkey["keyid"]
                )
            )
            continue

        # If the signature is valid, we may also extract relevant information from
        # its "info" field (e.g. subkey expiration date) and assign to it to the
        # subkey here
        validity_period = signature["info"]["subpackets"].get(KEY_EXPIRATION_SUBPACKET)
        if validity_period is not None:
            subkey["validity_period"] = struct.unpack(">I", validity_period)[0]

        verified_subkeys[subkey["keyid"]] = subkey

    return verified_subkeys


def get_pubkey_bundle(data, keyid):
    """
    <Purpose>
      Call function to extract and verify master key and subkeys from the passed
      gpg key data, where either the master key or one of the subkeys matches the
      passed keyid.

      NOTE:
      - If the keyid matches one of the subkeys, a warning is issued to notify
        the user about potential privilege escalation
      - Subkeys with invalid key binding signatures are discarded

    <Arguments>
      data:
            Public key data as written to stdout by
            securesystemslib._gpg.constants.gpg_export_pubkey_command.

      keyid:
            The keyid of the master key or one of its subkeys expected to be
            contained in the passed gpg data.

    <Exceptions>
      securesystemslib._gpg.exceptions.PacketParsingError
            If the key data could not be parsed

      securesystemslib._gpg.exceptions.KeyNotFoundError
            If the passed data is empty.
            If no master key or subkeys could be found that matches the passed
            keyid.


    <Side Effects>
      None.

    <Returns>
      A public key dict with optional subkeys.

    """
    if not data:
        raise KeyNotFoundError(
            f"Could not find gpg key '{keyid}' in empty exported key data."
        )

    # Parse out master key and subkeys (enriched and verified via certificates
    # and binding signatures)
    raw_key_bundle = parse_pubkey_bundle(data)
    master_public_key = _assign_certified_key_info(raw_key_bundle)
    sub_public_keys = _get_verified_subkeys(raw_key_bundle)

    # Since GPG returns all pubkeys associated with a keyid (master key and
    # subkeys) we check which key matches the passed keyid.
    # If the matching key is a subkey, we warn the user because we return
    # the whole bundle (master plus all subkeys) and not only the subkey.
    # If no matching key is found we raise a KeyNotFoundError.
    for idx, public_key in enumerate(
        [master_public_key] + list(sub_public_keys.values())
    ):
        if public_key and public_key["keyid"].endswith(keyid.lower()):
            if idx > 1:
                log.debug(
                    "Exporting master key '{}' including subkeys '{}' for"
                    " passed keyid '{}'.".format(
                        master_public_key["keyid"],
                        ", ".join(list(sub_public_keys.keys())),
                        keyid,
                    )
                )
            break

    else:
        raise KeyNotFoundError(
            f"Could not find gpg key '{keyid}' in exported key data."
        )

    # Add subkeys dictionary to master pubkey "subkeys" field if subkeys exist
    if sub_public_keys:
        master_public_key["subkeys"] = sub_public_keys

    return master_public_key


# ruff: noqa: PLR0912, PLR0915
def parse_signature_packet(
    data,
    supported_signature_types=None,
    supported_hash_algorithms=None,
    include_info=False,
):
    """
    <Purpose>
      Parse the signature information on an RFC4880-encoded binary signature data
      buffer.

      NOTE: Older gpg versions (< FULLY_SUPPORTED_MIN_VERSION) might only
      reveal the partial key id. It is the callers responsibility to determine
      the full keyid based on the partial keyid, e.g. by exporting the related
      public and replacing the partial keyid with the full keyid.

    <Arguments>
      data:
             the RFC4880-encoded binary signature data buffer as described in
             section 5.2 (and 5.2.3.1).
      supported_signature_types: (optional)
            a set of supported signature_types, the signature packet may be
            (see securesystemslib._gpg.constants for available types). If None is
            specified the signature packet must be of type SIGNATURE_TYPE_BINARY.
      supported_hash_algorithms: (optional)
            a set of supported hash algorithm ids, the signature packet
            may use. Available ids are SHA1, SHA256, SHA512 (see
            securesystemslib._gpg.constants). If None is specified, the signature
            packet must use SHA256.
      include_info: (optional)
            a boolean that indicates whether an opaque dictionary should be
            added to the returned signature under the key "info". Default is
            False.

    <Exceptions>
      ValueError: if the signature packet is not supported or the data is
        malformed
      IndexError: if the signature packet is incomplete

    <Side Effects>
      None.

    <Returns>
      A signature dict with the following special characteristics:
       - The "keyid" field is an empty string if it cannot be determined
       - The "short_keyid" is not added if it cannot be determined
       - At least one of non-empty "keyid" or "short_keyid" are part of the
         signature

    """
    if not supported_signature_types:
        supported_signature_types = {SIGNATURE_TYPE_BINARY}

    if not supported_hash_algorithms:
        supported_hash_algorithms = {SHA256}

    _, header_len, _, packet_len = gpg_util.parse_packet_header(
        data, PACKET_TYPE_SIGNATURE
    )

    data = bytearray(data[header_len:packet_len])

    ptr = 0

    # we get the version number, which we also expect to be v4, or we bail
    # FIXME: support v3 type signatures (which I haven't seen in the wild)
    version_number = data[ptr]
    ptr += 1
    if version_number not in SUPPORTED_SIGNATURE_PACKET_VERSIONS:
        raise ValueError(
            f"Signature version '{version_number}' not supported, "
            f"must be one of {SUPPORTED_SIGNATURE_PACKET_VERSIONS}."
        )

    # Per default we only parse "signatures of a binary document". Other types
    # may be allowed by passing type constants via `supported_signature_types`.
    # Types include revocation signatures, key binding signatures, persona
    # certifications, etc. (see RFC 4880 section 5.2.1.).
    signature_type = data[ptr]
    ptr += 1

    if signature_type not in supported_signature_types:
        raise ValueError(
            f"Signature type '{signature_type}' not supported, "
            f"must be one of {supported_signature_types} "
            "(see RFC4880 5.2.1. Signature Types)."
        )

    signature_algorithm = data[ptr]
    ptr += 1

    if signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError(
            f"Signature algorithm '{signature_algorithm}' not "
            "supported, please verify that your gpg configuration is creating "
            "either DSA, RSA, or EdDSA signatures (see RFC4880 9.1. Public-Key "
            "Algorithms)."
        )

    key_type = SUPPORTED_SIGNATURE_ALGORITHMS[signature_algorithm]["type"]
    handler = SIGNATURE_HANDLERS[key_type]

    hash_algorithm = data[ptr]
    ptr += 1

    if hash_algorithm not in supported_hash_algorithms:
        raise ValueError(
            f"Hash algorithm '{hash_algorithm}' not supported, "
            f"must be one of {supported_hash_algorithms} "
            "(see RFC4880 9.4. Hash Algorithms)."
        )

    # Obtain the hashed octets
    hashed_octet_count = struct.unpack(">H", data[ptr : ptr + 2])[0]
    ptr += 2
    hashed_subpackets = data[ptr : ptr + hashed_octet_count]
    hashed_subpacket_info = gpg_util.parse_subpackets(hashed_subpackets)

    if len(hashed_subpackets) != hashed_octet_count:  # pragma: no cover
        raise ValueError(
            "Signature packet contains an unexpected amount of hashed octets"
        )

    ptr += hashed_octet_count
    other_headers_ptr = ptr

    unhashed_octet_count = struct.unpack(">H", data[ptr : ptr + 2])[0]
    ptr += 2

    unhashed_subpackets = data[ptr : ptr + unhashed_octet_count]
    unhashed_subpacket_info = gpg_util.parse_subpackets(unhashed_subpackets)

    ptr += unhashed_octet_count

    # Use the info dict to return further signature information that may be
    # needed for intermediate processing, but does not have to be on the eventual
    # signature datastructure
    info = {
        "signature_type": signature_type,
        "hash_algorithm": hash_algorithm,
        "creation_time": None,
        "subpackets": {},
    }

    keyid = ""
    short_keyid = ""

    # Parse "Issuer" (short keyid) and "Issuer Fingerprint" (full keyid) type
    # subpackets
    # Strategy: Loop over all unhashed and hashed subpackets (in that order!) and
    # store only the last of a type. Due to the order in the loop, hashed
    # subpackets are prioritized over unhashed subpackets (see NOTEs below).

    # NOTE: A subpacket may be found either in the hashed or unhashed subpacket
    # sections of a signature. If a subpacket is not hashed, then the information
    # in it cannot be considered definitive because it is not part of the
    # signature proper. (see RFC4880 5.2.3.2.)
    # NOTE: Signatures may contain conflicting information in subpackets. In most
    # cases, an implementation SHOULD use the last subpacket, but MAY use any
    # conflict resolution scheme that makes more sense. (see RFC4880 5.2.4.1.)
    for idx, subpacket_tuple in enumerate(
        unhashed_subpacket_info + hashed_subpacket_info
    ):
        # The idx indicates if the info is from the unhashed (first) or
        # hashed (second) of the above concatenated lists
        is_hashed = idx >= len(unhashed_subpacket_info)
        subpacket_type, subpacket_data = subpacket_tuple

        # Warn if expiration subpacket is not hashed
        if subpacket_type == KEY_EXPIRATION_SUBPACKET:
            if not is_hashed:
                log.warning(
                    "Expiration subpacket not hashed, gpg client possibly "
                    "exporting a weakly configured key."
                )

        # Full keyids are only available in newer signatures
        # (see RFC4880 and rfc4880bis-06 5.2.3.1.)
        if subpacket_type == FULL_KEYID_SUBPACKET:  # pragma: no cover
            # Exclude from coverage for consistent results across test envs
            # NOTE: The first byte of the subpacket payload is a version number
            # (see rfc4880bis-06 5.2.3.28.)
            keyid = binascii.hexlify(subpacket_data[1:]).decode("ascii")

        # We also return the short keyid, because the full might not be available
        if subpacket_type == PARTIAL_KEYID_SUBPACKET:
            short_keyid = binascii.hexlify(subpacket_data).decode("ascii")

        if subpacket_type == SIG_CREATION_SUBPACKET:
            info["creation_time"] = struct.unpack(">I", subpacket_data)[0]

        info["subpackets"][subpacket_type] = subpacket_data

    # Fail if there is no keyid at all (this should not happen)
    if not (keyid or short_keyid):  # pragma: no cover
        raise ValueError(
            "This signature packet seems to be corrupted. It does "
            "not have an 'Issuer' or 'Issuer Fingerprint' subpacket (see RFC4880 "
            "and rfc4880bis-06 5.2.3.1. Signature Subpacket Specification)."
        )

    # Fail if keyid and short keyid are specified but don't match
    if keyid and not keyid.endswith(short_keyid):  # pragma: no cover
        raise ValueError(
            "This signature packet seems to be corrupted. The key ID "
            f"'{short_keyid}' of the 'Issuer' subpacket must match the "
            f"lower 64 bits of the fingerprint '{keyid}' of the 'Issuer "
            "Fingerprint' subpacket (see RFC4880 and rfc4880bis-06 5.2.3.28. "
            "Issuer Fingerprint)."
        )

    if not info["creation_time"]:  # pragma: no cover
        raise ValueError(
            "This signature packet seems to be corrupted. It does "
            "not have a 'Signature Creation Time' subpacket (see RFC4880 5.2.3.4 "
            "Signature Creation Time)."
        )

    # Uncomment this variable to obtain the left-hash-bits information (used for
    # early rejection)
    # left_hash_bits = struct.unpack(">H", data[ptr:ptr+2])[0]
    ptr += 2

    # Finally, fetch the actual signature (as opposed to signature metadata).
    signature = handler.get_signature_params(data[ptr:])

    signature_data = {
        "keyid": keyid,
        "other_headers": binascii.hexlify(data[:other_headers_ptr]).decode("ascii"),
        "signature": binascii.hexlify(signature).decode("ascii"),
    }

    if short_keyid:  # pragma: no branch
        signature_data["short_keyid"] = short_keyid

    if include_info:
        signature_data["info"] = info

    return signature_data
