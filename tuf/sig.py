#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  sig.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 28, 2012.   Based on a previous version by Geremy Condra.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  sig provides a higher-level signature handling interface for tuf.updater,
  tuf.repository_lib, and tuf.developer_tool.  Lower-level functionality used
  here comes primarily from securesystemslib, tuf.roledb, and tuf.keydb.

  sig also helps isolate signature-over-encoding issues from the rest of TUF.
  Signatures should be made and verified over the serialized form of metadata,
  which may or may not be JSON.  If signatures over ASN.1/DER metadata need to
  be handled, that is abstracted away here.


<Public Functions>
  NOTE that EVERY function in this module abstracts away serialization format,
  attempting to handles metadata in the form of BOTH ASN1 (asn1crypto objects
  of classes defined in tuf.encoding.asn1_definitions) AND JSON-compatible
  dictionaries (matching tuf.formats.ANYROLE_SCHEMA).

  These are provided from lowest to highest level:


  HELPER FUNCTIONS:

    is_top_level_role()
      True if the given rolename is a top-level role's name (root, targets,
      etc.)

    check_is_serializable_role_metadata()
      makes sure that the given data is serializable TUF role metadata in
      either a JSON-compatible dictionary or an asn1crypto ASN1 object.


  SINGLE SIGNATURE MANIPULATION:

    create_signature_over_metadata()
      given key and data, wraps securesystemslib.keys.create_signature(),
      creating a signature over given TUF role metadata, which it first
      canonicalizes and serializes, handling either ASN.1 or JSON- compatible
      formats.

    verify_signature_over_metadata()
      given key, signature, and data, wraps
      securesystemslib.keys.verify_signature(), verifying a signature over
      given TUF role metadata by a given key.  It first canonicalizes and
      serializes the role metadata, handling either ASN.1 or JSON-compatible
      formats.


  FULL METADATA VERIFICATION:

    get_signature_status()
      Analyzes the signatures included in given role metadata that includes
      signatures, taking arguments that convey the expected keyids and
      threshold for those signatures (either directly or in the form of a
      rolename to look up in roledb), produces a report of the validity of the
      signatures provided in the metadata indicating whether or not they
      correctly sign the given metadata and whether or each signature is from
      an authorized key.

    verify_signable()
      Verifies a full piece of role metadata, returning True if the given role
      metadata is verified (signed by at least enough correct signatures from
      authorized keys to meet the threshold expected for this metadata) and
      False otherwise.  It uses get_signature_status() to glean the status of
      each signature.

"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import logging

import tuf
import tuf.keydb
import tuf.roledb
import tuf.formats

import securesystemslib
import securesystemslib.keys

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.sig')

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True


def _is_top_level_role(rolename):
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
  return rolename.lower() in ['root', 'timestamp', 'snapshot', 'targets']


def check_is_serializable_role_metadata(data):
  """
  # TODO: write good docstring

  raises an appropriate error if the provided data is neither permitted format
  for TUF metadata:
    - JSON-compatible role dictionary conforming to tuf.formats.ANYROLE_SCHEMA
    - asn1crypto object, instance of one of the four role types defined in
      tuf.encoding.asn1_definitions (e.g TargetsMetadata).
  """

  if isinstance(data, dict):
    # Assume JSON-compatible metadata conforming to TUF specification.
    tuf.formats.ANYROLE_SCHEMA.check_match(data)

  elif isinstance(data, asn1core.Sequence):
    # Assume ASN.1 metadata conforming to tuf.encoding.asn1_metadata_definitions
    if not (isinstance(data, asn1defs.TargetsMetadata)
        or isinstance(data, asn1defs.RootMetadata)
        or isinstance(data, asn1defs.TimestampMetadata)
        or isinstance(data, asn1defs.SnapshotMetadata)):
      raise tuf.exceptions.FormatError('Unrecognized ASN1 metadata object.')


  else:
    raise tuf.exceptions.FormatError(
        'Unrecognized metadata object.  Expecting dictionary or asn1crypto '
        'object. Received object of type: ' + str(type(data)) + ', with '
        'value: ' + repr(data))





def create_signature_over_metadata(
    key, data):
  """
  <Purpose>
    Given a public key and data (JSON-compatible dictionary or asn1crypto ASN1
    object), create a signature using that key over a canonical, serialized
    form of the given data.

    Higher level function that wraps securesystemslib.keys.create_signature,
    and works specifically with metadata in the JSON-compatible metadata format
    from the TUF specification or an ASN.1 format defined by
    tuf.encoding.asn1_definitions.

  <Arguments>
    key:
      A dictionary representing a public key and its properties, conforming to
      securesystemslib.formats.PUBLIC_KEY_SCHEMA.

      For example, if 'key' is an RSA key, it has the form:
        {'keytype': 'rsa',
         'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
         'keyid_hash_algorithms': ['sha256', 'sha512'],
         'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...'}}# PEM format

    data:
      Data object over which a signature will be produced.

      Acceptable formats are:

        - ASN.1 metadata:
          an asn1crypto object, specifically an instance of one of these
          classes defined in tuf.encoding.asn1_metadata_definitions:
            RootMetadata, TimestampMetadata, SnapshotMetadata, TargetsMetadata.
          ASN.1 metadata will be serialized into to bytes as ASN.1/DER
          (Distinguished Encoding Rules) for signature checks.

        - JSON-compatible standard TUF-internal metadata:
          a dictionary conforming to one of these schemas from tuf.formats:
          ROOT_SCHEMA, TARGETS_SCHEMA, TIMESTAMP_SCHEMA, SNAPSHOT_SCHEMA.
          This is the usual metadata format defined in the TUF specification.
          JSON-compatible metadata will be serialized to bytes encoding
          canonical JSON for signature checks.

          (Note: While this function is intended to create signatures over
           these metadata types, it can technically be used more broadly with
           any dictionary that can be canonicalized to JSON or any serializable
           asn1crypto object.  Please be careful with such use, support for
           which may change.)

  <Exceptions>
    tuf.FormatError, raised if either 'key' or 'signature' are improperly
    formatted, or if data does not seem to match one of the expected formats.

    tuf.UnsupportedLibraryError, if an unsupported or unavailable library is
    detected.

    # TODO: Determine the likely types of errors asn1crypto will raise.  It
    #       doesn't look like they have the error classes I'd expect.

  <Returns>
    signature:
      The signature dictionary produced by one of the key generation functions,
      conforming to securesystemslib.formats.SIGNATURE_SCHEMA.

      For example:
        {'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
         'sig': 'abcdef0123456...'}.
  """

  securesystemslib.formats.ANYKEY_SCHEMA.check_match(key)

  # Validate format of data and serialize data.  Note that
  # tuf.encoding.util.serialize() only checks to make sure the data is a
  # JSON-compatible dict or any asn1crypto value that can be serialized, while
  # check_is_serializable_role_metadata() checks to make sure the metadata is
  # specifically TUF role metadata (of either type) that can be serialized.
  check_is_serializable_role_metadata(data)
  serialized_data = tuf.encoding.util.serialize(data)

  # All's well and the data is serialized.  Check the signature over it.
  return securesystemslib.keys.create_signature(key, serialized_data)






def verify_signature_over_metadata(
    key, signature, data):
  """
  <Purpose>
    Determine whether the given signature is a valid signature by key over
    the given data.  securesystemslib.keys.verify_signature() will use the
    public key found in 'key', the 'sig' objects contained in 'signature',
    along with 'data', to complete the verification.

    Higher level function that wraps securesystemslib.keys.verify_signature,
    and works specifically with metadata in the JSON-compatible metadata format
    from the TUF specification or an ASN.1 format defined by
    tuf.encoding.asn1_definitions.

  <Arguments>
    key:
      A dictionary representing a public key and its properties, conforming to
      securesystemslib.formats.PUBLIC_KEY_SCHEMA.

      For example, if 'key' is an RSA key, it has the form:
        {'keytype': 'rsa',
         'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
         'keyid_hash_algorithms': ['sha256', 'sha512'],
         'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...'}}# PEM format

    signature:
      The signature dictionary produced by one of the key generation functions,
      conforming to securesystemslib.formats.SIGNATURE_SCHEMA.

      For example:
        {'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
         'sig': 'abcdef0123456...'}.

    data:
      Data object over which the validity of the provided signature will be
      checked.

      Acceptable formats are:

        - ASN.1 metadata:
          an asn1crypto object, specifically an instance of one of these
          classes defined in tuf.encoding.asn1_metadata_definitions:
            RootMetadata, TimestampMetadata, SnapshotMetadata, TargetsMetadata.
          ASN.1 metadata will be serialized into to bytes as ASN.1/DER
          (Distinguished Encoding Rules) for signature checks.

        - JSON-compatible standard TUF-internal metadata:
          a dictionary conforming to one of these schemas from tuf.formats:
          ROOT_SCHEMA, TARGETS_SCHEMA, TIMESTAMP_SCHEMA, SNAPSHOT_SCHEMA.
          This is the usual metadata format defined in the TUF specification.
          JSON-compatible metadata will be serialized to bytes encoding
          canonical JSON for signature checks.

          (Note: While this function is intended to verify signatures over
           these metadata types, it can technically be used more broadly with
           any dictionary that can be canonicalized to JSON or any serializable
           asn1crypto object.  Please be careful with such use, support for
           which may change.)

  <Exceptions>
    tuf.FormatError, raised if either 'key' or 'signature' are improperly
    formatted, or if data does not seem to match one of the expected formats.

    tuf.UnsupportedLibraryError, if an unsupported or unavailable library is
    detected.

    # TODO: Determine the likely types of errors asn1crypto will raise.  It
    #       doesn't look like they have the error classes I'd expect.

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """

  securesystemslib.formats.ANYKEY_SCHEMA.check_match(key)
  securesystemslib.formats.SIGNATURE_SCHEMA.check_match(signature)

  # Validate format of data and serialize data.  Note that
  # tuf.encoding.util.serialize() only checks to make sure the data is a
  # JSON-compatible dict or any asn1crypto value that can be serialized, while
  # check_is_serializable_role_metadata() checks to make sure the metadata is
  # specifically TUF role metadata (of either type) that can be serialized.
  check_is_serializable_role_metadata(data)
  serialized_data = tuf.encoding.util.serialize(data)

  # All's well and the data is serialized.  Check the signature over it.
  return securesystemslib.keys.verify_signature(key, signature, serialized_data)





def get_signature_status(signable, role=None, repository_name='default',
    threshold=None, keyids=None):
  """
  # TODO: should probably be called get_status_of_signatures, plural?

  <Purpose>
    Return a dictionary representing the status of the signatures listed in
    'signable'.  Given an object conformant to SIGNABLE_SCHEMA, a set of public
    keys in 'tuf.keydb', a set of roles in 'tuf.roledb', and a role,
    the status of these signatures can be determined.  This method will iterate
    the signatures in 'signable' and enumerate all the keys that are valid,
    invalid, unrecognized, or unauthorized.

    Top-level roles (root, snapshot, timestamp, targets) have unambiguous
    signature expectations: the expected keyids and threshold come only from
    trusted root metadata.  Therefore, if optional args threshold and keyids
    are not provided, the expected values can be taken from trusted root
    metadata in tuf.roledb.  Delegated targets roles, on the other hand, may be
    the objects of multiple different delegations from different roles that can
    each have different keyid and threshold expectations, so it is not possible
    to deduce these without knowing the delegating role of interest.  Please
    always provide threshold and keyids if providing a role that isn't a
    top-level role.

    # TODO: After Issue #660 is fixed, update the above.
    # Replace "Please always provide..." with:
    # "If 'role' is not a top-level role but a delegated targets role, 'keyids'
    # and 'threshold' MUST be provided."

  <Arguments>

    signable:
      A metadata dictionary conformant to tuf.formats.SIGNABLE_SCHEMA.
      For example:
          {'signed': {...},
           'signatures': [{'keyid': '1234ef...', 'sig': 'abcd1234...'}]}

    role:
      TUF role (e.g., 'root', 'targets', 'some_delegated_project').

    threshold:
      Rather than reference the role's threshold as set in tuf.roledb.py, use
      the given 'threshold' to calculate the signature status of 'signable'.
      'threshold' is an integer value that sets the role's threshold value, or
      the minimum number of signatures needed for metadata to be considered
      fully signed.

    keyids:
      Similar to the 'threshold' argument, use the supplied list of 'keyids'
      to calculate the signature status, instead of referencing the keyids
      in tuf.roledb.py for 'role'.

  <Exceptions>

    securesystemslib.exceptions.FormatError, if 'signable' does not have the
    correct format.

    tuf.exceptions.UnknownRoleError, if 'role' is not recognized.

    tuf.exceptions.Error, if the optional arguments keyids and threshold are
    partially provided -- i.e. one is provided and one is not.  (They must
    both be provided or both not be provided.)

    # TODO: After Issue #660 is fixed, add the following:
    # tuf.exceptions.Error, if role is not a top-level role and keyids and
    # threshold are not provided.

  <Side Effects>
    None.

  <Returns>
    A dictionary representing the status of the signatures in 'signable'.
    Conformant to tuf.formats.SIGNATURESTATUS_SCHEMA.
    Includes threshold, good_sigs, bad_sigs, unknown_sigs, untrusted_sigs,
    and unknown_signing_schemes.
  """

  # Do the arguments have the correct format?  This check will ensure that
  # arguments have the appropriate number of objects and object types, and that
  # all dict keys are properly named.  Raise
  # 'securesystemslib.exceptions.FormatError' if the check fails.
  tuf.formats.SIGNABLE_SCHEMA.check_match(signable)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  # Argument sanity: we must either be given both the authorized keyids
  # and the threshold, or neither.  Receiving just one or the other makes no
  # sense.
  if (threshold is None) != (keyids is None):
    raise tuf.exceptions.Error(
        'Incoherent optional arguments: we must receive either both expected '
        'keyids and threshold, or neither.')

  # Argument sanity: We need either keyids&threshold or role.
  if keyids is None and role is None:
    logger.warning(
        'Given no information to use to validate signatures -- neither the '
        'expected keys and threshold, nor a role from which to derive them.  '
        'Signature report will be of very limited use.')
    # raise tuf.exceptions.Error(
    #   'Invalid arguments: no keyids or threshold provided, and no ' # update after #660 is fixed, to: ', and no top-level '
    #   'role provided from which to deduce them.')

  # Argument sanity: role has the right format, if provided.
  if role is not None:
    assert threshold is None and keyids is None, 'Not possible; mistake in this function!'  # TODO: consider removing after debug
    tuf.formats.ROLENAME_SCHEMA.check_match(role)
    # The following code must be used when it is time to fix #660....
    # if not _is_top_level_role(role):         # implicit -- and (threshold is None or keyids is None):
    #   raise tuf.exceptions.Error(
    #       # See github.com/theupdateframework/tuf/issues/660
    #       'Unable to determine keyids and threshold to expect from delegated '
    #       'targets role, "' + role + '"; when called for a delegated targets '
    #       'role, sig.get_signature_status() must be told which keyids and '
    #       'threshold should be used to validate the role.  A delegated role '
    #       'rolename need never be provided as argument.')

  # Argument sanity: keyids and threshold have the right format, if provided.
  if keyids is not None:
    securesystemslib.formats.KEYIDS_SCHEMA.check_match(keyids)
    assert threshold is not None, 'Not possible; mistake in this function!'  # TODO: consider removing after testing
    assert role is None, 'Not possible: mistake in this function!'  # TODO: consider removing after testing
    securesystemslib.formats.THRESHOLD_SCHEMA.check_match(threshold)


  # Determine which keyids and threshold should be used to verify this
  # metadata.  Either they are provided as arguments, or, if not, we will try
  # to check the roledb ourselves to see if the expected keyids and threshold
  # for this role (****) are known there.  (This only works for the four
  # top-level roles. See TUF Issue #660 on GitHub.)    # TODO: <~> Review this section!
  if keyids is None:
    # Redundant argument sanity check
    assert threshold is None, 'Not possible; mistake in this function!'


    if role is None:
      # We can only reach this spot if no role information AND no keyids were
      # given to this function, in which case our return data is QUITE limited,
      # but we can still check to see if a given signature is correct (though
      # not if that key is authorized to sign).
      keyids = []

    else:
      # Note that if the role is not known, tuf.exceptions.UnknownRoleError
      # is raised here.
      keyids = tuf.roledb.get_role_keyids(role, repository_name)
      threshold = tuf.roledb.get_role_threshold(
          role, repository_name=repository_name)


  # The signature status dictionary we will return.
  signature_status = {}

  # The fields of the signature_status dict, where each field is a list of
  # keyids.  A description of each field:
  #
  # good_sigs =      keyids confirmed to have produced 'sig' over 'signed',
  #                  which are associated with 'role'.
  #
  # bad_sigs =       keyids for which a signature is included that is not a
  #                  valid signature using the key indicated over 'signed'.
  #
  # unknown_sigs =   unknown keyids: keyids from signatures for which the keyid
  #                  has no entry in the 'keydb' database.
  #
  # untrusted_sigs = untrusted keyids: keyids from signatures whose keyids
  #                  correspond to known keys, but which are not authorized to
  #                  sign this metadata (according to keyids arg or rolename
  #                  lookup in roledb).
  #
  # unknown_signing_scheme = keyids from signatures that list a signing scheme
  #                          that is not supported.
  good_sigs = []
  bad_sigs = []
  unknown_sigs = []
  untrusted_sigs = []
  unknown_signing_schemes = []

  # Extract the relevant fields from 'signable' that will allow us to identify
  # the different classes of keys (i.e., good_sigs, bad_sigs, etc.).
  signed = signable['signed']
  signatures = signable['signatures']

  # Iterate the signatures and enumerate the signature_status fields.
  # (i.e., good_sigs, bad_sigs, etc.).
  for signature in signatures:
    keyid = signature['keyid']

    # Try to find the public key corresponding to the keyid (fingerprint)
    # listed in the signature, so that we can actually verify the signature.
    # If we can't find it, note this as an unknown key, and skip to the next.
    try:
      key = tuf.keydb.get_key(keyid, repository_name)

    except securesystemslib.exceptions.UnknownKeyError:
      unknown_sigs.append(keyid)
      continue

    # Now try verifying the signature (whether it's over canonical JSON + utf-8
    # or over ASN.1/DER).
    # If the signature use an unknown/unsupported signing scheme and cannot be
    # verified, note that and skip to the next signature.
    # TODO: Make sure that verify_signature_over_metadata will actually raise
    #       this unsupported algorithm error appropriately.
    try:
      valid_sig = verify_signature_over_metadata(key, signature, signed)
    except securesystemslib.exceptions.UnsupportedAlgorithmError:
      unknown_signing_schemes.append(keyid)
      continue

    # We know the key, we support the signing scheme, and
    # verify_signature_over_metadata completed, its boolean return telling us if
    # the signature is a valid signature by the key the signature mentions,
    # over the data provided.
    # We now ascertain whether or not this known key is one trusted to sign
    # this particular metadata.

    if valid_sig:
        # Is this an authorized key? (a keyid associated with 'role')
      if keyid in keyids:
        good_sigs.append(keyid)       # good sig from right key
      else:
        untrusted_sigs.append(keyid)  # good sig from wrong key

    else:
      # The signature not even valid for the key the signature says it's using.
      bad_sigs.append(keyid)


  # Retrieve the threshold value for 'role'.  Raise
  # securesystemslib.exceptions.UnknownRoleError if we were given an invalid
  # role.
  if role is not None:
    if threshold is None:
      # Note that if the role is not known, tuf.exceptions.UnknownRoleError is
      # raised here.
      threshold = tuf.roledb.get_role_threshold(
          role, repository_name=repository_name)

    else:
      logger.debug('Not using roledb.py\'s threshold for ' + repr(role))

  else:
    threshold = 0

  # Build the signature_status dict.
  signature_status['threshold'] = threshold
  signature_status['good_sigs'] = good_sigs
  signature_status['bad_sigs'] = bad_sigs
  signature_status['unknown_sigs'] = unknown_sigs
  signature_status['untrusted_sigs'] = untrusted_sigs
  signature_status['unknown_signing_schemes'] = unknown_signing_schemes

  return signature_status





def verify_signable(signable, role, repository_name='default', threshold=None,
    keyids=None):
  """
  <Purpose>
    Verify whether the authorized signatures of 'signable' meet the minimum
    required by 'role'.  Authorized signatures are those with valid keys
    associated with 'role'.  'signable' must conform to SIGNABLE_SCHEMA
    and 'role' must not equal 'None' or be less than zero.

    Top-level roles (root, snapshot, timestamp, targets) have unambiguous
    signature expectations: the expected keyids and threshold come only from
    trusted root metadata.  Therefore, if optional args threshold and keyids
    are not provided, the expected values can be taken from trusted root
    metadata in tuf.roledb.  Delegated targets roles, on the other hand, may be
    the objects of multiple different delegations from different roles that can
    each have different keyid and threshold expectations, so it is not possible
    to deduce these without knowing the delegating role of interest; therefore,
    if 'role' is not a top-level role but a delegated targets role, 'keyids'
    and 'threshold' MUST be provided.

  <Arguments>
    signable:
      A dictionary containing a list of signatures and a 'signed' identifier.
      signable = {'signed':, 'signatures': [{'keyid':, 'method':, 'sig':}]}

    role:
      TUF role (e.g., 'root', 'targets', 'snapshot').

    threshold:
      Rather than reference the role's threshold as set in tuf.roledb.py, use
      the given 'threshold' to calculate the signature status of 'signable'.
      'threshold' is an integer value that sets the role's threshold value, or
      the miminum number of signatures needed for metadata to be considered
      fully signed.

    keyids:
      Similar to the 'threshold' argument, use the supplied list of 'keyids'
      to calculate the signature status, instead of referencing the keyids
      in tuf.roledb.py for 'role'.

  <Exceptions>
    securesystemslib.exceptions.UnknownRoleError, if 'role' is not recognized.

    securesystemslib.exceptions.FormatError, if 'signable' is not formatted
    correctly.

    securesystemslib.exceptions.Error, if an invalid threshold is encountered.

    tuf.exceptions.Error, if role is not a top-level role and keyids and
    threshold are not provided.

  <Side Effects>
    tuf.sig.get_signature_status() called.  Any exceptions thrown by
    get_signature_status() will be caught here and re-raised.

  <Returns>
    Boolean.  True if the number of good signatures >= the role's threshold,
    False otherwise.
  """

  tuf.formats.SIGNABLE_SCHEMA.check_match(signable)

  # The other arguments are checked by the get_signature_status call.

  # Retrieve the signature status.  tuf.sig.get_signature_status() raises:
  # securesystemslib.exceptions.UnknownRoleError
  # securesystemslib.exceptions.FormatError.  'threshold' and 'keyids' are also
  # validated.
  # tuf.exceptions.Error if the role is a delegated targets role but keyids and
  # threshold are not provided.
  status = get_signature_status(signable, role, repository_name, threshold, keyids)

  # Retrieve the role's threshold and the authorized keys of 'status'
  threshold = status['threshold']
  good_sigs = status['good_sigs']

  # Does 'status' have the required threshold of signatures?
  # First check for invalid threshold values before returning result.
  # Note: get_signature_status() is expected to verify that 'threshold' is
  # not None or <= 0.
  if threshold is None or threshold <= 0: #pragma: no cover
    raise securesystemslib.exceptions.Error("Invalid threshold: " + repr(threshold))

  return len(good_sigs) >= threshold
