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

<Public Functions>

    get_signature_status()
      Analyzes the signatures included in given role metadata that includes
      signatures, taking arguments that convey the expected keyids and
      threshold for those signatures (either directly or in the form of a
      rolename to look up in roledb), produces a report of the validity of the
      signatures provided in the metadata indicating whether or not they
      correctly sign the given metadata and whether or each signature is from
      an authorized key.

    verify()
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

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.sig')

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True


def get_signature_status(signable, rolename=None, repository_name='default',
    threshold=None, keyids=None):
  """
  # TODO: should probably be called get_status_of_signatures, plural?

  <Purpose>
    Given a signable role dictionary, analyzes the signatures included in it
    (signable['signatures']) as signatures over the other metadata included in
    it (signable['signed']).

    Returns a dictionary representing an analysis of the status of the
    signatures in <signable> (see below).  This is done based on the
    keyids expected to sign for the role.

    If <threshold> and <keyids> are provided:
      Uses argument <keyids> to determine which keys are authorized to sign,
      and returns the information along with the <threshold> provided.

    If <threshold> and <keyids> are NOT provided and <rolename> is a top-level
    role:
      Determines the threshold and keyids to use based on the currently trusted
      Root metadata's listing for role <rolename>.

    Why <threshold> and <keyids> are sometimes required:
      # TODO: <~> Ask the reviewer in the PR if the comments below are
      #           important or just in the way.
      Note that the reason that keyids and threshold can only automatically be
      determined for top-level roles (root, snapshot, timestamp, targets) is
      that top-level roles have unambiguous signature expectations: the
      expected keyids and threshold come only from trusted root metadata. 
      Therefore, if optional args <threshold> and <keyids> are not provided,
      the expected values can be taken from trusted Root metadata in
      tuf.roledb.  Delegated targets roles, on the other hand, may be the
      objects of multiple different delegations from different roles that can
      each have different keyid and threshold expectations, so it is not
      possible to deduce these without knowing the delegating role of interest.


  <Arguments>
    signable:
      A dictionary with a 'signatures' entry containing a list of signatures,
      and a 'signed' entry, containing role metadata.
      Specifically, <signable> must conform to tuf.formats.SIGNABLE_SCHEMA,
      and the 'signed' entry in <signable> must conform to
      tuf.formats.ANYROLE_SCHEMA.
      e.g.:
        {'signatures': [
            {'keyid': '1234ef...', 'sig': 'abcd1234...'}, ... ],
         'signed': { '_type': 'root', 'version': 3, ... }
        }

    rolename:     (required if <keyids> and <threshold> are not provided)
      The name of the TUF role whose metadata is provided.
      If specified, this must conform to tuf.formats.ROLENAME_SCHEMA.
      e.g.: 'root', 'targets', 'some_delegated_rolename', ...
      This will be used to look up the required keyids and threshold to use,
      from the currently trusted Root metadata's listing by role.

    threshold:    (required for delegated targets roles)
      If specified, this must match tuf.formats.THRESHOLD_SCHEMA.  If provided
      along with <keyids>, this will be the information in the 'threshold'
      entry of the returned dictionary.

    keyids:       (required for delegated targets roles)
      If specified, this must conform to tuf.formats.KEYIDS_SCHEMA.  If
      provided along with <threshold>, this defines which keys can provide
      "good" signatures over the metadata.


  <Returns>
    Returns a dictionary representing the status of the signatures in
    <signable>, conforming to tuf.formats.SIGNATURESTATUS_SCHEMA.  The
    dictionary values are lists of keyids corresponding to signatures in
    <signable>, broken down under these dictionary keys:

      good_sigs:
          keyids corresponding to verified signatures over the role by keys
          trusted to sign over the role

      bad_sigs:
          keyids corresponding to invalid signatures over the role

      unknown_sigs:
          keyids (from signatures in <signable>) from unknown keys; i.e.,
          keyids that had no entry in tuf.keydb.

      untrusted_sigs:
          keyids corresponding to correct signatures over the role, by known
          keys (i.e. in tuf.keydb) that are nonetheless not authorized to sign
          over the role.
          (Authorization is based on either the <keyids> argument if provided,
          or, if not provided, Root metadata, as discussed below.)

      unknown_signing_scheme:
          keyids corresponding to signatures that list a signing scheme that is
          not supported.


  <Exceptions>
    securesystemslib.exceptions.UnknownRoleError
      if <rolename> is not a known role in the repository.

    tuf.exceptions.FormatError
      if <signable>, <rolename>, or <repository_name> are not formatted
        correctly,
      or if <threshold> is provided and not formatted correctly
      or if <threshold> is not provided but determined from trusted Root
        metadata yet somehow formatted incorrectly there.

    securesystemslib.exceptions.FormatError
      if <keyids> is provided but not formatted correctly,
      or if <repository_name> is not formatted correctly.

    tuf.exceptions.Error
      if <threshold> is provided but <keyids> is not, or vice versa,
      of if we have no way of determining the right keyids and threshold to use
        in verification -- specifically, if rolename is not the name of a
        top-level role and <keyids> and <threshold> arguments are not provided.


  <Side Effects>
    None.
  """

  # Make sure that <signable> is correctly formatted.
  tuf.formats.SIGNABLE_SCHEMA.check_match(signable)

  # This helper function will perform all other argument checks and -- if
  # necessary -- look up the keyids and threshold to use from currently trusted
  # Root metadata.
  keyids, threshold = _determine_keyids_and_threshold_to_use(
      rolename, repository_name, keyids, threshold)

  # The signature status dictionary we will return.
  signature_status = {}

  # The fields of the signature_status dict, where each field is a list of
  # keyids.  See docstring for an explanation of each.
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

    # Now try verifying the signature.  If the signature use an
    # unknown/unsupported signing scheme and cannot be verified, note that and
    # skip to the next signature.
    # TODO: Make sure that verify_signature_over_metadata will actually raise
    #       this unsupported algorithm error appropriately.
    # TODO: Note that once the next version of securesystemslib gets released,
    #       signed here will have to be canonicalized and encoded before it
    #       gets passed to verify_signature.
    try:
      valid_sig = securesystemslib.keys.verify_signature(key, signature, signed)

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




def _determine_keyids_and_threshold_to_use(
    rolename, repository_name, keyids, threshold):
  """
  Helper function for get_signature_status.  Tests all the various argument
  constraints for get_signature_status and looks up the keyids and threshold if
  necessary.  See docstring for get_signature_status.
  """

  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  # Sanity check for argument pairs:
  if (keyids is None) != (threshold is None) or \
      (keyids is None) == (rolename is None):
    raise tuf.exceptions.Error(
        'This function must be called using either the "rolename" argument OR '
        'using the "keyids" and "threshold" arguments.  One set or the other '
        'must be provided, and not both sets. '
        '(keyids provided? ' + str(keyids is not None) +
        '; threshold provided? ' + str(threshold is not None) +
        '; rolename provided? ' + str(rolename is not None) + ')')

  if keyids is not None:

    # DEBUG ONLY: REMOVE AFTER TESTING:
    assert threshold is not None, 'Not possible; mistake in this function!'
    assert rolename is None, 'Not possible: mistake in this function!'

    securesystemslib.formats.KEYIDS_SCHEMA.check_match(keyids)
    tuf.formats.THRESHOLD_SCHEMA.check_match(threshold)

    # We were given keyids and threshold and their formats check out.
    return keyids, threshold

  # Otherwise, we weren't provided keyids and threshold, so figure them out if
  # possible.

  # DEBUG ONLY: REMOVE AFTER TESTING:
  assert threshold is None and keyids is None, 'Not possible; mistake in this function!'
  assert rolename is not None, 'Not possible; mistake in this function!'

  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
  if not roledb.is_top_level_rolename(rolename):
    raise tuf.exceptions.Error(
        'Cannot automatically determine the keyids and threshold expected of '
        'a delegated targets role ("' + rolename + '").  The rolename '
        'argument is sufficient only for roles listed by Root.  The name of '
        'a delegated role need never be provided as argument.')

  keyids = tuf.roledb.get_role_keyids(rolename, repository_name)
  threshold = tuf.roledb.get_role_threshold(
      rolename, repository_name=repository_name)

  # Check the results.
  # TODO: Determine if this is overkill.  It's probably checked already
  #       before it is returned.
  securesystemslib.formats.KEYIDS_SCHEMA.check_match(keyids)
  tuf.formats.THRESHOLD_SCHEMA.check_match(threshold)





def verify(signable, rolename=None, repository_name='default', threshold=None,
    keyids=None):
  """
  <Purpose>
    Verify whether the signatures in <signable> meet the requirements.

    Returns True if there are at least a threshold of valid signatures over the
    'signed' component of <signable> by distinct keys with keyids in a list
    of authorized keyids, else returns False.

    The list of authorized keys and the threshold of signatures required may
    be passed in as <keyids> and <threshold>.  Alternatively, if they are not
    provided, the keyids and threshold will be determined based on the
    currently trusted Root metadata's listing for role <rolename>, but that
    only works if the role being verified is a top-level role.


    This wraps get_signature_status(), takes the same arguments, and raises
    the same errors, so please see the docstring for get_signature_status().


  <Returns>
    Boolean.  True if the number of good signatures >= the role's threshold,
    False otherwise.

  <Side Effects>
    None.
  """

  # Note that get_signature_status() checks all arguments, so argument
  # checking here is skipped.

  # Retrieve the status of signatures included in argument <signable>.
  # tuf.sig.get_signature_status() raises:
  #   securesystemslib.exceptions.UnknownRoleError,
  #   tuf.exceptions.FormatError, and
  #   securesystemslib.exceptions.FormatError
  # tuf.exceptions.Error if the role is a delegated targets role but keyids and
  # threshold are not provided.
  status = get_signature_status(
      signable, rolename, repository_name, threshold, keyids)

  # Retrieve the role's threshold and the authorized keys of 'status'
  threshold = status['threshold']
  good_sigs = status['good_sigs']

  # Does 'status' have the required threshold of signatures?

  return len(good_sigs) >= threshold
