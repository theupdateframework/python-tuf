"""
<Program Name>
  sig.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 28, 2012.   Based on a previous version by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Survivable key compromise is one feature of a secure update system
  incorporated into TUF's design. Responsibility separation through
  the use of multiple roles, multi-signature trust, and explicit and
  implicit key revocation are some of the mechanisms employed towards
  this goal of survivability.  These mechanisms can all be seen in
  play by the functions available in this module.

  The signed metadata files utilized by TUF to download target files
  securely are used and represented here as the 'signable' object.
  More precisely, the signature structures contained within these metadata
  files are packaged into 'signable' dictionaries.  This module makes it
  possible to capture the states of these signatures by organizing the
  keys into different categories.  As keys are added and removed, the
  system must securely and efficiently verify the status of these signatures.
  For instance, a bunch of keys have recently expired. How many valid keys
  are now available to the Snapshot role?  This question can be answered by
  get_signature_status(), which will return a full 'status report' of these 
  'signable' dicts.  This module also provides a convenient verify() function
  that will determine if a role still has a sufficient number of valid keys.
  If a caller needs to update the signatures of a 'signable' object, there
  is also a function for that.
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
import tuf.ssl_crypto.formats
import tuf.ssl_crypto.keydb
import tuf.roledb


# See 'log.py' to learn how logging is handled in TUF.                          
logger = logging.getLogger('tuf.sig')                                
                                                                                
# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the      
# log file.                                                                     
iso8601_logger = logging.getLogger('iso8601')                                   
iso8601_logger.disabled = True                                   


def get_signature_status(signable, role=None, repository_name='default',
                         threshold=None, keyids=None):
  """
  <Purpose>
    Return a dictionary representing the status of the signatures listed in
    'signable'.  Given an object conformant to SIGNABLE_SCHEMA, a set of public
    keys in 'tuf.ssl_crypto.keydb', a set of roles in 'tuf.roledb', and a role,
    the status of these signatures can be determined.  This method will iterate
    the signatures in 'signable' and enumerate all the keys that are valid,
    invalid, unrecognized, unauthorized, or generated using an unknown method.

  <Arguments>
    signable:
      A dictionary containing a list of signatures and a 'signed' identifier.
      signable = {'signed': 'signer',
                  'signatures': [{'keyid': keyid,
                                  'method': 'evp',
                                  'sig': sig}]}
      
      Conformant to tuf.ssl_crypto.formats.SIGNABLE_SCHEMA.

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
    tuf.ssl_commons.exceptions.FormatError, if 'signable' does not have the
    correct format.

    tuf.ssl_commons.exceptions.UnknownRoleError, if 'role' is not recognized.

  <Side Effects>
    None.

  <Returns>
    A dictionary representing the status of the signatures in 'signable'.
    Conformant to tuf.ssl_crypto.formats.SIGNATURESTATUS_SCHEMA.
  """

  # Do the arguments have the correct format?  This check will ensure that
  # arguments have the appropriate number of objects and object types, and that
  # all dict keys are properly named.  Raise
  # 'tuf.ssl_commons.exceptions.FormatError' if the check fails.
  tuf.ssl_crypto.formats.SIGNABLE_SCHEMA.check_match(signable)
  tuf.ssl_crypto.formats.NAME_SCHEMA.check_match(repository_name)

  if role is not None:
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(role)

  if threshold is not None:
    tuf.ssl_crypto.formats.THRESHOLD_SCHEMA.check_match(threshold) 
  
  if keyids is not None:
    tuf.ssl_crypto.formats.KEYIDS_SCHEMA.check_match(keyids)
  
  # The signature status dictionary returned.
  signature_status = {}

  # The fields of the signature_status dict, where each field stores keyids.  A
  # description of each field:
  # good_sigs = keys confirmed to have produced 'sig' and 'method' using
  # 'signed', which are associated with 'role';
  # bad_sigs = negation of good_sigs;
  # unknown_sigs = keys not found in the 'keydb' database;
  # untrusted_sigs = keys that are not in the list of keyids associated with
  # 'role';
  # unknown_method_sigs = keys found to have used an unsupported method
  # of generating signatures.
  good_sigs = []
  bad_sigs = []
  unknown_sigs = []
  untrusted_sigs = []
  unknown_method_sigs = []

  # Extract the relevant fields from 'signable' that will allow us to identify
  # the different classes of keys (i.e., good_sigs, bad_sigs, etc.).
  signed = signable['signed']
  signatures = signable['signatures']

  # Iterate the signatures and enumerate the signature_status fields.
  # (i.e., good_sigs, bad_sigs, etc.).
  for signature in signatures:
    sig = signature['sig']
    keyid = signature['keyid']
    method = signature['method']

    # Does the signature use an unrecognized key?
    try:
      key = tuf.ssl_crypto.keydb.get_key(keyid, repository_name)
    
    except tuf.ssl_commons.exceptions.UnknownKeyError:
      unknown_sigs.append(keyid)
      continue

    # Does the signature use an unknown key signing method?
    try:
      valid_sig = tuf.ssl_crypto.keys.verify_signature(key, signature, signed)
    
    except tuf.ssl_commons.exceptions.UnknownMethodError:
      unknown_method_sigs.append(keyid)
      continue

    # We are now dealing with either a trusted or untrusted key... 
    if valid_sig:
      if role is not None:
        
        try:
          # Is this an unauthorized key? (a keyid associated with 'role')
          if keyids is None:
            keyids = tuf.roledb.get_role_keyids(role, repository_name) 
          
          if keyid not in keyids:
            untrusted_sigs.append(keyid)
            continue
        
        # Unknown role, re-raise exception. 
        except tuf.ssl_commons.exceptions.UnknownRoleError:
          raise
      
      # This is an unset role, thus an unknown signature.
      else:
        unknown_sigs.append(keyid)
        continue

      # Identify good/authorized key.
      good_sigs.append(keyid)
    
    else:
      # This is a bad signature for a trusted key.
      bad_sigs.append(keyid) 
  
  # Retrieve the threshold value for 'role'.  Raise
  # tuf.ssl_commons.exceptions.UnknownRoleError if we were given an invalid
  # role.
  if role is not None:
    try:
      threshold = \
        tuf.roledb.get_role_threshold(role, repository_name=repository_name)
    
    except tuf.ssl_commons.exceptions.UnknownRoleError:
      raise
  
  else:
    threshold = 0

  # Build the signature_status dict.
  signature_status['threshold'] = threshold
  signature_status['good_sigs'] = good_sigs
  signature_status['bad_sigs'] = bad_sigs
  signature_status['unknown_sigs'] = unknown_sigs
  signature_status['untrusted_sigs'] = untrusted_sigs
  signature_status['unknown_method_sigs'] = unknown_method_sigs

  return signature_status





def verify(signable, role, repository_name='default',
           threshold=None, keyids=None):
  """
  <Purpose> 
    Verify whether the authorized signatures of 'signable' meet the minimum
    required by 'role'.  Authorized signatures are those with valid keys
    associated with 'role'.  'signable' must conform to SIGNABLE_SCHEMA
    and 'role' must not equal 'None' or be less than zero.

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
    tuf.ssl_commons.exceptions.UnknownRoleError, if 'role' is not recognized.

    tuf.ssl_commons.exceptions.FormatError, if 'signable' is not formatted
    correctly.

    tuf.ssl_commons.exceptions.Error, if an invalid threshold is encountered.

  <Side Effects>
    tuf.sig.get_signature_status() called.  Any exceptions thrown by
    get_signature_status() will be caught here and re-raised.

  <Returns>
    Boolean.  True if the number of good signatures >= the role's threshold,
    False otherwise.
  """
    
  tuf.ssl_crypto.formats.SIGNABLE_SCHEMA.check_match(signable)
  tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(role)
  tuf.ssl_crypto.formats.NAME_SCHEMA.check_match(repository_name)

  # Retrieve the signature status.  tuf.sig.get_signature_status() raises:
  # tuf.ssl_commons.exceptions.UnknownRoleError
  # tuf.ssl_commons.exceptions.FormatError.  'threshold' and 'keyids' are also
  # validated.
  status = get_signature_status(signable, role, repository_name, threshold, keyids)
        
  # Retrieve the role's threshold and the authorized keys of 'status'
  threshold = status['threshold']
  good_sigs = status['good_sigs']

  # Does 'status' have the required threshold of signatures?
  # First check for invalid threshold values before returning result.
  # Note: get_signature_status() is expected to verify that 'threshold' is
  # not None or <= 0.
  if threshold is None or threshold <= 0: #pragma: no cover
    raise tuf.ssl_commons.exceptions.Error("Invalid threshold: " + repr(threshold))

  return len(good_sigs) >= threshold





def may_need_new_keys(signature_status):
  """
  <Purpose> 
    Return true iff downloading a new set of keys might tip this
    signature status over to valid.  This is determined by checking
    if either the number of unknown or untrused keys is > 0.

  <Arguments>
    signature_status:
      The dictionary returned by tuf.sig.get_signature_status().

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'signature_status does not have
    the correct format.

  <Side Effects>
    None.

  <Returns>
    Boolean.
  """

  # Does 'signature_status' have the correct format?
  # This check will ensure 'signature_status' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.ssl_commons.exceptions.FormatError' if the check fails.
  tuf.ssl_crypto.formats.SIGNATURESTATUS_SCHEMA.check_match(signature_status)

  unknown = signature_status['unknown_sigs']
  untrusted = signature_status['untrusted_sigs']

  return len(unknown) or len(untrusted)





def generate_rsa_signature(signed, rsakey_dict):
  """
  <Purpose>
    Generate a new signature dict presumably to be added to the 'signatures'
    field of 'signable'.  The 'signable' dict is of the form:

    {'signed': 'signer',
               'signatures': [{'keyid': keyid,
                               'method': 'evp',
                               'sig': sig}]}

    The 'signed' argument is needed here for the signing process.
    The 'rsakey_dict' argument is used to generate 'keyid', 'method', and 'sig'.

    The caller should ensure the returned signature is not already in
    'signable'.

  <Arguments>
    signed:
      The data used by 'tuf.ssl_crypto.keys.create_signature()' to generate
      signatures.  It is stored in the 'signed' field of 'signable'.

    rsakey_dict:
      The RSA key, a 'tuf.ssl_crypto.formats.RSAKEY_SCHEMA' dictionary.
      Used here to produce 'keyid', 'method', and 'sig'.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'rsakey_dict' does not have the
    correct format.

    TypeError, if a private key is not defined for 'rsakey_dict'.

  <Side Effects>
    None.

  <Returns>
    Signature dictionary conformant to tuf.ssl_crypto.formats.SIGNATURE_SCHEMA.
    Has the form:
    {'keyid': keyid, 'method': 'evp', 'sig': sig}
  """

  # We need 'signed' in canonical JSON format to generate
  # the 'method' and 'sig' fields of the signature.
  signed = tuf.ssl_crypto.formats.encode_canonical(signed)

  # Generate the RSA signature.
  # Raises tuf.ssl_commons.exceptions.FormatError and TypeError.
  signature = tuf.ssl_crypto.keys.create_signature(rsakey_dict, signed)

  return signature
