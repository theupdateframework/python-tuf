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

import tuf
import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.asn1_codec as asn1_codec

import hashlib

def get_signature_status(signable, role=None, repository_name='default'):
  """
  <Purpose>
    Return a dictionary representing the status of the signatures listed
    in 'signable'.  Given an object conformant to SIGNABLE_SCHEMA, a set
    of public keys in 'tuf.keydb', a set of roles in 'tuf.roledb',
    and a role, the status of these signatures can be determined.  This
    method will iterate through the signatures in 'signable' and enumerate
    all the keys that are valid, invalid, unrecognized, unauthorized, or
    generated using an unknown method.

    PLEASE NOTE that when running TUF with DER metadata (setting
    tuf.conf.METADATA_FORMAT == 'der'), this function can only be called
    on a SIGNABLE_SCHEMA in which the 'signed' entry is role metadata
    (i.e. 'signed' entry conforms to tuf.formats.ANYROLE_SCHEMA).
    This is because checking the signature of a signed metadata role in DER
    involves converting the 'signed' element (the role) back into DER to check
    the signature, and conversion from role metadata in a Python dictionary
    into an ASN.1 format requires special conversion code for that metadata
    type. Thus, when TUF is in DER metadata mode, this function will only
    operate for timestamp, snapshot, root, and targets metadata types, and not
    any other signature.
    # TODO: <~> Consider an optional parameter to force raw signature checking,
    # or, better, using an optional parameter instead of checking
    # tuf.conf.METADATA_FORMAT.

  <Arguments>
    signable:
      A dictionary containing a list of signatures and a 'signed' identifier.
      signable = {'signed': 'signer',
                  'signatures': [{'keyid': keyid,
                                  'method': 'evp',
                                  'sig': sig}]}
      Conformant to tuf.formats.SIGNABLE_SCHEMA.

    role:
      TUF role (e.g., 'root', 'targets', 'snapshot').

    repository_name:
      The name of the repository to check the signature status.  The roledb
      keeps a separate set of roles for each repository.  If not supplied, the
      signature status is verified for the 'role' in the 'default' repository.

  <Exceptions>
    tuf.FormatError, if 'signable' does not have the correct format.

    tuf.UnknownRoleError, if 'role' is not recognized.

    tuf.InvalidNameError, if 'repository_name' does not exist in the role db.

  <Side Effects>
    None.

  <Returns>
    A dictionary representing the status of the signatures in 'signable'.
    Conformant to tuf.formats.SIGNATURESTATUS_SCHEMA.
  """

  # Do the arguments have the correct format?  This check will ensure that
  # arguments have the appropriate number of objects and object types, and that
  # all dict keys are properly named.  Raise 'tuf.FormatError' if the check
  # fails.
  tuf.formats.SIGNABLE_SCHEMA.check_match(signable)
  tuf.formats.NAME_SCHEMA.check_match(repository_name)

  if role is not None:
    tuf.formats.ROLENAME_SCHEMA.check_match(role)
  
  # The signature status dictionary returned.
  signature_status = {}

  # The fields of the signature_status dict.  A description of each field:
  # good_sigs = keys confirmed to have produced 'sig' and 'method' using
  # 'signed' and that are associated with 'role'; bad_sigs = negation of
  # good_sigs; unknown_sigs = keys not found in the 'keydb' database; 
  # untrusted_sigs = keys that are not in the list of keyids associated
  # with 'role'; unknown_method_sigs = keys found to have used an 
  # unsupported method of generating signatures. 
  good_sigs = []
  bad_sigs = []
  unknown_sigs = []
  untrusted_sigs = []
  unknown_method_sigs = []

  # Extract the relevant fields from 'signable' that will allow us to identify
  # the different classes of keys (i.e., good_sigs, bad_sigs, etc.).
  signed = signable['signed']
  signatures = signable['signatures']

  # If we are using DER metadata, the 'signed' field must be converted into
  # DER so that the signature (which was signed into DER) can match it.
  # If the format or encoding are different, this verification will fail,
  # since we're re-encoding to check the signature....
  if tuf.conf.METADATA_FORMAT == 'der':
    signed = asn1_codec.convert_signed_metadata_to_der(
        signable, only_signed=True)
    # Replace signed with a hash of signed, since that's all we'll need to sign
    # and we are not doing anything else with 'signed' here.
    # Digest provides binary data.
    signed = hashlib.sha256(signed).digest()

  # Iterate through the signatures and enumerate the signature_status fields.
  # (i.e., good_sigs, bad_sigs, etc.).
  for signature in signatures:
    sig = signature['sig']
    keyid = signature['keyid']
    method = signature['method']

    # Identify unrecognized key.
    try:
      key = tuf.keydb.get_key(keyid, repository_name)
    
    except tuf.UnknownKeyError:
      unknown_sigs.append(keyid)
      continue

    # Identify key using an unknown key signing method.
    try:
      if tuf.conf.METADATA_FORMAT == 'der':
        valid_sig = tuf.keys.verify_signature(
            key, signature, signed, is_binary_data=True)
      else:
        valid_sig = tuf.keys.verify_signature(key, signature, signed)

    except tuf.UnknownMethodError:
      unknown_method_sigs.append(keyid)
      continue

    # We are now dealing with a valid key. 
    if valid_sig:
      if role is not None:
        try:
          # Identify unauthorized key. 
          if keyid not in tuf.roledb.get_role_keyids(role, repository_name):
            untrusted_sigs.append(keyid)
            continue
        
        # Unknown role, re-raise exception. 
        except tuf.UnknownRoleError:
          raise
      # Identify good/authorized key.
      good_sigs.append(keyid)
    
    else:
      # Identify bad key.
      bad_sigs.append(keyid)

  # Retrieve the threshold value for 'role'.  Raise tuf.UnknownRoleError
  # if we were given an invalid role.
  if role is not None:
    try:
      threshold = tuf.roledb.get_role_threshold(role, repository_name)
    
    except tuf.UnknownRoleError:
      raise
  
  else:
    threshold = 0

  # Build the signature_status dict.
  signature_status['threshold']  = threshold
  signature_status['good_sigs'] = good_sigs
  signature_status['bad_sigs'] = bad_sigs
  signature_status['unknown_sigs'] = unknown_sigs
  signature_status['untrusted_sigs'] = untrusted_sigs
  signature_status['unknown_method_sigs'] = unknown_method_sigs

  return signature_status





def verify(signable, role, repository_name='default'):
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

    repository_name:
      The  name of the repository to verify 'signable'.  The role and key db
      modules keep track of separate sets of roles and keys for each
      repository.  If 'repository_name' is not supplied, the 'default'
      repository is queried.

  <Exceptions>
    tuf.UnknownRoleError, if 'role' is not recognized.

    tuf.FormatError, if 'signable' is not formatted correctly.

    tuf.Error, if an invalid threshold is encountered.

    tuf.InvalidNameError, if 'repository_name' does not exist in either the
    role or key db.

  <Side Effects>
    tuf.sig.get_signature_status() called.  Any exceptions thrown by
    get_signature_status() will be caught here and re-raised.

  <Returns>
    Boolean.  True if the number of good signatures >= the role's threshold,
    False otherwise.
  """

  # Do the arguments have the correct format?  If not, raise 'tuf.FormatError'.
  tuf.formats.SIGNABLE_SCHEMA.check_match(signable) 
  tuf.formats.ROLENAME_SCHEMA.check_match(role)
  tuf.formats.NAME_SCHEMA.check_match(repository_name)

  # Retrieve the signature status.  tuf.sig.get_signature_status() raises:
  # tuf.UnknownRoleError
  # tuf.FormatError
  status = get_signature_status(signable, role, repository_name)
  
  # Retrieve the role's threshold and the authorized keys of 'status'
  threshold = status['threshold']
  good_sigs = status['good_sigs']

  # Does 'status' have the required threshold of signatures?
  # First check for invalid threshold values before returning result.
  # Note: get_signature_status() is expected to verify that 'threshold' is
  # not None or <= 0.
  if threshold is None or threshold <= 0: #pragma: no cover
      raise tuf.Error("Invalid threshold: " + str(threshold))

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
    tuf.FormatError, if 'signature_status does not have the correct format.

  <Side Effects>
    None.

  <Returns>
    Boolean.
  """

  # Does 'signature_status' have the correct format?
  # This check will ensure 'signature_status' has the appropriate number
  # of objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.SIGNATURESTATUS_SCHEMA.check_match(signature_status)

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
      The data used by 'tuf.keys.create_signature()' to generate signatures.
      It is stored in the 'signed' field of 'signable'.

    rsakey_dict:
      The RSA key, a 'tuf.formats.RSAKEY_SCHEMA' dictionary.
      Used here to produce 'keyid', 'method', and 'sig'.

  <Exceptions>
    tuf.FormatError, if 'rsakey_dict' does not have the correct format.

    TypeError, if a private key is not defined for 'rsakey_dict'.

  <Side Effects>
    None.

  <Returns>
    Signature dictionary conformant to tuf.formats.SIGNATURE_SCHEMA.
    Has the form:
    {'keyid': keyid, 'method': 'evp', 'sig': sig}
  """

  # We need 'signed' in canonical JSON format to generate
  # the 'method' and 'sig' fields of the signature.
  signed = tuf.formats.encode_canonical(signed)

  # Generate the RSA signature.
  # Raises tuf.FormatError and TypeError.
  signature = tuf.keys.create_signature(rsakey_dict, signed)

  return signature
