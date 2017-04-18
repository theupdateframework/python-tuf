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
      # TODO: Consider more efficient measures. If the metadata format is
      # ASN.1/DER ('der'), this line performs a conversion of the data into
      # ASN.1/DER once per signature. It would be more efficient to do the
      # conversion once before the loop, and manually use lower-level
      # signature verification, but that would also be less clean.
      # If we're using JSON, then this is equally efficient and still cleaner.
      valid_sig = verify_signature_over_metadata(key, signature, signed)

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





def sign_over_metadata(
    key_dict, data,
    metadata_format=tuf.conf.METADATA_FORMAT):
  """
  <Purpose>
    Given a key and data, returns a signature over that data.

    Higher level function that wraps tuf.keys.create_signature, and works
    specifically with metadata that will be in JSON or ASN.1/DER format. See
    tuf.keys.create_signature, which this function employs, for lower level
    details.

  <Arguments>
    key_dict:
      A dictionary containing the TUF keys.  An example RSA key dict has the
      form:

      {'keytype': 'rsa',
       'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
       'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                  'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

      The public and private keys are strings in PEM format.

    data:
      Data object used by create_signature() to generate the signature.
      Acceptable format depends somewhat on tuf.conf.METADATA_FORMAT, or, if
      the optional argument is provided, metadata_format.

      This will be converted into a bytes object and passed down to
      tuf.keys.create_signature().

      In 'der' mode:
        'data' is expected to be a dictionary compliant with
        tuf.formats.ANYROLE_SCHEMA. ASN.1/DER conversion requires strictly
        defined formats.

      In 'json' mode:
        'data' can be any data that can be processed by
        tuf.formats.encode_canonical(data) can be signed. This function is
        generally intended to sign metadata (tuf.formats.ANYROLE_SCHEMA), but
        can be used more broadly.

    metadata_format: (optional; default based on tuf.conf.METADATA_FORMAT)
      If 'json', treats data as a JSON-friendly Python dictionary to be turned
      into a canonical JSON string and then encoded as utf-8 before signing.
      When operating TUF with DER metadata but checking the signature on some
      piece of JSON for some reason, this should be manually set to 'json'. The
      purpose of this canonicalization is to produce repeatable signatures
      across different platforms and Python key dictionaries (avoiding things
      like different signatures over the same dictionary).
      If 'der', the data will be converted into ASN.1, encoded as DER,
      and hashed. The signature is then checked against that hash.

  <Exceptions>
    tuf.FormatError, if 'key_dict' is improperly formatted.

    tuf.UnsupportedLibraryError, if an unsupported or unavailable library is
    detected.

    TypeError, if 'key_dict' contains an invalid keytype.

  <Side Effects>
    The cryptography library specified in 'tuf.conf' is called to do the actual
    verification. When in 'der' mode, argument data is converted into ASN.1/DER
    in order to verify it. (Argument object is unchanged.)

  <Returns>
    A signature dictionary conformant to 'tuf.format.SIGNATURE_SCHEMA'. e.g.:
    {'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
     'method': '...',
     'sig': '...'}.

  """

  tuf.formats.ANYKEY_SCHEMA.check_match(key_dict)
  # TODO: Check format of data, based on metadata_format.
  # TODO: Consider checking metadata_format redundantly. It's checked below.

  if metadata_format == 'json':
    data = tuf.formats.encode_canonical(data).encode('utf-8')

  elif metadata_format == 'der':

    # TODO: Have convert_signed_metadata_to_der take just the 'signed' element
    # so we don't have to do this silly wrapping in an empty signable.
    data = asn1_codec.convert_signed_metadata_to_der(
        {'signed': data, 'signatures': []}, only_signed=True)
    data = hashlib.sha256(data).digest()

  else:
    raise tuf.Error('Unsupported metadata format: ' + repr(metadata_format))


  return tuf.keys.create_signature(key_dict, data)





def verify_signature_over_metadata(
    key_dict, signature, data, metadata_format=tuf.conf.METADATA_FORMAT):
  """
  <Purpose>
    Determine whether the private key belonging to 'key_dict' produced
    'signature'. tuf.keys.verify_signature() will use the public key found in
    'key_dict', the 'method' and 'sig' objects contained in 'signature',
    and 'data' to complete the verification.

    Higher level function that wraps tuf.keys.verify_signature, and works
    specifically with metadata that will be in JSON or ASN.1/DER format.

    See tuf.keys.verify_signature for lower level details.

  <Arguments>
    key_dict:
      A dictionary containing the TUF keys and other identifying information.
      If 'key_dict' is an RSA key, it has the form:

      {'keytype': 'rsa',
       'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
       'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                  'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}

      The public and private keys are strings in PEM format.

    signature:
      The signature dictionary produced by one of the key generation functions.
      'signature' has the form:

      {'keyid': 'f30a0870d026980100c0573bd557394f8c1bbd6...',
       'method': 'method',
       'sig': sig}.

      Conformant to 'tuf.formats.SIGNATURE_SCHEMA'.

    data:
      Data object over which the validity of the provided signature will be
      checked by verify_signature().

      Acceptable format depends somewhat on tuf.conf.METADATA_FORMAT, or, if
      the optional argument is provided, metadata_format.

      This will be converted into a bytes object and passed down to
      tuf.keys.verify_signature().

      In 'der' mode:
        'data' is expected to be a dictionary compliant with
        tuf.formats.ANYROLE_SCHEMA. ASN.1/DER conversion requires strictly
        defined formats.

      In 'json' mode:
        'data' can be any data that can be processed by
        tuf.formats.encode_canonical(data). This function is generally intended
        to verify signatures over TUF metadata (tuf.formats.ANYROLE_SCHEMA),
        but can be used more broadly when in 'json' mode.

    metadata_format: (optional; default based on tuf.conf.METADATA_FORMAT)
      If 'json', treats data as a JSON-friendly Python dictionary to be turned
      into a canonical JSON string and then encoded as utf-8 before checking
      against the signature. When operating TUF with DER metadata but checking
      the signature on some piece of JSON for some reason, this should be
      manually set to 'json'. The purpose of this canonicalization is to
      produce repeatable signatures across different platforms and Python key
      dictionaries (avoiding things like different signatures over the same
      dictionary).

      If 'der', the data will be converted into ASN.1, encoded as DER,
      and hashed. The signature is then checked against that hash.

  <Exceptions>
    tuf.FormatError, raised if either 'key_dict' or 'signature' are improperly
    formatted.

    tuf.UnsupportedLibraryError, if an unsupported or unavailable library is
    detected.

    tuf.UnknownMethodError.  Raised if the signing method used by
    'signature' is not one supported.

  <Side Effects>
    The cryptography library specified in 'tuf.conf' is called to do the actual
    verification. When in 'der' mode, argument data is converted into ASN.1/DER
    in order to verify it. (Argument object is unchanged.)

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """

  tuf.formats.ANYKEY_SCHEMA.check_match(key_dict)
  tuf.formats.SIGNATURE_SCHEMA.check_match(signature)
  # TODO: Check format of data, based on metadata_format.
  # TODO: Consider checking metadata_format redundantly. It's checked below.

  if metadata_format == 'json':
    data = tuf.formats.encode_canonical(data).encode('utf-8')

  elif metadata_format == 'der':

    # TODO: Have convert_signed_metadata_to_der take just the 'signed' element
    # so we don't have to do this silly wrapping in an empty signable.
    data = asn1_codec.convert_signed_metadata_to_der(
        {'signed': data, 'signatures': []}, only_signed=True)
    data = hashlib.sha256(data).digest()

  else:
    raise tuf.Error('Unsupported metadata format: ' + repr(metadata_format))


  return tuf.keys.verify_signature(key_dict, signature, data)
