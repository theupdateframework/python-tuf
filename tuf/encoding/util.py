#!/usr/bin/env python

"""
<Program Name>
  util.py

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  tuf.encoding.util performs serialization and deserialization of JSON and
  ASN.1/DER, using existing functions in securesystemslib.util for JSON and
  asn1crypto for ASN.1.

  Provides:
    serialize()
    deserialize_der()
    deserialize()
    deserialize_der_file()
    deserialize_file()
"""

# Support some Python 3 style and functionality in Python 2 (example: print())
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import logging

import six
import asn1crypto.core

import securesystemslib
import securesystemslib.formats
import securesystemslib.util
import tuf
import tuf.formats
import tuf.encoding.asn1_convert as asn1_convert
import tuf.encoding.asn1_metadata_definitions as asn1_defs

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf_util')


def serialize(obj):
  """
  <Purpose>
    Encode an asn1crypto object or JSON-compatible dictionary as bytes, in the
    serialized form of that object:
      If obj is an asn1crypto object, it is converted to ASN.1/DER bytes.
      If obj is a dictionary, it is converted into UTF-8-encoded JSON bytes.

    Wrapper for 'securesystemslib.formats.encode_canonical()' and the
    asn1crypto method 'dump()'.

  <Arguments>
    obj
      an asn1crypto object or JSON-compatible dictionary.
      # TODO: Consider defining what makes a dict JSON-compatible somewhere and
      #       referencing that here....

  <Exceptions>
    tuf.exceptions.Error if both attempts to deserialize from JSON and DER fail.

  <Returns>
    If given JSON data, returns a dictionary.
    Otherwise, if given ASN.1/DER data, returns an asn1crypto object.
  """

  if isinstance(obj, asn1crypto.core.Asn1Value):
    # If the given object is an asn1crypto object, then it has a dump() method
    # that returns the serialized DER bytes that represent the ASN.1 object.
    return obj.dump()

  elif isinstance(obj, dict):
    # If the given object is instead a dictionary, assume it is a dictionary
    # that can be converted to canonicalized JSON and encoded as UTF-8.
    return securesystemslib.formats.encode_canonical(obj).encode('utf-8')

  else:
    raise tuf.exceptions.FormatError(
        'Received an object that appears to be neither an asn1crypto object '
        'nor a dictionary.')

# def serialize_json(dictionary):
#   return securesystemslib.formats.encode_canonical(dictionary).encode('utf-8')





def deserialize(data, convert=True):
  """
  <Purpose>
    bytes encoding JSON or ASN.1/DER -> dictionary or asn1crypto object


    Wrapper for deserialize_json and deserialize_der. Also see docstrings there.

    Deserializes the given bytes of ASN.1/DER or JSON/UTF-8.
    Produces an asn1crypto object (from ASN.1) or dictionary object (from JSON).

    Tries JSON UTF-8 first.  If that fails, tries ASN.1 DER.

  <Arguments>
    data
      bytes.  Data in either ASN.1/DER or JSON/UTF8.

  <Exceptions>
    tuf.exceptions.Error if both attempts to deserialize from JSON and DER fail.

  <Returns>
    If given JSON data, returns a dictionary.
    Otherwise, if given ASN.1/DER data, returns an asn1crypto object.

  """
  exception_msgs = []


  # Try JSON first.
  try:
    deserialized = deserialize_json(data)

  except tuf.exceptions.InvalidMetadataJSONError as e:
    exception_msgs.append(str(e))

  else:
    return deserialized


  # Try ASN.1 second.
  try:
    deserialized = deserialize_der(data)

  except Exception as e:
    # TODO: <~> Refine expected errors. Catch only expected DER errors...?
    exception_msgs.append(str(e))
    # TODO: Create or choose a better error class for the below.
    raise tuf.exceptions.Error(
        'Unable to deserialize given data as JSON in UTF-8 or as ASN.1 in DER. '
        'Exceptions follow: ' + str(exception_msgs))

  else:
    return deserialized





def deserialize_file(filepath, convert=True):
  """
  <Purpose>
    Deserialize a JSON or ASN.1/DER object from a file containing the object.
    Tries JSON first, and if that fails, tries ASN.1.

    Wrapper for deserialize_json_file and deserialize_der_file. Also see
    docstrings there.

    Produces an asn1crypto object (from ASN.1) or dictionary object (from JSON).

  <Arguments>
    filepath
      The path of a file containing data in either ASN.1/DER or JSON/UTF8.

    convert
      boolean, optional.  If True, converts ASN.1/DER data into JSON-compatible
      dictionaries, the old TUF internal format, matching the specification.
      Note that if this is done and there are signatures in the given data,
      those signatures will still be signed over whatever format they were
      signed over, and you should make sure to check them over the right format.

      # TODO: Consider marking signatures here, if the file given has a
      #       'signatures' element at the top level, and elements under it,
      #       by adding an 'over_der' field to each signature, and adding a
      #       tuf.formats.SIGNATURE_SCHEMA that takes over for
      #       securesystemslib.formats.SIGNATURE_SCHEMA and includes an optional
      #       element 'over_der'.  All uses of
      #       securesystemslib.formats.SIGNATURE_SCHEMA in TUF should then be
      #       switched.

  <Exceptions>
    tuf.exceptions.FormatError:
      if 'filepath' is improperly formatted.

    securesystemslib.exceptions.FormatError:
      if 'filepath' is improperly formatted according to securesystemslib but
      not according to tuf (unexpected, may occur if code changes).

    tuf.exceptions.Error:
      if 'filepath' cannot be deserialized to a Python object.

    IOError:
      if file manipulation fails due to IO errors.

    tuf.exceptions.Error:
      if both attempts to deserialize from JSON and DER fail

  <Returns>
    If given JSON data, returns a dictionary.
    Otherwise, if given ASN.1/DER data, returns an asn1crypto object.
  """

  # Making sure that the format of 'filepath' is a path string.
  # tuf.FormatError is raised on incorrect format.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  exception_msgs = []

  deserialized = None

  # Try JSON first.  (Quite a bit less work while blind.)
  try:
    deserialized = deserialize_json_file(filepath) # securesystemslib.util.load_json_file(filepath)

  except securesystemslib.exceptions.Error as e:
    exception_msgs.append(str(e))


  if deserialized is None:
    # Try ASN.1/DER second.
    try:
      deserialized = deserialize_der_file(filepath)

    except (tuf.exceptions.Error, securesystemslib.exceptions.Error) as e:
      exception_msgs.append(str(e))
      raise tuf.exceptions.Error(
          'Unable to deserialize given data as JSON in UTF-8 or as ASN.1 in '
          'DER.  Exceptions follow: ' + str(exception_msgs))


  logger.debug('Successfully read data from filepath ' + str(filepath))
  return deserialized





def deserialize_json_file(filepath):
  """
  <Purpose>
    Read in a utf-8-encoded JSON file and return a dictionary object with the
    parsed JSON data.

    Currently just uses securesystemslib.util.load_json_file.

  <Arguments>
    filepath:
      Path of DER file.

  <Exceptions>
    tuf.exceptions.Error:
      if 'filepath' cannot be deserialized to a Python object.

    IOError:
      if file manipulation fails due to IO errors.

    tuf.exceptions.Error:
      if the contents of filepath cannot be deserialized to a Python object.

  <Side Effects>
    None.

  <Return>
    An asn1crypto object deserialized from the DER data in the file whose path
    was provided,
  """
  return securesystemslib.util.load_json_file(filepath)





def deserialize_der_file(filepath):
  """
  <Purpose>
    Read in an ASN.1/DER file and return an asn1crypto object containing the
    translated contents of the DER file.

  <Arguments>
    filepath:
      Path of DER file.

  <Exceptions>
    tuf.exceptions.Error:
      if 'filepath' cannot be deserialized to a Python object.

    IOError:
      if file manipulation fails due to IO errors.

    tuf.exceptions.Error:
      if the contents of filepath cannot be deserialized to a Python object.

  <Side Effects>
    None.

  <Return>
    An asn1crypto object deserialized from the DER data in the file whose path
    was provided,

    # NO: Trying something different
    # #  in TUF's standard format, conforming to
    # # tuf.formats.SIGNABLE_SCHEMA, where the 'signed' entry matches
    # # tuf.formats.ANYROLE_SCHEMA (though conversion of the Mirrors role is not
    # # supported).
    # # The signatures contained in the returned dictionary (the 'signatures'
    # # entry), if any, will have been unchanged. If, for example, the signatures
    # # were over a DER object, they will remain that way, even though the 'signed'
    # # portion will no longer be in DER.
  """

  # Making sure that the format of 'filepath' is a path string.
  # tuf.FormatError is raised on incorrect format.
  securesystemslib.formats.PATH_SCHEMA.check_match(filepath)

  logger.debug('Reading file ' + str(filepath))
  with open(filepath, 'rb') as fobj:
    data = fobj.read()

  # Decode the DER into an abstract asn1crypto ASN.1 representation of its data,


  # NO: trying something new.
  # # then convert that into a basic Python dictionary representation of the
  # # data within.

  return deserialize_der(data)





def deserialize_json(data):
  """
  <Purpose>
    Deserializes the given bytes of utf-8-encoded JSON into a dictionary.

  <Arguments>
    data
      bytes.  JSON data encoded as utf-8.

  <Exceptions>
    tuf.exceptions.InvalidMetadataJSONError
      if unable to decode data as utf-8, or unable to parse resulting string
      as valid JSON.

  <Returns>
    Deserialized object, as a dictionary.
  """

  # TODO: Format check on data.

  try:
    deserialized = securesystemslib.util.load_json_string(data.decode('utf-8'))

  except (
      securesystemslib.exceptions.InvalidMetadataJSONError,   # never raised?
      securesystemslib.exceptions.Error,        # takes the place of the former
      UnicodeDecodeError) as e:                 # if not valid utf-8
    # raise tuf.exceptions.InvalidMetadataJSONError('Cannot parse as JSON+utf8.') from e   # Python3-only
    raise tuf.exceptions.InvalidMetadataJSONError(str(e))

    # NOTE: Unit testing should try "\xfc\xa1\xa1\xa1\xa1\xa1", which is not
    #       valid utf-8, but is valid octet string.

  else:
    return deserialized





def deserialize_der(data, datatype=None):
  """
  <Purpose>
    Deserializes the given bytes of ASN.1/DER into an asn1crypto object.

    Can be called without the datatype of the object to be deserialized known,
    but will attempt to guess several types in order to avoid returning the
    result of a blind conversion (a conversion that does not know the expected
    datatype).

    See docstring of tuf.encoding.asn1_convert.asn1_from_der() to have the
    difference explained.

    If datatype is None, attempts to avoid blind conversion by trying to
    interpret the given data as, first, role metadata, then, second, a signing
    envelope around role metadata.

    If both fail, returns the results of the blind conversion.

    This function will validate its output: whatever deserialized data it
    produces will only be returned if serializing that data produces the
    original bytes (variable 'data').

  <Arguments>
    data
      bytes.  Data in ASN.1/DER format.

    datatype  (optional)
      A subclass of asn1crypto.core.Asn1Value, the type of data expected to
      be returned.

  <Exceptions>
    tuf.exceptions.ASN1ConversionError
      if a deserialized object is produced, but that object does not produce
      the original bytes ('data') when serialized again.

    asn1crypto errors or tuf.exceptions.ASN1ConversionError
      if DER deserialization fails otherwise.
    # TODO: delineate the above errors?

  <Returns>
    Deserialized object, as an asn1crypto object.
  """

  # TODO: Format check on data.

  deserialized = None

  # If we were told the datatype, then convert expecting that type.
  if datatype is not None:

    if not issubclass(datatype, asn1crypto.core.Asn1Value):
      raise tuf.exceptions.FormatError(
          'Received a datatype that was not an asn1crypto class.')

    deserialized = asn1_convert.asn1_from_der(data, datatype)


  else:      # datatype is None, so we must be clever

    # ABANDONED STRATEGY 1:  No: do not just blind load.
    # # If we were NOT told the datatype, get creative. Attempt a blind conversion,
    # # not knowing what datatype the encoded object is (the data definition).  See
    # # asn1_from_der docstring for the differences.
    # deserialized = asn1_convert.asn1_from_der(data)

    # Given the result of the blind conversion, attempt to deduce the type from
    # the converted data in a few ways....

    # (It would be nice to look for a '_type' field in the data or a '_type'
    #  field under the object in a 'signed' field in the data, but we can't,
    #  because, after a blind conversion, we don't have field names.)
    # # if '_type' in deserialized:
    # #   datatype = interpret_datatype(deserialized['_type'].native)
    # # else if 'signed' in deserialized and '_type' in deserialized['signed']:
    # #   datatype = interpret_datatype(deserialized['signed']['_type'].native)


    # ABANDONED STRATEGY 2: No.  Do not try creating an additional level of
    #                       Choice on top of the objects. This has to be part of
    #                       the original DER we're now loading. Try AnyEnvelope
    #                       and AnyMetadata.  These are guaranteed to have a
    #                       '_type' field somewhere that defines their metadata
    #                       type.
    # asn1_obj = None
    # datatype_str = None
    # is_envelope = None
    #
    # try:
    #   asn1_obj = asn1_convert.asn1_from_der(data, asn1_defs.AnyEnvelope)
    #   datatype_str = asn1_obj.native['signed']['_type']
    #   is_envelope = True
    #
    # except:
    #   # TODO: Refine the expected exceptions from the above.
    #   # It looks like ValueError, btw, when unexpected structures are encountered.
    #   pass
    #
    # # Note that we check for the success of the parsing of datatype_str as well,
    # # since asn1crypto will still provide an object in some circumstances if the
    # # parsing failed to produce a coherent object.  Trying to use asn1_obj.native
    # # or asn1_obj.debug() is the easiest way to check.
    # # I think this is related to a kind of lazy parsing in which some checks are
    # # skipped for speed....
    # if asn1_obj is None or datatype_str is None or is_envelope is None:
    #   try:
    #     asn1_obj = asn1_convert.asn1_from_der(data, asn1_defs.AnyMetadata)
    #     datatype_str = asn1_obj.native['_type']
    #     is_envelope = False
    #
    #   except:
    #     # TODO: Refine the expected exceptions from the above.
    #     pass
    #
    # # If neither of those succeeded, give up and return the results of a blind
    # # conversion.
    # if asn1_obj is None or datatype_str is None or is_envelope is None:
    #   return asn1_convert.asn1_from_der(data)
    #
    #
    # # If one of those succeeded, then asn1_obj is now either a Choice object that
    # # is an AnyMetadata or an AnyEnvelope, and datatype_str contains all we need
    # # to re-parse the object with the correct subclasses and field names.
    # datatype = _interpret_datatype(datatype_str, is_envelope)
    # return asn1_convert.asn1_from_der(data, datatype)


    # Strategy 3: Just try every role type metadata definition individually....
    # This is presumably quite slow, so they're in order of likely access.
    for datatype in [
        asn1_defs.RootEnvelope,
        asn1_defs.TimestampEnvelope,
        asn1_defs.SnapshotEnvelope,
        asn1_defs.TargetsEnvelope,
        asn1_defs.RootMetadata,
        asn1_defs.TimestampMetadata,
        asn1_defs.SnapshotMetadata,
        asn1_defs.TargetsMetadata]:

      try:
        deserialized = asn1_convert.asn1_from_der(data, datatype)

      except (tuf.exceptions.ASN1ConversionError, ValueError):
        # Note that asn1crypto often raises ValueError if parsing fails.
        continue


  # If NONE of those succeeded, then give up and return the results of a blind
  # conversion.
  if deserialized is None:
    logger.debug(
        'Failed to interpret ASN.1/DER as role metadata.  Converting into '
        'generic asn1crypto object (no field data or subclass data).')
    deserialized = asn1_convert.asn1_from_der(data)


  # Regardless of how we produced the deserialized object, we must now do
  # consistency checking, as asn1crypto is a little bit too happy to produce
  # something when the data doesn't actually make sense.
  # Our primary expectation is that if we try to serialize the data again, we
  # get the same thing we loaded.
  der_sanity_check(deserialized, data)

  # If it worked, return the object....
  logger.debug('Successfully interpreted ASN.1/DER as ' + str(datatype))
  return deserialized





def der_sanity_check(asn1_obj, expected_der_bytes):
  """
  Raises tuf.exceptions.ASN1ConversionError if the given asn1_obj does not
  serialize to produce the expected DER bytes.
  Intended as helper function for deserialize_der().
  """
  # First, force some lazy loading to complete.  This also sometimes raises
  # errors if the object is malformed.
  try:
    asn1_obj.contents
  except Exception:
    raise tuf.exceptions.ASN1ConversionError(
        'Attempted deserialization of ASN.1/DER data resulted in an asn1crypto '
        'object which was not as expected (would not serialize back to the '
        'same data.')

  if asn1_obj.dump() != expected_der_bytes:
    raise tuf.exceptions.ASN1ConversionError(
        'Attempted deserialization of ASN.1/DER data resulted in an asn1crypto '
        'object which was not as expected (would not serialize back to the '
        'same data.')





# This was used for Abandoned Strategy 2 in deserialize_der.
# def _interpret_datatype(datatype_str, is_envelope):
#   """
#   Converts role type string to a type of asn1crypto object for that role type.
#
#   e.g. 'root' to type tuf.encoding.asn1_metadata_definitions.RootMetadata
#   """
#   datatype_str = datatype_str.lower()
#
#   if datatype_str == 'root':
#     if is_envelope:
#       return tuf.encoding.asn1_metadata_definitions.RootEnvelope
#     else:
#       return tuf.encoding.asn1_metadata_definitions.RootMetadata
#
#   elif datatype_str == 'timestamp':
#     if is_envelope:
#       return tuf.encoding.asn1_metadata_definitions.TimestampEnvelope
#     else:
#       return tuf.encoding.asn1_metadata_definitions.TimestampMetadata
#
#   elif datatype_str == 'snapshot':
#     if is_envelope:
#       return tuf.encoding.asn1_metadata_definitions.SnapshotEnvelope
#     else:
#       return tuf.encoding.asn1_metadata_definitions.SnapshotMetadata
#
#   elif datatype_str == 'targets':
#     if is_envelope:
#       return tuf.encoding.asn1_metadata_definitions.TargetsEnvelope
#     else:
#       return tuf.encoding.asn1_metadata_definitions.TargetsMetadata
#
#   else:
#     # TODO: Consider a different exception class.  UnknownRoleError is used
#     #       pretty differently in other parts of the code.
#     raise tuf.exceptions.UnknownRoleError(
#         'Given type string, "' + datatype_str + '" matches no known datatype.')
