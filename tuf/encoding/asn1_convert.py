#!/usr/bin/env python

"""
<Program Name>
  asn1_convert.py

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide conversion functions to create ASN.1 metadata from TUF's usual
  JSON-compatible internal metadata format, and vice versa.
"""

# Support some Python3 functionality in Python2:
#    Support print as a function (`print(x)`).
#    Do not use implicit relative imports.
#    Operator `/` performs float division, not floored division.
#    Interpret string literals as unicode. (Treat 'x' like u'x')
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# Standard Library Imports
import binascii # for bytes -> hex string conversions
# Dependency Imports
import asn1crypto as asn1
import asn1crypto.core as asn1_core
import pyasn1
import pyasn1.type.univ as pyasn1_univ
import pyasn1.type.char as pyasn1_char
import pyasn1.type.namedtype as pyasn1_namedtype
import pyasn1.codec.der.encoder as pyasn1_der_encoder
import pyasn1.codec.der.decoder as pyasn1_der_decoder
# TUF Imports
import tuf
import tuf.formats
import tuf.encoding
import tuf.encoding.asn1_metadata_definitions as asn1_definitions
import tuf.exceptions


# DEBUG ONLY; remove.
DEBUG_MODE = True
recursion_level = -1
def debug(msg):
  if DEBUG_MODE:
    print('R' + str(recursion_level) + ': ' + msg)


def asn1_to_der(asn1_obj):
  """
  Encode any ASN.1 (in the form of an asn1crypto object) as DER (Distinguished
  Encoding Rules), suitable for transport.

  Note that this will raise asn1crypto errors if the encoding fails.
  """
  # TODO: Perform some minimal validation of the incoming object.
  # TODO: Investigate the scenarios in which this could potentially result in
  # BER-encoded data. (Looks pretty edge case.) See:
  # https://github.com/wbond/asn1crypto/blob/master/docs/universal_types.md#basic-usage
  return asn1_obj.dump()





def asn1_from_der(der_obj, datatype=None):
  """
  Decode ASN.1 in the form of DER-encoded binary data (Distinguished Encoding
  Rules), into an asn1crypto object representing abstract ASN.1 data.

  Reverses asn1_to_der.

  Arguments:

    der_obj:
      bytes.  A DER encoding of asn1 data.  (BER-encoded data may be
      successfully decoded but should not be used in TUF.)

    datatype:  (optional)
      the class of asn1 data expected.  This should be compatible with
      asn1crypto asn1 object classes (e.g. from asn1_metadata_definitions.py).

      If datatype is not provided, the data will be decoded but might fail to
      match the structure expected: e.g.:
        - Instances of custom subclasses of Sequence will just be read as
          instances of Sequence.
        - Field names won't be captured. e.g. a Signature object will look like
          an asn1 representation of this:
            {'0':     b'1234...', '1':      'rsa...', '2':     'abcd...'}
          instead of an asn1 representation of this:
            {'keyid': b'1234...', 'method': 'rsa...', 'value': 'abcd...'}

  """
  # Make sure der_obj is bytes or bytes-like:
  if not hasattr(der_obj, 'decode'):
    raise TypeError(
        'asn1_from_der expects argument der_obj to be a bytes or bytes-like '
        'object, providing method "decode".  Provided object has no "decode" '
        'method.  der_obj is of type: ' + str(type(der_obj)))

  if datatype is None:
    # Generic load DER as asn1
    return asn1_core.load(der_obj)

  else:
    # Load DER as asn1, interpreting it as a particular structure.
    return datatype.load(der_obj)





def pyasn1_to_der(pyasn1_object):
  """
  Encode any ASN.1 (in the form of a pyasn1 object) as DER (Distinguished
  Encoding Rules), suitable for transport.

  Note that this will raise pyasn1 errors if the encoding fails.
  """
  # TODO: Perform some minimal validation of the incoming object.

  return pyasn1_der_encoder.encode(pyasn1_object)





def pyasn1_from_der(der_object):
  """
  Decode ASN.1 in the form of DER-encoded binary data (Distinguished Encoding
  Rules), into a pyasn1 object representing abstract ASN.1 data.

  Reverses pyasn1_to_der.

  # TODO: The following note is not quite accurate....  There are multiple
  # ways to do this.  This will probably not be here in the end, in any event.
  # This requires that the types and structure defined in the DER be known to
  # pyasn1.  They're imported here from module
  # tuf.encoding.asn1_metadata_definitions.

  Note that this will raise pyasn1 errors if the decoding fails.
  """
  pyasn1_object, remainder = pyasn1_der_decoder.decode(der_object)

  # Finding a remainder means that only part of the data could be decoded,
  # which is a failure.
  if remainder:
    # TODO: Create appropriate error class for DER encoding/decoding errors.
    #       Consider catching pyasn1 errors here and raising that instead.
    raise tuf.Error(
        'Unexpected remainder present in ASN.1/DER decode: ' + remainder)

  return pyasn1_object





def hash_to_pyasn1(function, digest):
  """
  Converts a JSON-compatible dictionary representing a single hash with its
  hash function named, into a pyasn1-compatible ASN.1 object containing the
  same data.

  Converts:
      tuf.formats.HASHDICT_SCHEMA
          HASHDICT_SCHEMA = SCHEMA.DictOf(
              key_schema = SCHEMA.AnyString(),
              value_schema = SCHEMA.RegularExpression(r'[a-fA-F0-9]+'))
  to:
      tuf.encoding.asn1_metadata_definitions.Hash:
          Hash ::= SEQUENCE {
              function            VisibleString,
              digest              OCTET STRING
          }
  """
  tuf.formats.HASH_SCHEMA.check_match(digest)
  tuf.formats.NAME_SCHEMA.check_match(function)

  hash_pyasn1 = asn1_definitions.Hash()
  hash_pyasn1['function'] = function
  hash_pyasn1['digest'] = hex_str_to_pyasn1_octets(digest)

  return hash_pyasn1





def hashes_to_pyasn1(hashes):
  """
  Converts a JSON-compatible dictionary representing a dictionary of hashes of
  different types (i.e. using different functions) into a pyasn1-compatible
  ASN.1 list object containing the same data -- specifically, the pyasn1 object
  contains hash-function-and-hash-digest pairs.

  # NOT CORRECT:
  # Since there is no order implicit in the dictionary provided, and we're
  # producing a list that will be ordered by nature, The list produced will be
  # sorted in alphabetical order by hash function name.

  Converts:
      tuf.formats.HASHDICT_SCHEMA
          HASHDICT_SCHEMA = SCHEMA.DictOf(
              key_schema = SCHEMA.AnyString(),
              value_schema = SCHEMA.RegularExpression(r'[a-fA-F0-9]+'))
  to:
      SEQUENCE OF tuf.encoding.asn1_metadata_definitions.Hash, where
          Hash ::= SEQUENCE {
              function            VisibleString,
              digest              OCTET STRING
          }
  """
  tuf.formats.HASHDICT_SCHEMA.check_match(hashes)

  # Construct the new pyasn1 object, a list of Hash objects
  # DEBUGGING ONLY, DO NOT MERGE!!
  #  hashes_pyasn1 = pyasn1_univ.Set()
  hashes_pyasn1 = asn1_definitions.Hashes()

  # Index of the hash we're currently converting in the new list (Sequence).
  num_hashes = 0

  # In the absence of an implicit order, sort the hash functions (keys in the
  # dict) by hash function name.
  # TODO: Is this appropriate? What are the implications for other implementers?
  sorted_list_of_hash_funcs = sorted(list(hashes))

  for hash_func in sorted_list_of_hash_funcs:
    # Create a new pyasn1 Hash object for each entry in the JSON-compatible
    # dictionary of hashes, and populate it.  Then add it to the set (pyasn1
    # Set) of Hash objects we're constructing.
    hashes_pyasn1[num_hashes] = hash_to_pyasn1(hash_func, hashes[hash_func])
    num_hashes += 1

  return hashes_pyasn1







def public_key_to_pyasn1(public_key_dict):
  """
  from   tuf.formats.KEY_SCHEMA (public key only)
  to     tuf.encoding.asn1_metadata_definitions.PublicKey
  """
  tuf.formats.KEY_SCHEMA.check_match(public_key_dict)

  # TODO: normalize this case.  Should have PUBLIC_KEY_SCHEMA in formats.py,
  # even if it overlaps with KEY_SCHEMA or other schemas.  Make it sensible.
  # Then this will just be a tuf.formats.PUBLIC_KEY_SCHEMA.check_match() call,
  # whether it replaces the previous one or is a second check_match on the same
  # arg.
  if 'private' in public_key_dict['keyval']:

    # TODO: Clean this conditional up! Removing an empty 'private' value is
    # not ideal, and might change the keyid based on how we currently calculate
    # keyids.... Empty strings don't seem to be OK as OctetStrings, though, so
    # for now, we're doing this....
    if not public_key_dict['keyval']['private']:
      del public_key_dict['keyval']['private']
    else:
      raise tuf.exceptions.FormatError('Expected public key, received key dict '
          'containing a private key entry!')

  # TODO: Intelligently handle PEM-style RSA keys, which have value set to an
  # ASCII-prefixed Base64 string like:
  #    '-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQE...'
  # while also handling ed25519 keys, which have hexstring values. For now,
  # we're using VisibleString inefficiently, for easy compatibility with both.
  key_pyasn1 = asn1_definitions.PublicKey()
  key_pyasn1['keytype'] = public_key_dict['keytype']
  key_pyasn1['scheme'] = public_key_dict['scheme']

  # Field key-id-hash-algorithms has some structure to it.
  algos_pyasn1 = asn1_definitions.KeyIDHashAlgorithms()

  i = 0
  for algo in public_key_dict['keyid_hash_algorithms']:
    algos_pyasn1[i] = algo
    i += 1

  key_pyasn1['keyid-hash-algorithms'] = algos_pyasn1

  # Field 'keyval' has some structure to it.
  keyvals_pyasn1 = pyasn1_univ.Set(componentType=asn1_definitions.KeyValue())
  i = 0
  for valtype in public_key_dict['keyval']:
    keyval_pyasn1 = asn1_definitions.KeyValue()
    # OctetString handling for ed25519 keys, if definitions use OCTET STRING
    # keyval_pyasn1['public'] = pyasn1_univ.OctetString(
    #     hexValue=public_key_dict['keyval'][valtype])
    keyval_pyasn1['public'] = public_key_dict['keyval'][valtype]
    keyvals_pyasn1[i] = keyval_pyasn1
    i += 1

    key_pyasn1['keyval'] = keyvals_pyasn1

# STACK POP: WORKING HERE

# STACK POP: WORKING HERE






def hex_str_to_pyasn1_octets(hex_string):
  """
  Convert a hex string into a pyasn1 OctetString object.
  Example arg: '12345abcd'  (string / unicode)
  Returns a pyasn1.type.univ.OctetString object.
  """
  # TODO: Verify hex_string type.
  tuf.formats.HEX_SCHEMA.check_match(hex_string)

  if len(hex_string) % 2:
    raise tuf.exceptions.ASN1ConversionError(
        'Expecting hex strings with an even number of digits, since hex '
        'strings provide 2 characters per byte.  We prefer not to pad values '
        'implicitly.')

  # Should be a string containing only hexadecimal characters, e.g. 'd3aa591c')
  octets_pyasn1 = pyasn1_univ.OctetString(hexValue=hex_string)

  if isinstance(octets_pyasn1._value, pyasn1.type.base.NoValue):
    # Note that pyasn1 tends to ignore arguments it doesn't expect, rather than
    # raising errors, preferring to produce invalid values that can result in
    # delayed and confusing debugging, so it's better to check this here.

    # TODO: Create an appropriate error type for pyasn1 conversions.
    raise tuf.Error(
        'Conversion of hex string to pyasn1 octet string failed: noValue '
        'returned when converting ' + hex_string)

  return octets_pyasn1




def hex_str_from_pyasn1_octets(octets_pyasn1):
  """
  Convert a pyasn1.type.univ.OctetString object into a hex string.
  Example return:   '4b394ae2' (string / unicode)
  Raises Error() if an individual octet's supposed integer value is out of
  range (0 <= x <= 255).
  """
  octets = octets_pyasn1.asNumbers()
  hex_string = ''

  for x in octets:
    if x < 0 or x > 255:
      raise tuf.exceptions.ASN1ConversionError(
          'Unable to generate hex string from OctetString: integer value of '
          'octet provided is not in range: ' + str(x))
    hex_string += '%.2x' % x

  # Make sure that the resulting value is a valid hex string.
  tuf.formats.HEX_SCHEMA.check_match(hex_string)

  return hex_string





def hex_str_to_asn1_octets(hex_string, datatype=asn1_core.OctetString):
  """
  Convert a hex string into an asn1 OctetString object, or, optionally, a
  subclass of OctetString passed in as argument 'datatype'.

  <Arguments>
    hex_string
      string/unicode; the string to interpret as bytes and convert, e.g.
      '12345abcd'

    datatype    (optional)
      type/class; must be a subclass of asn1_core.OctetString; if provided, an
      instance of this class will be created and returned instead of an
      OctetString.

  <Returns>
    An object of type 'datatype', an ASN.1 representation of the hex_string
    provided.  The returned object will be an instance of asn1_core.OctetString
    or of a subclass of asn1_core.OctetString.
  """
  # TODO: Verify hex_string type.
  tuf.formats.HEX_SCHEMA.check_match(hex_string)
  if not issubclass(datatype, asn1_core.OctetString):
    raise tuf.exceptions.ASN1ConversionError(
        'hex_str_to_asn1_octets is only able to convert to '
        'asn1_core.OctetString or a subclass thereof.  The provided datatype '
        '"' + str(datatype) + '" is not a subclass of asn1_core.OctetString.')

  if len(hex_string) % 2:
    raise tuf.exceptions.ASN1ConversionError(
        'Expecting hex strings with an even number of digits, since hex '
        'strings provide 2 characters per byte.  We prefer not to pad values '
        'implicitly.')

  # Should be a string containing only hexadecimal characters, e.g. 'd3aa591c')
  octets_asn1 = datatype(bytes.fromhex(hex_string))

  return octets_asn1





def hex_str_from_asn1_octets(octets_asn1):
  """
  Convert an asn1 OctetString object into a hex string.
  Example return:   '4b394ae2'
  """
  if not isinstance(octets_asn1, asn1_core.OctetString):
    raise ValueError(
        'hex_str_from_asn1_octets expects an instance of '
        'asn1crypto.core.OctetString.  arg is a ' + str(type(octets_asn1)))

  octets = octets_asn1.native

  # Can't just use octets.hex() because that's Python3-only, so:
  hex_string = binascii.hexlify(octets).decode('utf-8')

  return hex_string





def to_pyasn1(data, datatype):
  """
  Converts an object into a pyasn1-compatible ASN.1 representation of that
  object.  Recurses, with base cases being simple types like integers or
  strings.

  Returns:
    an instance of a class specified by the datatype argument, from module
    asn1_metadata_definitions.

  Arguments:
    - a dictionary representing data to convert into ASN.1
    - the type (class) of the pyasn1-compatible class corresponding to this
      type of object, from asn1_metadata_definitions.py

  # TODO: Add max recursion depth, and possibly split this into a high-level
  # function and a recursing private helper function. Consider tying the max
  # depth to some dynamic analysis of asn1_metadata_definitions.py...? Nah?
  """
  global recursion_level # DEBUG
  recursion_level += 1 # DEBUG

  # Instantiate an object of class datatype.  This is used for introspection
  # and then replaced.
  pyasn1_obj = datatype()

  debug('to_pyasn1() called to convert to ' + str(datatype) + '. Data: '
      + str(data))

  # Check to see if it's a basic data type from among the list of basic data
  # types we expect (Integer or VisibleString in one camp; OctetString in the
  # other).  If so, re-initialize as such and return that new object.  These
  # are the base cases of the recursion.
  if isinstance(pyasn1_obj, pyasn1_univ.Integer) \
      or isinstance(pyasn1_obj, pyasn1_char.VisibleString):
    debug('Converting a (hopefully-)primitive value to: ' + str(datatype))
    pyasn1_obj = datatype(data)
    debug('Completed conversion of primitive to ' + str(datatype))
    recursion_level -= 1 # DEBUG
    return pyasn1_obj

  elif isinstance(pyasn1_obj, pyasn1_univ.OctetString):
    # If datatype is a subclass of OctetString, then, also, we discard
    # the just-initialized pyasn1_obj, re-initialize, and return the value
    # right away.
    #
    # OctetStrings require a bit more finessing due to their odd nature in
    # pyasn1, supporting the officially-undesirable use case of containing
    # simple text strings (which we will not do!).
    #
    # To use OctetString correctly, we provide binary data, either as a hex
    # string (hexValue='0123abcdef'), a base-2 binary string (binValue='0101'),
    # or a string of octets (value=b'012GH\x211').
    # Our use cases all involve hex strings.
    #
    # NOTE that if the keyword argument (e.g. hexValue) is named incorrectly
    # here, that pyasn1 WILL NOT COMPLAIN and will save the given value as a
    # sort of custom field in a NULL OctetString object, leading to odd errors
    # down the line. Be SURE that this line is correct if you change it.
    debug('Converting a (hopefully-)primitive value to ' + str(datatype))
    tuf.formats.HEX_SCHEMA.check_match(data)
    if len(data) % 2:
      raise tuf.exceptions.ASN1ConversionError(
          'Expecting hex strings with an even number of digits, since hex '
          'strings provide 2 characters per byte.  We prefer not to pad values '
          'implicitly.')
    # Don't be tempted to use hex_string_to_pyasn1_octets() here; we should
    # convert to the datatype provided, which might be some subclass of
    # pyasn1.type.univ.OctetString.
    pyasn1_obj = datatype(hexValue=data)
    debug('Completed conversion of primitive to ' + str(datatype))
    recursion_level -= 1 # DEBUG
    return pyasn1_obj


  # Else, datatype is not a basic data type of any of the list of expected
  # basic data types.  Assume either Set or Sequence?
  # There are two general possibilities here. Objects of type datatype (which
  # we must convert data into) may be either:
  #   - a list-like Sequence (or Set) of objects of the same conceptual type
  #   - a struct-like Sequence (or Set) with conceptually-distinct elements
  #
  # If the component of the Set or Sequence is a NamedTypes class, we'll assume
  # that datatype is struct-like, containing disparate elements to be mapped,
  # where each key in data indicates the field in the new object to associate
  # its value with:
  #       e.g. data = {'address': '...', 'phone_number': '...'}
  #     mapping such that:
  #       pyasn1_obj['address'] = '...'
  #       pyasn1_obj['phone_number'] = '...'
  #
  # If the component of the Sequence (Set makes a bit less sense here) is not a
  # NamedTypes class, then the resulting object will be integer-indexed, and
  # we'll assume that the elements in it are of a single conceptual type, so
  # that the mapping will look more like:
  #       e.g. data = {'Robert': '...', 'Layla': '...'}
  #     mapping such that:
  #       pyasn1_obj[0] = some conversion of ('Robert', '...')
  #       pyasn1_obj[1] = some conversion of ('Layla', '...')
  # or
  #       e.g. data = ['some info about Robert', 'some info about Layla']
  #     mapping such that:
  #       pyasn1_obj[0] = some conversion of 'some info about Robert'
  #       pyasn1_obj[1] = some conversion of 'some info about Layla'

  # Handling a struct-like datatype, with distinct named fields:
  # elif None is getattr(datatype, 'componentType', None):
  #   import pdb; pdb.set_trace()
  #   debug('debugging...')

  elif isinstance(datatype.componentType, pyasn1_namedtype.NamedTypes):
    assert isinstance(pyasn1_obj, pyasn1_univ.Sequence) or isinstance(pyasn1_obj, pyasn1_univ.Set), 'Expectation broken during drafting' # TEMPORARY, DO NOT MERGE
    debug('Converting a struct-like dict to ' + str(datatype))
    pyasn1_obj = _structlike_dict_to_pyasn1(data, datatype)
    debug('Completed conversion of struct-like dict to ' + str(datatype))
    recursion_level -= 1 # DEBUG
    return pyasn1_obj

  elif isinstance(data, list):
    assert isinstance(pyasn1_obj, pyasn1_univ.SequenceOf) or isinstance(pyasn1_obj, pyasn1_univ.SetOf), 'Expectation broken during drafting' # TEMPORARY, DO NOT MERGE
    # Converting from a list to a datatype similar to a list of
    # conceptually-similar objects, without distinct named fields.
    debug('Converting a list to ' + str(datatype))
    pyasn1_obj = _list_to_pyasn1(data, datatype)
    debug('Completed conversion of list to ' + str(datatype))
    recursion_level -= 1 # DEBUG
    return pyasn1_obj

  elif isinstance(data, dict):
    assert isinstance(pyasn1_obj, pyasn1_univ.SequenceOf) or isinstance(pyasn1_obj, pyasn1_univ.SetOf), 'Expectation broken during drafting' # TEMPORARY, DO NOT MERGE
    debug('Converting a list-like dict to ' + str(datatype))
    # Converting from a dict to a datatype similar to a list of
    # conceptually-similar objects, without distinct named fields.
    pyasn1_obj = _listlike_dict_to_pyasn1(data, datatype)
    debug('Completed conversion of list-like dict to ' + str(datatype))
    recursion_level -= 1 # DEBUG
    return pyasn1_obj

  else:
    recursion_level -= 1 # DEBUG
    raise tuf.exceptions.ASN1ConversionError(
        'Unable to determine how to automatically '
        'convert data into pyasn1 data.  Can only handle primitives to Integer/'
        'VisibleString/OctetString, or list to list-like pyasn1, or list-like '
        'dict to list-like pyasn1, or struct-like dict to struct-like pyasn1.  '
        'Source data type: ' + str(type(data)) + '; output type is: ' +
        str(datatype))




def _structlike_dict_to_pyasn1(data, datatype):
  """
  Private helper function for to_pyasn1.
  See to_pyasn1 for full docstring.
  This function handles the case wherein:

    - data is a dict
    - and objects of type datatype are:
        "struct-like", meaning that they may contain a specific number of
        named elements of potentially variable type.
        This is as opposed to a "list-like" dict, where the elements may not be
        named, will have a conceptual type in common, and the number of elements
        is variable -- beyond just specifying optional elements.
        It is assumed that:
         - datatype is pyasn1_univ.Sequence or Set, or a subclass thereof.
         - datatype.componentType is a NamedTypes object

  The mapping from data to the new object, pyasn1_obj, will try to use the same
  keys in both. '-' and '_' will be swapped as necessary (ASN.1 uses dashes in
  variable names and does not permit underscores in them, while Python uses
  underscores in variable names and does not permit dashes in them.).

  Now moot, as num- fields have been removed.
    #Additional 'num-'-prefixed elements in ASN.1 that provide the length of lists
    #will be handled (length calculated and element added).
  """

  pyasn1_obj = datatype()

  # For a datatype that is a Sequence (or Set) with named types, the
  # componentType object should be a NamedTypes object that will tell us the
  # names and types that datatype contains.
  named_types_obj = datatype.componentType
  assert isinstance(named_types_obj, pyasn1_namedtype.NamedTypes) # TEMPORARY, DO NOT MERGE; generate error instead

  # Determine how many elements objects of type datatype have.
  num_elements = len(named_types_obj)

  # Iterate over the fields in an object of type datatype.  Check to see if
  # each is in data, and feed them in if so, by recursing.
  for i in range(0, num_elements):

    # Discern the named values and the classes of the component objects.
    # We'll use the names extracted to determine which fields in data to assign
    # to each element of pyasn1_obj, and use the types to instantiate individual
    # pyasn1 objects for each.
    element_name = named_types_obj.getNameByPosition(i)
    element_type = type(named_types_obj.getTypeByPosition(i)) # not clear why this isn't already a type...

    # In ASN.1, '_' is invalid in variable names and '-' is valid. The opposite
    # is true of Python, so we swap.
    element_name_python = element_name.replace('-', '_')

    # Is there an entry in data that corresponds to this?
    if element_name_python in data:
      # If there are matching names in the source and destination structures,
      # transfer the data, recursing to instantiate a pyasn1 object of the
      # expected type.
      debug('In conversion of struct-like dict to ' + str(datatype) + ', '
          'recursing to convert subcomponent of type ' + str(element_type))
      element = to_pyasn1(data[element_name_python], element_type)
      pyasn1_obj[element_name] = element


      # Moot, as num- fields have been removed from the definitions.
      # # Note that this includes the edge case where both have an element that
      # # LOOKS like a length-of-list element beginning with 'num-'. I don't
      # # see any issues with this, though; that seems like the right behavior.

    # elif element_name.startswith('num-'):
    #   # It is okay for this element name not to appear in the source,
    #   # JSON-compatible metadata if and only if it is a length-of-list
    #   # element that is useful in the ASN.1 metadata but not in the
    #   # JSON-compatible metadata. We expect these to start with 'num-', and
    #   # we expect the rest of their names to match another element in data.
    #   # We'll populate the value using the length of the associated element
    #   relevant_element_name = element_name[4:] # whatever is after 'num-'.
    #   relevant_element_name_python = relevant_element_name.replace('-','_')

    #   if relevant_element_name_python in data:
    #     pyasn1_obj[element_name] = len(data[relevant_element_name_python])

    #   else:
    #     raise tuf.exceptions.ASN1ConversionError(
    #         'When converting dict into pyasn1, '
    #         'found an element that appeared to be a "num-"-prefixed '
    #         'length-of-list for another element; however, did not find '
    #         'corresponding element to calculate length of. Element name: ' +
    #         element_name + '; did not find element name: ' +
    #         relevant_element_name)

    else:
      # Found an element name in datatype that does not match anything in
      # data (MOOT: and does not begin with 'num-').
      raise tuf.exceptions.ASN1ConversionError(
          'Unable to convert dict into pyasn1: it '
          'seems to be missing elements.  dict does not contain "' +
          element_name + '". Datatype for conversion: ' + str(datatype) +
          '; dict contents: ' + str(data))

  return pyasn1_obj





def _list_to_pyasn1(data, datatype):
  """
  Private helper function for to_pyasn1.
  See to_pyasn1 for full docstring.
  This function handles the case wherein:

    - data is a list
    - and objects of type datatype are:
        "list-like", meaning that they may contain a variable number of
        elements of the same conceptual type. This is as opposed to a
        "struct-like" datatype where each field specifies a distinct kind of
        thing about data. The to_pyasn1 docstring and comments contain more
        explanation and examples.
  """

  pyasn1_obj = datatype() # DEBUG

  if None is getattr(datatype, 'componentType', None):
    # TODO: Determine whether or not to keep this error.
    # It's useful in debugging because the error we get if we don't
    # specifically detect this may be misleading.
    raise tuf.exceptions.ASN1ConversionError(
        'Unable to determine type of component in a '
        'list. datatype of list: ' + str(datatype) + '; componentType '
        'appears to be None')

  for i in range(0, len(data)):
    datum = data[i]

    debug('In conversion of list to type ' + str(datatype) + ', recursing '
        'to convert subcomponent of type ' + str(type(datatype.componentType)))

    pyasn1_datum = to_pyasn1(datum, type(datatype.componentType)) # Not sure why componentType is an instance, not a class....
    pyasn1_obj[i] = pyasn1_datum

  return pyasn1_obj





def _listlike_dict_to_pyasn1(data, datatype):
  """
  Private helper function for to_pyasn1.
  See to_pyasn1 for full docstring.
  This function handles the case wherein:

    - data is a dictionary
    - and objects of type datatype are:
        "list-like", meaning that they may contain a variable number of
        elements of the same conceptual type. This is as opposed to a
        "struct-like" datatype where each field specifies a distinct kind of
        thing about data. The to_pyasn1 docstring and comments contain more
        explanation and examples.

  We will re-interpret dictionary data as list elements, where each list
  element will be a 2-tuple of key, then value.

  Iterate over the key-value pairs in dict data. Convert them by recursing
  and plug them into the pyasn1 object we're constructing.
  We assume that each key-value pair in the dict is expected to be a distinct
  list element, with the key and value from the dict mapped to a first and
  second element in the resulting tuple in the outputted pyasn1 Sequence.
  We split the single dict with many keys into many dicts with one key each.
  """

  # Introspect to determine the structure of the component objects in instances
  # of class datatype (e.g., if datatype describes a list of objects of some
  # class, determine that class).
  pyasn1_obj = datatype()
  # NOTE that datatype.componentType (ostensibly the type of the component
  # elements in a Sequence/Set-style pyasn1 class) is for some reason an
  # INSTANCE of a class, NOT a type.  Furthermore, strange things happen to
  # later instantiations of datatype if you iterate through the elements of
  # the componentType instance.  That is why we use the strange type(...)()
  # logic below: we determine the class of the component, then instantiate a
  # distinct sample object for introspection. Do NOT just use:
  # sample_component_obj = datatype.componentType
  sample_component_obj = type(datatype.componentType)()
  # For each key-value pair in data (and so for each element in the Sequence
  # we're constructing), map key to the first field in the element, and value
  # to the second field in the element.
  #  Map key to the first element and value to the second element of
  # TODO: Replace use of list comprehensions.
  # debug('datatype: ' + str(datatype))
  debug('type of subcomponent of datatype: ' + str(type(sample_component_obj)))
  # debug('sample subcomponent of datatype: ' + repr(sample_component_obj))
  debug('full data: ' + str(data))

  names_in_component = [i for i in sample_component_obj]
  types_in_component = [type(sample_component_obj[i]) for i in sample_component_obj]

  # Moot: removing 'num-'-prefixed fields for now, until they are explicitly
  # necessary.
  # # Account for the possibility that the "value" in the dict is a list and thus
  # # needs a list length argument ('num-'-prefixed) to precede it in ASN.1 for
  # # the convenience of ASN.1 decoders / parsers. In this specific scenario,
  # # we'll have 3 elements instead of 2.
  # if len(names_in_component) == 3 and 'num-' not in names_in_component[1]:
  #   if 'num-' not in 

  if len(names_in_component) != 2:
    # TODO: FINISH THIS EXPLANATION OF WHY WE EXPECT 2 ELEMENTS!
    # TODO: FINISH THIS EXPLANATION OF WHY WE EXPECT 2 ELEMENTS!
    # We are assuming that we can convert in={k1: v1, k2: v2, ...} to
    # out[i][0] = k1, out[0][1] = v1,
    # TODO: more useful error message and conversion-specific exception class
    raise tuf.exceptions.ASN1ConversionError()

  i = 0
  for key in data:
    # key = key.replace('_', '-') # ASN.1 uses - instead of _ in var names.
    datum = {names_in_component[0]: key, names_in_component[1]: data[key]}

    debug('In conversion of list-like dict to type ' + str(datatype) + ', '
        'recursing to convert subcomponent of type ' +
        str(datatype.componentType))

    pyasn1_datum = to_pyasn1(datum, type(datatype.componentType)) # Not sure why componentType is an instance, not a class....
    pyasn1_obj[i] = pyasn1_datum
    i += 1

  return pyasn1_obj











def to_asn1(data, datatype):
  """
  Recursive (base case: datatype is ASN.1 version of int, str, or bytes)

  Converts an object into an asn1crypto-compatible ASN.1 representation of that
  object, using asn1crypto functionality.  In the process, we might have to do
  some data surgery, in part because ASN.1 does not support dictionaries.

  The scenarios we handle are these:
    1- datatype is primitive
    2- datatype is "list-like" (subclass of SequenceOf/SetOf) and:
      2a- data is a list
      2b- data is a "list-like" dict
    3- datatype is "struct-like" (subclass of Sequence/Set) and data is a dict

  Scenario 1: primitive
    No recursion is necessary.  We can just convert to one of these classes
    from asn1crypto.core: Integer, VisibleString, or OctetString, based on what
    datatype is / is a subclass of.  (Note that issubclass() also returns True
    if the classes given are the same; i.e. a class is its own subclass.)


  Scenario 2: "list-like" (datatype is/subclasses SequenceOf/SetOf)
    The resulting object will be integer-indexed and may be converted from
    either a list or a dict.  Length might be variable See below.

    Scenario 2a: "list-like" from list
      Each element in data will map directly into an element of the returned
      object, with the same integer indices.
          e.g. data = ['some info about Robert', 'some info about Layla']
        mapping such that:
          asn1_obj[0] = some conversion of 'some info about Robert'
          asn1_obj[1] = some conversion of 'some info about Layla'

    Scenario 2b: "list-like" from dict
      Each key-value pair in data will become a 2-tuple element in the returned
      object.
          e.g. data = {'Robert': '...', 'Layla': '...'}
        mapping such that:
          asn1_obj[0] = ('Robert', '...')
          asn1_obj[1] = ('Layla', '...')


  <Returns>
    an instance of a class specified by the datatype argument, from module
    tuf.encoding.asn1_metadata_definitions.

  <Arguments>
    data:
      dict; a dictionary representing data to convert into ASN.1
    datatype
      type; the type (class) of the asn1crypto-compatible class corresponding to
      this type of object, generally from tuf.encoding.asn1_metadata_definitions

  # TODO: Add max recursion depth, and possibly split this into a high-level
  # function and a recursing private helper function. Consider tying the max
  # depth to some dynamic analysis of asn1_metadata_definitions.py...? Nah?
  """

  debug('to_asn1() called to convert to ' + str(datatype) + '. Data: ' +
      str(data))

  global recursion_level # DEBUG
  recursion_level += 1 # DEBUG



  # Check to see if it's a basic data type from among the list of basic data
  # types we expect (Integer or VisibleString in one camp; OctetString in the
  # other).  If so, re-initialize as such and return that new object.  These
  # are the base cases of the recursion.
  if issubclass(datatype, asn1_core.Integer) \
      or issubclass(datatype, asn1_core.VisibleString):
    debug('Converting a (hopefully-)primitive value to: ' + str(datatype)) # DEBUG
    asn1_obj = datatype(data)
    debug('Completed conversion of primitive to ' + str(datatype)) # DEBUG
    recursion_level -= 1 # DEBUG
    return asn1_obj

  elif issubclass(datatype, asn1_core.OctetString):
    # If datatype is a subclass of OctetString, then we assume we have a hex
    # string as input (only because that's the only thing in TUF metadata we'd
    # want to store as an OctetString), so we'll make sure data is a hex string
    # and then convert it into bytes, then turn it into an asn1crypto
    # OctetString.
    debug('Converting a (hopefully-)primitive value to ' + str(datatype)) # DEBUG
    asn1_obj = hex_str_to_asn1_octets(data, datatype)
    debug('Completed conversion of primitive to ' + str(datatype)) # DEBUG
    recursion_level -= 1 # DEBUG
    return asn1_obj


  # Else, datatype is not a basic data type of any of the list of expected
  # basic data types.  Assume we're converting to a Sequence, SequenceOf, Set,
  # or SetOf.  The input should therefore be a list or a dictionary.

  elif not (issubclass(datatype, asn1_core.Sequence)
      or issubclass(datatype, asn1_core.Set)
      or issubclass(datatype, asn1_core.SequenceOf)
      or issubclass(datatype, asn1_core.SetOf)):
    raise tuf.exceptions.ASN1ConversionError(
        'to_asn1 is only able to convert into ASN.1 to produce the following '
        'or any subclass of the following: VisibleString, OctetString, '
        'Integer, Sequence, SequenceOf, Set, SetOf. The provided datatype "' +
        str(datatype) + '" is neither one of those nor a subclass of one.')

  elif not isinstance(data, list) and not isinstance(data, dict):
    raise tuf.exceptions.ASN1ConversionError(
      'to_asn1 is only able to convert into ASN.1 to produce the following or '
      'any subclass of the following: VisibleString, OctetString, Integer, '
      'Sequence, SequenceOf, Set, SetOf. The provided datatype "' +
      str(datatype) + '" was not a subclass of VisibleString, OctetString, or '
      'Integer, and the input data was of type "' + str(type(data)) + '", not '
      'dict or list.')


  elif (issubclass(datatype, asn1_core.SequenceOf)
      or issubclass(datatype, asn1_core.SetOf)):
    # In the case of converting to a SequenceOf/SetOf, we expect to be dealing
    # with either input that is either a list or a list-like dictionary -- in
    # either case, objects of the same conceptual type, of potentially variable
    # number.
    #
    # - Lists being converted to lists in ASN.1 are straightforward.
    #   Convert list to SequenceOf/SetOf.
    #   Each element of the list will be a datatype._child_spec instance.
    #
    # - List-like dictionaries will become lists of pairs in ASN.1
    #   dict -> SequenceOf/SetOf
    #   Each element will be an instance of datatype._child_spec, which should
    #   be a key-value 2-tuple.
    # TODO: Confirm the last sentence. Could potentially want 3-tuples....

    if isinstance(data, list):
      debug('Converting a list to ' + str(datatype)) # DEBUG
      asn1_obj = _list_to_asn1(data, datatype)
      debug('Completed conversion of list to ' + str(datatype)) # DEBUG
      recursion_level -= 1 # DEBUG
      return asn1_obj

    elif isinstance(data, dict):
      debug('Converting a list-like dict to ' + str(datatype)) # DEBUG
      asn1_obj = _listlike_dict_to_asn1(data, datatype)
      debug('Completed conversion of list-like dict to ' + str(datatype)) # DEBUG
      recursion_level -= 1 # DEBUG
      return asn1_obj

    else:
      assert False, 'Coding error. This should be impossible. Previously checked that data was a list or dict, but now it is neither. Check conditions.' # DEBUG


  elif (issubclass(datatype, asn1_core.Sequence)
      or issubclass(datatype, asn1_core.Set)):
    # In the case of converting to Sequence/Set, we expect to be dealing with a
    # struct-like dictionary -- elements with potentially different types
    # associated with different keys.
    # - Struct-like dictionaries will become Sequences/Sets with field names
    #   in the input dictionary mapping directly to field names in the output
    #   object.xw
    debug('Converting a struct-like dict to ' + str(datatype))
    asn1_obj = _structlike_dict_to_asn1(data, datatype)
    debug('Completed conversion of struct-like dict to ' + str(datatype))
    recursion_level -= 1 # DEBUG
    return asn1_obj


  else:
    recursion_level -= 1 # DEBUG
    raise tuf.exceptions.ASN1ConversionError(
        'Unable to determine how to automatically '
        'convert data into ASN.1 data.  Can only handle primitives to Integer/'
        'VisibleString/OctetString, or list to list-like ASN.1, or list-like '
        'dict to list-like ASN.1, or struct-like dict to struct-like ASN.1.  '
        'Source data type: ' + str(type(data)) + '; output type is: ' +
        str(datatype))







def _list_to_asn1(data, datatype):
  """
  Private helper function for to_asn1.
  See to_asn1 for full docstring.
  This function handles the case wherein:

    - data is a list
    - datatype is or is a subclass of SequenceOf or SetOf, meaning that it is
        "list-like", containing a potentially variable number of elements of
        the same conceptual type. This is as opposed to a "struct-like"
        datatype where each field specifies a distinct kind of thing about
        data. The to_asn1 docstring and comments contain more explanation and
        examples.

  These classes from tuf.encoding.asn1_metadata_definitions are good EXAMPLES
  of the types of metadata this helper function handles:
    - KeyIDHashAlgorithms       (recursions will go directly to base cases)
    -
    - Conversions to unnamed-type SequenceOf objects within Delegation objects,
      converted from delegation path lists in Targets metadata
    -
    -

  # TODO: Complete above list of examples and add the new ones to the test
  # module as you go.

  """

  # Input testing
  if not issubclass(datatype, asn1_core.SequenceOf) \
      and not issubclass(datatype, asn1_core.SetOf):
    raise tuf.exceptions.ASN1ConversionError(
        '_list_to_asn1 called to convert to datatype "' + str(datatype) + '", '
        'which is not a subclass of SequenceOf or SetOf')

  if not isinstance(data, list):    # TODO: Consider allowing duck typing.
    raise tuf.exceptions.ASN1ConversionError(
        '_list_to_asn1 called to convert from type "' + str(type(data)) + '", '
        'which is not list or a subclass of list.')

  # Create object to be populated and returned.
  asn1_obj = datatype()

  for element in data:
    debug('In conversion of list to type ' + str(datatype) + ', recursing '
        'to convert subcomponent of type ' + str(datatype._child_spec))
    element_asn1 = to_asn1(element, datatype._child_spec)

    asn1_obj.append(element_asn1)


  return asn1_obj






def _list_from_asn1(asn1_obj):
  """
  Private helper function for from_asn1.
  See from_asn1 for full docstring.

  Reverses _list_to_asn1.

  This function handles the case wherein asn1_obj is an instance of SequenceOf
  or SetOf (or a subclass thereof) meaning that it is "list-like".
  """

  # Input testing
  if not isinstance(asn1_obj, asn1_core.SequenceOf) \
      and not isinstance(asn1_obj, asn1_core.SetOf):
    import pdb; pdb.set_trace()
    raise tuf.exceptions.ASN1ConversionError(
        '_list_from_asn1 called to convert from datatype "' +
        str(type(asn1_obj)) + '", which is neither SequenceOf, nor SetOf, nor '
        'a subclass thereof.')

  # Create object to be populated and returned.
  data = []

  for element in asn1_obj:
    debug(
        'In conversion of asn1 object of type "' + str(type(asn1_obj)) + '", '
        'recursing to convert subcomponent of type "' + str(type(element)) +
        '"')
    element_asn1 = from_asn1(element)

    data.append(element_asn1)

  return data





def _listlike_dict_to_asn1(data, datatype):
  """



  These classes from tuf.encoding.asn1_metadata_definitions are good EXAMPLES
  of the types of metadata this helper function handles:
    - Conversion to tuf.encoding.asn_metadata_definitions.Hashes from snapshot
      hash dicts in Timestamp metadata
    -
  """
  raise NotImplementedError()





def _structlike_dict_to_asn1(data, datatype):
  """
  Private helper function for to_asn1.
  See to_asn1 for full docstring.
  This function handles the case wherein:

    - data is a dict and
    - datatype is or is a subclass of Sequence or Set, meaning that it is
        "struct-like", containing a specific number of named elements of
        potentially variable type. This is as opposed to conversion to SetOf
        or SequenceOf from a "list-like" dict or list, where the elements might
        not be named, will have a conceptual type in common, and the number of
        elements is variable -- beyond just specifying optional elements. The
        to_asn1 docstring and comments contain more explanation and examples.

  The mapping from data to the new object, asn1_obj, will try to use the same
  keys in both. '-' and '_' will be swapped as necessary (ASN.1 uses dashes in
  variable names and does not permit underscores in them, while Python uses
  underscores in variable names and does not permit dashes in them.).

  These classes from tuf.encoding.asn1_metadata_definitions are good EXAMPLES
  of the types of metadata this helper function handles:
    - Signature           (recursions will go directly to base cases)
    - Hash                (recursions will go directly to base cases)
    - TopLevelDelegation  (recursions will go directly to base cases)
    - RootMetadata        (recursions will hit other functions, multiple layers)
    - HashesContainer
  """

  # Input testing
  if not issubclass(datatype, asn1_core.Sequence) \
      and not issubclass(datatype, asn1_core.Set):
    raise tuf.exceptions.ASN1ConversionError(
        '_structlike_dict_to_asn1 called to convert to datatype "' +
        str(datatype) + '", which is not a subclass of Sequence or Set.')

  if not isinstance(data, dict):    # TODO: Consider allowing duck typing.
    raise tuf.exceptions.ASN1ConversionError(
        '_structlike_dict_to_asn1 called to convert from type "' +
        str(type(data)) + '", which is not dict or a subclass of dict.')

  if len(datatype._fields) < len(data):
    # Note that this takes into account optional fields.
    raise tuf.exceptions.ASN1ConversionError(
        'The dictionary provided has more fields than datatype "' +
        str(datatype) + '" expects/allows. Provided: ' +
        str(len(data)) + '; expected: ' + str(len(datatype._fields)) + '(' +
        str(datatype._fields) + ')')


  # Keep track of the number of matched elements so that we can determine if
  # there were extra elements in the dictionary.  Note that we can't just
  # compare lengths because there may be optional fields in datatype.
  # Unhandled edge case: dictionaries with more than one of the same key, to
  # the extent that's permitted....
  num_matched_elements = 0

  # Create object to be populated and returned.
  asn1_obj = datatype()


  # Parse datatype._fields to discern the names and types of fields. We'll use
  # the names extracted to determine which keys in data to assign to each
  # element of asn1_obj, and use the types to instantiate individual asn1
  # objects for each.
  for row in datatype._fields:

    element_name_asn1 = row[0]
    element_type = row[1]
    element_special_traits = row[2] # #TODO: <~> We don't use this yet.

    # In ASN.1, '_' is invalid in variable names and '-' is valid. The opposite
    # is true of Python, so we swap.
    element_name_py = str(element_name_asn1).replace('-', '_')

    # Is there an entry in data that corresponds to this?
    if element_name_py not in data:
      if 'optional' in element_special_traits \
          and element_special_traits['optional']:
        continue
      else:
        raise tuf.exceptions.ASN1ConversionError(
            'In conversion to "' + str(datatype) + '", expected to find key ' +
            element_name_py + ' in input data, but did not.  Keys in input '
            'data: ' + str(data.keys()))

    debug('In conversion of dict to type ' + str(datatype) + ', recursing '
        'to convert subcomponent named "' + element_name_asn1 + '", of type ' +
        str(element_type))

    element_asn1 = to_asn1(data[element_name_py], element_type)

    asn1_obj[element_name_asn1] = element_asn1

    num_matched_elements += 1

  if num_matched_elements != len(data):
    raise tuf.exceptions.ASN1ConversionError(
        'The dictionary provided has keys in it that did not match expected '
        'fields in datatype "' + str(datatype) + '.  Matched: ' +
        str(num_matched_elements) + '; present in dict: ' + str(len(data)))

  return asn1_obj





def _structlike_dict_from_asn1(asn1_obj):
  """
  Private helper function for from_asn1.
  See from_asn1 for full docstring.

  Reverses _structlike_dict_to_asn1.

  This function handles the case wherein asn1_obj is an instance of Sequence
  or Set (or a subclass thereof) meaning that it is "struct-like".
  """

  # Input testing
  if not isinstance(asn1_obj, asn1_core.Sequence) \
      and not isinstance(asn1_obj, asn1_core.Set):
    raise tuf.exceptions.ASN1ConversionError(
        '_structlike_dict_from_asn1 called to convert from datatype "' +
        str(type(asn1_obj)) + '", which is not a subclass of Sequence or Set.')


  # Create object to be populated and returned.
  data = {}

  # Parse asn1_obj.
  for element_name_asn1 in asn1_obj:

    # In ASN.1, '_' is invalid in variable names and '-' is valid. The opposite
    # is true of Python, so we swap.
    element_name_py = str(element_name_asn1).replace('-', '_')

    debug('In conversion to dict from type "' + str(type(asn1_obj)) + '", '
        'recursing to convert subcomponent named "' + element_name_asn1 + '", '
        'of type ' + str(type(asn1_obj[element_name_asn1])))

    data[element_name_py] = from_asn1(asn1_obj[element_name_asn1])

  return data




  """
  # TODO: DOCSTRING and clean the below up to match to_asn1 style.

  # Note: This will never yield non-string indices in dictionaries, so if you
          had integer indices in your TUF metadata dictionaries for some reason,
          and convert to ASN.1 and back, you will get a dict back that uses
          strings for those indices instead.  There are probably a few quirky
          edge cases like this to keep in mind.
  """
  debug('from_asn1() called to convert from ' + str(type(asn1_obj)) +
      '. asn1crypto data: ' + str(asn1_obj))

  # TODO: It would be interesting to see what use can be made here of this:
  #   return asn1_obj.native
  # It would work just fine for simple types, but not at all for complex things
  # (since we have to restructure things a bit to convert dictionaries into
  # ASN.1)  and I think we're better off reversing that restructuring while we
  # still have the ASN.1 information, not after it has been turned into a dict
  # via '.native', when we might have less information.

  global recursion_level # DEBUG
  recursion_level += 1 # DEBUG


  if isinstance(asn1_obj, asn1_core.Integer):
    data = int(asn1_obj)
    debug('Completed conversion to int from ' + str(type(asn1_obj))) # DEBUG
    recursion_level -= 1 # DEBUG
    return data

  elif isinstance(asn1_obj, asn1_core.VisibleString):
    data = str(asn1_obj)
    debug('Completed conversion to string from ' + str(type(asn1_obj))) # DEBUG
    recursion_level -= 1 # DEBUG
    return data

  elif isinstance(asn1_obj, asn1_core.OctetString):
    # If datatype is a subclass of OctetString, then we assume we have to
    # produce a hex string as output (only because that's the only thing in TUF
    # metadata we'd want to store as an OctetString), so we'll convert the
    # contents into a hex string.
    hex_string = hex_str_from_asn1_octets(asn1_obj)
    tuf.formats.HEX_SCHEMA.check_match(hex_string)
    debug('Completed conversion of primitive to ' + str(type(asn1_obj))) # DEBUG
    recursion_level -= 1 # DEBUG
    return hex_string


  # Else, asn1_obj is not an instance of a basic data type of any of the list
  # of expected basic data types.  Therefore, assume we're converting to a
  # Sequence, SequenceOf, Set, or SetOf.  The output should therefore be a list
  # or a dictionary.

  # Get the type checking out of the way sooner rather than later, even though
  # the elifs below will be somewhat redundant as a result.
  elif not (isinstance(asn1_obj, asn1_core.Sequence)
      or isinstance(asn1_obj, asn1_core.Set)
      or isinstance(asn1_obj, asn1_core.SequenceOf)
      or isinstance(asn1_obj, asn1_core.SetOf)):
    raise tuf.exceptions.ASN1ConversionError(
        'from_asn1 is only able to convert instances of the following classes '
        'or of any subclasses of the following classes: VisibleString, '
        'OctetString, Integer, Sequence, SequenceOf, Set, SetOf. The provided '
        'asn1crypto object is of type "' + str(type(asn1_obj)) + '", which is '
        'is neither one of those classes nor a subclass of them.')


  elif (isinstance(asn1_obj, asn1_core.SequenceOf)
      or isinstance(asn1_obj, asn1_core.SetOf)):
    # In the case of converting from a SequenceOf/SetOf, we expect to be dealing
    # with either output that is either a list or a list-like dictionary -- in
    # either case, objects of the same conceptual type, of potentially variable
    # number.
    #
    # The trouble is how to know which to produce (list or list-like dict).
    # For now, we won't do any clever translation yet, and always convert to a
    # list....
    #
    debug('Converting to a list from ' + str(type(asn1_obj))) # DEBUG
    data = _list_from_asn1(asn1_obj)
    debug('Completed conversion to list from ' + str(type(asn1_obj))) # DEBUG
    recursion_level -= 1 # DEBUG
    return data


  elif (isinstance(asn1_obj, asn1_core.Sequence)
      or isinstance(data, asn1_core.Set)):
    # In the case of converting to Sequence/Set, we expect to be dealing with a
    # struct-like dictionary -- elements with potentially different types
    # associated with different keys.
    # - Struct-like dictionaries will become Sequences/Sets with field names
    #   in the input dictionary mapping directly to field names in the output
    #   object.
    debug('Converting to struct-like dict from ' + str(type(asn1_obj))) # DEBUG
    data = _structlike_dict_from_asn1(asn1_obj)
    debug('Completed conversion to struct-like dict from ' + str(type(asn1_obj))) # DEBUG
    recursion_level -= 1 # DEBUG
    return data


  else:
    recursion_level -= 1 # DEBUG
    assert False, 'Coding error: should be impossible to reach this point ' + \
        'given earlier checks.' # DEBUG; # TODO: adjust structure / remove this.
    raise tuf.exceptions.ASN1ConversionError(
        'Unable to determine how to automatically '
        'convert data into ASN.1 data.  Can only handle primitives to Integer/'
        'VisibleString/OctetString, or list to list-like ASN.1, or list-like '
        'dict to list-like ASN.1, or struct-like dict to struct-like ASN.1.  '
        'Source data type: ' + str(type(data)) + '; output type is: ' +
        str(datatype))












def _listlike_dict_from_pyasn1(data, datatype):
  """
  TODO: Docstring, modeled off _listlike_dict_to_pyasn1
  Also adjust style of function below and clean up.
  """

  raise NotImplementedError()





def _structlike_dict_from_pyasn1(data, datatype):
  """
  TODO: Docstring, modeled off _structlike_dict_to_pyasn1
  Also adjust style of function below and clean up.
  """
  d = {}

  # For a datatype that is a Sequence (or Set) with named types, the
  # componentType object should be a NamedTypes object that will tell us the
  # names and types that datatype contains.
  named_types_obj = datatype.componentType
  assert isinstance(named_types_obj, pyasn1_namedtype.NamedTypes) # TEMPORARY, DO NOT MERGE; generate error instead

  # Determine how many elements objects of type datatype have.
  num_elements = len(named_types_obj)

  # Iterate over the fields in an object of type datatype.  Check to see if
  # each is in data, and feed them in if so, by recursing.
  for i in range(0, num_elements):

    # Discern the named values and the classes of the component objects.
    # We'll use the names extracted to determine which fields in data to assign
    # to each element of pyasn1_obj, and use the types to instantiate individual
    # pyasn1 objects for each.
    element_name = named_types_obj.getNameByPosition(i)
    element_type = type(named_types_obj.getTypeByPosition(i)) # not clear why this isn't already a type...

    # In ASN.1, '_' is invalid in variable names and '-' is valid. The opposite
    # is true of Python, so we swap.
    element_name_python = element_name.replace('-', '_')

    # # Is there an entry in data that corresponds to this?
    # if element_name_python in data:
    #   # If there are matching names in the source and destination structures,
    #   # transfer the data, recursing to instantiate a pyasn1 object of the
    #   # expected type.
    debug('In conversion to struct-like dict from ' + str(datatype) + ', '
        'recursing to convert subcomponent of type ' + str(element_type)) # DEBUG
    element = from_pyasn1(data[element_name], element_type)
    d[element_name_python] = element

  return d





def _list_from_pyasn1(data, datatype):
  """
  TODO: Docstring, modeled off _list_to_pyasn1
  Also adjust style of function below and clean up.
  """

  list_python = []

  if None is getattr(datatype, 'componentType', None):
    # TODO: Determine whether or not to keep this error.
    # It's useful in debugging because the error we get if we don't
    # specifically detect this may be misleading.
    raise tuf.exceptions.ASN1ConversionError(
        'Unable to determine type of component in a '
        'list. datatype of list: ' + str(datatype) + '; componentType '
        'appears to be None')

  for i in range(0, len(data)):
    datum = data[i]


    debug('In conversion to list from type ' + str(datatype) + ', recursing '
        'to convert subcomponent of type ' + str(type(datatype.componentType)))

    datum_python = from_pyasn1(datum, type(datatype.componentType)) # Not sure why componentType is an instance, not a class....
    list_python.append(datum_python)

  return list_python



  raise NotImplementedError()
