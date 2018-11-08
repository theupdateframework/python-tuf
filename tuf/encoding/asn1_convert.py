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
    Note: if data is None, an asn1crypto.core.Void object is returned instead.

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



  # Translate None to asn1crypto's null value, which looks like:
  #     <asn1crypto.core.Void 4497329624 b''>
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

def _is_optional_field_in(field_name, asn1_obj):
  """
  Assuming that field_name is a field in asn1_obj's definition, determines if
  field_name is optional.

  Returns True:
    - if field_name is an optional field for asn1crypto object
    asn1_obj.

  Returns False:
    - if field_name is a non-optional field in asn1_obj.

  Raises ValueError if:
    - asn1_obj doesn't seem to be a Sequence or Set, as it does not have a
      _fields attribute; or
    - field_name is not an attribute of asn1_obj

  # TODO: Do those seem like ValueErrors, or does another class make more sense?
  """
  check_structlike_datatype(type(asn1_obj))

  relevant_row = None

  # Find field_name in the asn1_obj object's element definitions.
  for row in asn1_obj._fields:
    if row[0] == field_name:
      relevant_row = row

  if relevant_row is None:
    raise ValueError(
        'Provided asn1crypto object does not seem to permit a field named ' +
        field_name)

  # The field is listed.  Find out if the field is marked optional.
  if (len(relevant_row) > 2
      and 'optional' in relevant_row[2]
      and relevant_row[2]['optional']):
    return True

  else:
    return False





def check_datatype(datatype):
  """
  Raises ValueError if provided datatype is not a type.
  """
  if not isinstance(datatype, type):
    raise ValueError(
        'datatype must be a type.  It is, instead, ' + str(type(datatype)))




def is_listlike_datatype(datatype):
  """
  True if provided datatype has attribute _child_spec and is either a subclass
  of SequenceOf or SetOf.

  Raises ValueError if datatype is not a type.

  See module docstring and to_asn1 docstring for discussions of list-like and
  struct-like ASN.1 objects.
  """
  check_datatype(datatype)

  if hasattr(datatype, '_child_spec') and (
      issubclass(datatype, asn1_core.SequenceOf)
      or issubclass(datatype, asn1_core.SetOf)):
    return True

  else:
    return False



def check_listlike_datatype(datatype):
  """
  Raises ValueError if provided datatype is not an asn1crypto type that
  subclasses either SequenceOf or SetOf or does not have attribute _child_spec.

  See other docstrings for discussions of list-like and struct-like ASN.1
  objects.
  """
  if not is_listlike_datatype(datatype):
    raise tuf.exceptions.ASN1ConversionError(
        'Expected list-like datatype: subclass of SequenceOf or SetOf, with '
        'attribute "_child_type" that specifies the type of its components.  '
        'Datatype ' + str(datatype) + ' did not.')





def is_listlike_derived_from_dict(datatype):
  """
  Returns True if datatype is a list-like asn1crypto class that is populated
  through conversion from a JSON-compatible dictionary (instead of from a list).

  Raises ValueError if datatype is not a type.
  """
  if (is_listlike_datatype(datatype)
      and hasattr(datatype, '_from_listlike_dict')
      and datatype._from_listlike_dict):
    return True

  else:
    return False





def check_listlike_derived_from_dict(datatype):
  """
  Raises ValueError if provided datatype:
   - is not an asn1crypto type that subclasses either SequenceOf or SetOf,
   - or does not have attribute _child_spec,
   - or does not have attribute _from_listlike_dict set to True.

  See other docstrings for discussions of list-like and struct-like ASN.1
  objects.
  """
  if not is_listlike_derived_from_dict:
    raise ValueError(
        'Provided datatype ' + str(datatype) + ' expected to be a list-like '
        'asn1crypto class derived from a dictionary, but is not.')





def is_listlike_derived_from_dict(datatype):
  """
  Returns True if datatype is a list-like asn1crypto class that is populated
  through conversion from a JSON-compatible dictionary (instead of from a list).

  Raises ValueError if datatype is not a type.
  """
  if (is_listlike_datatype(datatype)
      and hasattr(datatype, '_from_listlike_dict')
      and datatype._from_listlike_dict):
    return True

  else:
    return False


def is_structlike_datatype(datatype):
  """
  True if provided datatype has attribute _fields and is either a subclass of
  Sequence or Set.

  Raises ValueError if datatype is not a type.

  See module docstring and to_asn1 docstring for discussions of list-like and
  struct-like ASN.1 objects.
  """
  check_datatype(datatype)

  if hasattr(datatype, '_fields') and (
      issubclass(datatype, asn1_core.Sequence)
      or issubclass(datatype, asn1_core.Set)):

    # Sanity check to make sure definition for a structlike dict doesn't set
    # _from_listlike_dict.
    if (hasattr(datatype, '_from_listlike_dict')
        and datatype._from_listlike_dict):
      # TODO: Decide on an appropriate exception class.
      raise Exception('Definition for class ' + str(datatype) + ' appears to '
          'incorrectly set _from_listlike_dict, even though it is a '
          'struct-like asn1crypto object.')

    return True

  else:
    return False



def check_structlike_datatype(datatype):
  """
  Raises ValueError if provided datatype is not an asn1crypto type that
  subclasses either Sequence or Set or does not have attribute _fields.

  See other docstrings for discussions of list-like and struct-like ASN.1
  objects.
  """
  if not is_structlike_datatype(datatype):
    raise tuf.exceptions.ASN1ConversionError(
        'Expected struct-like datatype: subclass of SequenceOf or SetOf, '
        'with attribute "_fields" that specifies elements.  Datatype ' +
        str(datatype) + ' did not.')


