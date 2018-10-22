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
# Dependency Imports
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

  This requires that the types and structure defined in the DER be known to
  pyasn1.  They're imported here from module
  tuf.encoding.asn1_metadata_definitions.

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

  """
  # TODO: Verify hex_string type.
  # Should be a string containing only hexadecimal characters, e.g. 'd3aa591c')
  octets_pyasn1 = pyasn1_univ.OctetString(hexValue=hex_string)

  if isinstance(octets_pyasn1._value, pyasn1.type.base.NoValue):
    # Note that pyasn1 tends to ignore arguments it doesn't expect, rather than
    # raising errors, preferring to produce invalid values that can result in
    # delayed and confusing debugging, so it's better to check this here.

    # TODO: Create an appropriate error type for pyasn1 conversions.
    raise tuf.Error('Conversion of hex string to pyasn1 octet string failed: '
        'noValue returned when converting ' + hex_string)

  return octets_pyasn1




def hex_str_from_pyasn1_octets(octets_pyasn1):
  """
  Convert a pyasn1 OctetString object into a hex string.
  Example return:   '4b394ae2'
  Raises Error() if an individual octet's supposed integer value is out of
  range (0 <= x <= 255).
  """
  octets = octets_pyasn1.asNumbers()
  hex_string = ''

  for x in octets:
    if x < 0 or x > 255:
      raise tuf.Error('Unable to generate hex string from OctetString: integer '
          'value of octet provided is not in range: ' + str(x))
    hex_string += '%.2x' % x

  # Make sure that the resulting value is a valid hex string.
  tuf.formats.HEX_SCHEMA.check_match(hex_string)

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

  # Instantiate an object of class datatype.  This is used for introspection
  # and then replaced.
  pyasn1_obj = datatype()

  # Check to see if it's a basic data type from among the list of basic data
  # types we expect (Integer or VisibleString in one camp; OctetString in the
  # other).  If so, re-initialize as such and return that new object.  These
  # are the base cases of the recursion.
  if isinstance(pyasn1_obj, pyasn1_univ.Integer) \
      or isinstance(pyasn1_obj, pyasn1_char.VisibleString):
    print('\nConverting a (hopefully-)primitive value to: ' + str(datatype)) # DEBUG
    return datatype(data)

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
    print('\nConverting a (hopefully-)primitive value to: ' + str(datatype)) # DEBUG
    return datatype(hexValue=data)


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
  #   print('debugging...')

  elif isinstance(datatype.componentType, pyasn1_namedtype.NamedTypes):
    assert isinstance(pyasn1_obj, pyasn1_univ.Sequence) or isinstance(pyasn1_obj, pyasn1_univ.Set), 'Expectation broken during drafting' # TEMPORARY, DO NOT MERGE
    print('\nConverting a struct-like dict to ' + str(datatype)) # DEBUG
    return _structlike_dict_to_pyasn1(data, datatype)

  elif isinstance(data, list):
    assert isinstance(pyasn1_obj, pyasn1_univ.SequenceOf) or isinstance(pyasn1_obj, pyasn1_univ.SetOf), 'Expectation broken during drafting' # TEMPORARY, DO NOT MERGE
    # Converting from a list to a datatype similar to a list of
    # conceptually-similar objects, without distinct named fields.
    print('\nConverting a list to ' + str(datatype)) # DEBUG
    return _list_to_pyasn1(data, datatype)

  elif isinstance(data, dict):
    assert isinstance(pyasn1_obj, pyasn1_univ.SequenceOf) or isinstance(pyasn1_obj, pyasn1_univ.SetOf), 'Expectation broken during drafting' # TEMPORARY, DO NOT MERGE
    print('\nConverting a list-like dict to ' + str(datatype)) # DEBUG
    # Converting from a dict to a datatype similar to a list of
    # conceptually-similar objects, without distinct named fields.
    return _listlike_dict_to_pyasn1(data, datatype)

  else:
    # TODO: Use a better error class for ASN.1 conversion errors.
    raise tuf.exceptions.Error('Unable to determine how to automatically '
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
        elements of disparate elements of potentially variable type. (This is
        as opposed to a "list-like" dict, where the number of elements is
        variable -- beyond just having specific optional elements --, and the
        elements have a conceptual type in common.)

  The mapping from data to the new object, pyasn1_obj, will try to use the same
  keys in both.
  """

  pyasn1_obj = datatype()

  # Discern the named values and the classes of the component objects.
  # TODO: Later, switch from using list comprehension to standard loop.
  names_in_datatype = [i for i in pyasn1_obj]
  types_in_datatype = [type(pyasn1_obj[i]) for i in pyasn1_obj]


  # We'll use the names extracted to determine which fields in data to assign
  # to each element of pyasn1_obj, and use the types to instantiate individual
  # pyasn1 objects for each.
  #
  # Iterate over the fields in an object of type datatype.  Check to see if
  # each is in data, and feed them in if so, by recursing.
  for i in range(0,len(names_in_datatype)):
    element_name = names_in_datatype[i]
    element_type = types_in_datatype[i]

    # In ASN.1, '_' is invalid in variables names and '-' is valid.
    element_name_underscores = element_name.replace('-', '_')

    # Is there an entry in data that corresponds to this?

    if element_name_underscores in data:
      # If there are matching names in the source and destination structures,
      # transfer the data, recursing to instantiate a pyasn1 object of the
      # expected type.
      print('\nIn conversion of a struct-like dict, recursing to convert subcomponent of type ' + str(element_type)) # DEBUG
      element = to_pyasn1(data[element_name_underscores], element_type)
      pyasn1_obj[element_name] = element

      # Note that this includes the edge case where both have an element that
      # LOOKS like a length-of-list element beginning with 'num-'. I don't
      # see any issues with this, though; that seems like the right behavior.

    elif element_name.startswith('num-'):
      # It is okay for this element name not to appear in the source,
      # JSON-compatible metadata if and only if it is a length-of-list
      # element that is useful in the ASN.1 metadata but not in the
      # JSON-compatible metadata. We expect these to start with 'num-', and
      # we expect the rest of their names to match another element in data.
      # We'll populate the value using the length of the associated element
      relevant_element_name = element_name[4:] # whatever is after 'num-'.
      relevant_element_name_underscores = relevant_element_name.replace('-','_')

      if relevant_element_name_underscores in data:
        pyasn1_obj[element_name] = len(data[relevant_element_name_underscores])

      else:
        # TODO: Use a better exception class, relevant to ASN1 conversion.
        raise tuf.exceptions.Error('When converting dict into pyasn1, '
            'found an element that appeared to be a "num-"-prefixed '
            'length-of-list for another element; however, did not find '
            'corresponding element to calculate length of. Element name: ' +
            element_name + '; did not find element name: ' +
            relevant_element_name)

    else:
      # Found an element name in datatype that does not match anything in
      # data and does not begin with 'num-'.
      # TODO: Use a better exception class, relevant to ASN1 conversion.
      raise tuf.exceptions.Error('Unable to convert dict into pyasn1: it '
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

  for i in range(0,len(data)):
      datum = data[i]

      if None is getattr(datatype, 'componentType', None):
        import pdb; pdb.set_trace()
        print('debugging...')

      print('\nIn conversion of a list, recursing to convert subcomponent of type ' + str(type(datatype.componentType)))

      pyasn1_datum = to_pyasn1(datum, type(datatype.componentType)) # Not sure why componentType is an instance, not a class....
      pyasn1_obj[i] = pyasn1_datum





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
  print('\n\nBeginning listlike dict to pyasn1 conversion.')
  print('datatype: ' + str(datatype))
  print('type of subcomponent of datatype: ' + str(type(sample_component_obj)))
  print('sample subcomponent of datatype: ' + str(sample_component_obj))
  print('full data: ' + str(data))

  names_in_component = [i for i in sample_component_obj]
  types_in_component = [type(sample_component_obj[i]) for i in sample_component_obj]

  # TODO: FINISH THIS EXPLANATION OF WHY WE EXPECT 2 ELEMENTS!
  # TODO: FINISH THIS EXPLANATION OF WHY WE EXPECT 2 ELEMENTS!
  # We are assuming that we can convert in={k1: v1, k2: v2, ...} to
  # out[i][0] = k1, out[0][1] = v1,
  if len(names_in_component) != 2:
    raise tuf.exceptions.Error()

  i = 0
  for key in data:
    key = key.replace('_', '-') # ASN.1 uses - instead of _ in var names.
    datum = {names_in_component[0]: key, names_in_component[1]: data[key]}

    print('\nIn conversion of a struct-like dict, recursing to convert subcomponent of type ' + str(datatype.componentType))

    pyasn1_datum = to_pyasn1(datum, type(datatype.componentType)) # Not sure why componentType is an instance, not a class....
    pyasn1_obj[i] = pyasn1_datum
    i += 1

  return pyasn1_obj
