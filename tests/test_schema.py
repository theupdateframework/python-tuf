#!/usr/bin/env python

"""
<Program Name>
  test_schema.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'schema.py'
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import re
import logging

import tuf
import tuf.log
import tuf.schema

logger = logging.getLogger('tuf.test_schema')


class TestSchema(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    pass



  def test_Schema(self):
    # Test conditions for the instantation of classes that inherit
    # from class Schema().
    class NewSchema(tuf.schema.Schema): 
      def __init__(self):
        pass

    new_schema = NewSchema()
    self.assertRaises(NotImplementedError, new_schema.matches, 'test')
   
    # Define a new schema.
    class NewSchema2(tuf.schema.Schema):
      def __init__(self, string):
        self._string = string

      def check_match(self, object):
        if self._string != object:
          message = 'Expected: '+repr(self._string)
          raise tuf.FormatError(message)

    new_schema2 = NewSchema2('test')
    self.assertRaises(tuf.FormatError, new_schema2.check_match, 'bad')
    self.assertFalse(new_schema2.matches('bad'))
    self.assertTrue(new_schema2.matches('test'))
   
    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, new_schema2.check_match, True)
    self.assertRaises(tuf.FormatError, new_schema2.check_match, NewSchema2)
    self.assertRaises(tuf.FormatError, new_schema2.check_match, 123)

    self.assertFalse(new_schema2.matches(True))
    self.assertFalse(new_schema2.matches(NewSchema2))
    self.assertFalse(new_schema2.matches(123))



  def test_Any(self):
    # Test conditions for valid arguments. 
    any_schema = tuf.schema.Any() 

    self.assertTrue(any_schema.matches('test'))
    self.assertTrue(any_schema.matches(123))
    self.assertTrue(any_schema.matches(['test']))
    self.assertTrue(any_schema.matches({'word':'definition'}))
    self.assertTrue(any_schema.matches(True))



  def test_String(self):
    # Test conditions for valid arguments. 
    string_schema = tuf.schema.String('test')

    self.assertTrue(string_schema.matches('test'))

    # Test conditions for invalid arguments. 
    self.assertFalse(string_schema.matches(True))
    self.assertFalse(string_schema.matches(['test']))
    self.assertFalse(string_schema.matches(tuf.schema.Schema))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.String, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.String, [1])
    self.assertRaises(tuf.FormatError, tuf.schema.String, {'a': 1})



  def test_AnyString(self):
    # Test conditions for valid arguments. 
    anystring_schema = tuf.schema.AnyString()
    
    self.assertTrue(anystring_schema.matches(''))
    self.assertTrue(anystring_schema.matches('a string'))
    
    # Test conditions for invalid arguments. 
    self.assertFalse(anystring_schema.matches(['a']))
    self.assertFalse(anystring_schema.matches(3))
    self.assertFalse(anystring_schema.matches({'a': 'string'}))



  def test_OneOf(self):
    # Test conditions for valid arguments. 
    oneof_schema = tuf.schema.OneOf([tuf.schema.ListOf(tuf.schema.Integer()),
                                     tuf.schema.String('Hello'),
                                     tuf.schema.String('bye')])
    
    self.assertTrue(oneof_schema.matches([]))
    self.assertTrue(oneof_schema.matches('bye'))
    self.assertTrue(oneof_schema.matches([1,2]))
    
    # Test conditions for invalid arguments.
    self.assertFalse(oneof_schema.matches(3))
    self.assertFalse(oneof_schema.matches(['Hi']))
    
    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.OneOf, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.OneOf, [1])
    self.assertRaises(tuf.FormatError, tuf.schema.OneOf, {'a': 1})
    self.assertRaises(tuf.FormatError, tuf.schema.OneOf, [tuf.schema.AnyString(), 1])



  def test_AllOf(self):
    # Test conditions for valid arguments. 
    allof_schema = tuf.schema.AllOf([tuf.schema.Any(),
                                     tuf.schema.AnyString(),
                                     tuf.schema.String('a')])
    
    self.assertTrue(allof_schema.matches('a'))
    
    # Test conditions for invalid arguments.
    self.assertFalse(allof_schema.matches('b'))
   
    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.AllOf, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.AllOf, [1])
    self.assertRaises(tuf.FormatError, tuf.schema.AllOf, {'a': 1})
    self.assertRaises(tuf.FormatError, tuf.schema.AllOf, [tuf.schema.AnyString(), 1])


  def test_Boolean(self):
    # Test conditions for valid arguments. 
    boolean_schema = tuf.schema.Boolean()
    
    self.assertTrue(boolean_schema.matches(True) and
                    boolean_schema.matches(False))
    
    # Test conditions for invalid arguments.
    self.assertFalse(boolean_schema.matches(11))



  def test_ListOf(self):
    # Test conditions for valid arguments. 
    listof_schema = tuf.schema.ListOf(tuf.schema.RegularExpression('(?:..)*'))
    listof2_schema = tuf.schema.ListOf(tuf.schema.Integer(),
                                       min_count=3, max_count=10)

    self.assertTrue(listof_schema.matches([]))
    self.assertTrue(listof_schema.matches(['Hi', 'this', 'list', 'is',
                                           'full', 'of', 'even', 'strs']))
    
    self.assertTrue(listof2_schema.matches([3]*3))
    self.assertTrue(listof2_schema.matches([3]*10))
   
    # Test conditions for invalid arguments.
    self.assertFalse(listof_schema.matches('hi'))
    self.assertFalse(listof_schema.matches({}))
    self.assertFalse(listof_schema.matches(['This', 'one', 'is not']))

    self.assertFalse(listof2_schema.matches([3]*2))
    self.assertFalse(listof2_schema.matches(([3]*11)))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.ListOf, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.ListOf, [1])
    self.assertRaises(tuf.FormatError, tuf.schema.ListOf, {'a': 1})



  def test_Integer(self):
    # Test conditions for valid arguments. 
    integer_schema = tuf.schema.Integer()

    self.assertTrue(integer_schema.matches(99))
    self.assertTrue(tuf.schema.Integer(lo=10, hi=30).matches(25))
    
    # Test conditions for invalid arguments.
    self.assertFalse(integer_schema.matches(False))
    self.assertFalse(integer_schema.matches('a string'))
    self.assertFalse(tuf.schema.Integer(lo=10, hi=30).matches(5))



  def test_DictOf(self):
    # Test conditions for valid arguments. 
    dictof_schema = tuf.schema.DictOf(tuf.schema.RegularExpression(r'[aeiou]+'),
                                      tuf.schema.Struct([tuf.schema.AnyString(),
                                                         tuf.schema.AnyString()]))

    self.assertTrue(dictof_schema.matches({}))
    self.assertTrue(dictof_schema.matches({'a': ['x', 'y'], 'e' : ['', '']}))
   
    # Test conditions for invalid arguments.
    self.assertFalse(dictof_schema.matches(''))
    self.assertFalse(dictof_schema.matches({'a': ['x', 3], 'e' : ['', '']}))
    self.assertFalse(dictof_schema.matches({'a': ['x', 'y'], 'e' : ['', ''],
                                            'd' : ['a', 'b']}))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.DictOf, 1, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.DictOf, [1], [1])
    self.assertRaises(tuf.FormatError, tuf.schema.DictOf, {'a': 1}, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.DictOf, tuf.schema.AnyString(), 1)



  def test_Optional(self):
    # Test conditions for valid arguments. 
    optional_schema = tuf.schema.Object(k1=tuf.schema.String('X'), 
                                k2=tuf.schema.Optional(tuf.schema.String('Y')))

    self.assertTrue(optional_schema.matches({'k1': 'X', 'k2': 'Y'}))
    self.assertTrue(optional_schema.matches({'k1': 'X'}))

    # Test conditions for invalid arguments.
    self.assertFalse(optional_schema.matches({'k1': 'X', 'k2': 'Z'}))
  
    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.Optional, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.Optional, [1])
    self.assertRaises(tuf.FormatError, tuf.schema.Optional, {'a': 1})
 


  def test_Object(self):
    # Test conditions for valid arguments. 
    object_schema = tuf.schema.Object(a=tuf.schema.AnyString(),
                                      bc=tuf.schema.Struct([tuf.schema.Integer(),
                                                            tuf.schema.Integer()]))

    self.assertTrue(object_schema.matches({'a':'ZYYY', 'bc':[5,9]}))
    self.assertTrue(object_schema.matches({'a':'ZYYY', 'bc':[5,9], 'xx':5}))
    
    # Test conditions for invalid arguments.
    self.assertFalse(object_schema.matches({'a':'ZYYY', 'bc':[5,9,3]}))
    self.assertFalse(object_schema.matches({'a':'ZYYY'}))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.Object, a='a')
    self.assertRaises(tuf.FormatError, tuf.schema.Object, a=[1])
    self.assertRaises(tuf.FormatError, tuf.schema.Object, a=tuf.schema.AnyString(),
                                                          b=1)

    # Test condition for invalid non-dict arguments.
    self.assertFalse(object_schema.matches([{'a':'XYZ'}]))
    self.assertFalse(object_schema.matches(8))



  def test_Struct(self):
    # Test conditions for valid arguments. 
    struct_schema = tuf.schema.Struct([tuf.schema.ListOf(tuf.schema.AnyString()),
                                                         tuf.schema.AnyString(),
                                                         tuf.schema.String('X')])
    struct2_schema = tuf.schema.Struct([tuf.schema.String('X')], allow_more=True)
    struct3_schema = tuf.schema.Struct([tuf.schema.String('X'),
                     tuf.schema.Integer()], [tuf.schema.Integer()])

    self.assertTrue(struct_schema.matches([[], 'Q', 'X']))
    
    self.assertTrue(struct2_schema.matches(['X']))
    self.assertTrue(struct2_schema.matches(['X', 'Y']))
    self.assertTrue(struct2_schema.matches(['X', ['Y', 'Z']]))

    self.assertTrue(struct3_schema.matches(['X', 3]))
    self.assertTrue(struct3_schema.matches(['X', 3, 9]))

    # Test conditions for invalid arguments.
    self.assertFalse(struct_schema.matches(False))
    self.assertFalse(struct_schema.matches('Foo'))
    self.assertFalse(struct_schema.matches([[], 'Q', 'D']))
    self.assertFalse(struct_schema.matches([[3], 'Q', 'X']))
    self.assertFalse(struct_schema.matches([[], 'Q', 'X', 'Y']))

    self.assertFalse(struct2_schema.matches([]))
    self.assertFalse(struct2_schema.matches([['X']]))

    self.assertFalse(struct3_schema.matches([]))
    self.assertFalse(struct3_schema.matches({}))
    self.assertFalse(struct3_schema.matches(['X']))
    self.assertFalse(struct3_schema.matches(['X', 3, 9, 11]))
    self.assertFalse(struct3_schema.matches(['X', 3, 'A']))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(tuf.FormatError, tuf.schema.Struct, 1)
    self.assertRaises(tuf.FormatError, tuf.schema.Struct, [1])
    self.assertRaises(tuf.FormatError, tuf.schema.Struct, {'a': 1})
    self.assertRaises(tuf.FormatError, tuf.schema.Struct,
                      [tuf.schema.AnyString(), 1])



  def test_RegularExpression(self):
    # Test conditions for valid arguments.
    # RegularExpression(pattern, modifiers, re_object, re_name).
    re_schema = tuf.schema.RegularExpression('h.*d')

    self.assertTrue(re_schema.matches('hello world'))
    
    # Provide a pattern that contains the trailing '$'
    re_schema_2 = tuf.schema.RegularExpression(pattern='abc$',
                                               modifiers=0,
                                               re_object=None,
                                               re_name='my_re')

    self.assertTrue(re_schema_2.matches('abc'))
   
    # Test for valid optional arguments.
    compiled_re = re.compile('^[a-z].*')
    re_schema_optional = tuf.schema.RegularExpression(pattern='abc',
                                                      modifiers=0,
                                                      re_object=compiled_re,
                                                      re_name='my_re')
    self.assertTrue(re_schema_optional.matches('abc'))
   
    # Valid arguments, but the 'pattern' argument is unset (required if the 
    # 're_object' is 'None'.)
    self.assertRaises(tuf.FormatError, tuf.schema.RegularExpression, None, 0,
                                                      None, None)
    
    # Valid arguments, 're_name' is unset, and 'pattern' is None.  An exception
    # is not raised, but 're_name' is set to 'pattern'.
    re_schema_optional = tuf.schema.RegularExpression(pattern=None,
                                                      modifiers=0,
                                                      re_object=compiled_re,
                                                      re_name=None)
    
    self.assertTrue(re_schema_optional.matches('abc'))
    self.assertTrue(re_schema_optional._re_name == 'pattern')

    # Test conditions for invalid arguments.
    self.assertFalse(re_schema.matches('Hello World'))
    self.assertFalse(re_schema.matches('hello world!'))
    self.assertFalse(re_schema.matches([33, 'Hello']))

    self.assertRaises(tuf.FormatError, tuf.schema.RegularExpression, 8)



  def test_LengthString(self):
    # Test conditions for valid arguments.
    length_string = tuf.schema.LengthString(11)

    self.assertTrue(length_string.matches('Hello World'))
    self.assertTrue(length_string.matches('Hello Marty'))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, tuf.schema.LengthString, 'hello')
 
    self.assertFalse(length_string.matches('hello'))
    self.assertFalse(length_string.matches(8))
  
  
  
  def test_LengthBytes(self):
    # Test conditions for valid arguments.
    length_bytes = tuf.schema.LengthBytes(11)

    self.assertTrue(length_bytes.matches(b'Hello World'))
    self.assertTrue(length_bytes.matches(b'Hello Marty'))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, tuf.schema.LengthBytes, 'hello')
    self.assertRaises(tuf.FormatError, tuf.schema.LengthBytes, True)
 
    self.assertFalse(length_bytes.matches(b'hello'))
    self.assertFalse(length_bytes.matches(8))
  
  
  
  def test_AnyBytes(self):
    # Test conditions for valid arguments. 
    anybytes_schema = tuf.schema.AnyBytes()
    
    self.assertTrue(anybytes_schema.matches(b''))
    self.assertTrue(anybytes_schema.matches(b'a string'))
    
    # Test conditions for invalid arguments.
    self.assertFalse(anybytes_schema.matches('a string'))
    self.assertFalse(anybytes_schema.matches(['a']))
    self.assertFalse(anybytes_schema.matches(3))
    self.assertFalse(anybytes_schema.matches({'a': 'string'}))


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
