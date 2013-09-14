"""
<Program>
  unittest_toolbox.py

<Author>
  Konstantin Andrianov

<Started>
  March 26, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides an array of various methods for unit testing.  Use it instead of
  actual unittest module.  This module builds on unittest module.
  Specifically, Modified_TestCase is a derived class from unittest.TestCase.

"""

import os
import sys
import shutil
import unittest
import tempfile
import random
import string
import ConfigParser

import tuf.rsa_key as rsa_key
import tuf.repo.keystore as keystore

# Modify the number of iterations (from the higher default count) so the unit
# tests run faster.
keystore._PBKDF2_ITERATIONS = 1000


class Modified_TestCase(unittest.TestCase):
  """
  <Purpose>
    Provide additional test-setup methods to make testing
    of module's methods-under-test as independent as possible.

    If you want to modify setUp()/tearDown() do:
    class Your_Test_Class(modified_TestCase):
      def setUp():
        your setup modification
        your setup modification
        ...
        modified_TestCase.setUp(self)

  <Methods>
    make_temp_directory(self, directory=None):
      Creates and returns an absolute path of a temporary directory.

    make_temp_file(self, suffix='.txt', directory=None):
      Creates and returns an absolute path of an empty temp file.

    make_temp_data_file(self, suffix='', directory=None, data = junk_data):
      Returns an absolute path of a temp file containing some data.

    make_temp_config_file(self, suffix='', directory=None, config_dict={}, expiration=None):
      Creates a temporary file and puts a config dictionary in it using
      ConfigParser.  It then returns a (config_file_path, config_dictionary)
      tuple.

    make_temp_directory_with_data_files(self, _current_dir=None,directory_content=\
        directory_dictionary, directory=None):
      Creates a temp directory with files, directories and sub-directories
      based on the dictionary supplied. It returns a temp directory, which
      is parent of the structure supplied in the dictionary.

    random_path(self, length = 7):
      Generate a 'random' path consisting of n-length strings of random chars.

    get_keystore_key(self, keyid):
      This a monkey patch for keystore's get_key method.


    Static Methods:
    --------------
    Following methods are static because they technically don't operate
    on any instances of the class, what they do is: they modify class variables
    (dictionaries) that are shared among all instances of the class.  So
    it is possible to call them without instantiating the class.

    generate_rsakey():
      Generate rsa key and put it into 'rsa_keystore' dictionary.

    bind_keys_to_a_role(role, threshold=1):
      Binds a key to a 'role' thus modifying 'semi_roledict' and
      'rsa_keystore' dictionaries.

    bind_keys_to_roles(role_thresholds={}):
      Bind keys to top level roles.  If dictionary of roles-thresholds is
      supplied set - use it to crate appropriate amount of keys.  If you
      want to set a dictionary specifying a threshold each role should have,
      the dictionary should look like this: {role : 2, ... }  where role
      might be 'root' and # is a threshold #.

    random_string(length=7):
      Generate a 'length' long string of random characters.

  """

  # List of all top level roles.
  role_list = ['root', 'targets', 'release', 'timestamp']

  # List of delegated roles.
  delegated_role_list = ['targets/delegated_role1',
                         'targets/delegated_role1/delegated_role2']

  # 'rsa_keyids' stores keyids of all created rsa keys.
  rsa_keyids = []

  # 'rsa_keystore' stores all created rsa keys, that are RSAKEY_SCHEMA
  # conformant, as values for their corresponding keyid dictionary keys.
  # {keyid : {-- rsa key --}, ...}
  rsa_keystore = {}

  # 'rsa_passwords' stores the passwords for all created rsa keys.
  rsa_passwords = {}

  # 'derived_keys' stores the salt and derived keys (e.g., PBKDF2) for the
  # RSA keys. 
  rsa_derived_keys = {}

  # 'semi_roledict' because it lacks an item that a fully pledged
  # ROLEDICT_SCHEMA dictionary would have i.e. 'path' key is absent.
  semi_roledict = {}

  # 'top_level_role_info' same as 'semi_roledict' except that it only
  # contains top-level roles.
  top_level_role_info = {}

  junk_data = 'Stored data.'

  directory_dictionary = {'targets':[{'delegated_level1':
                                      [{'delegated_level2':junk_data},
                                      junk_data]},
                                    junk_data,
                                    junk_data]}

  config_expiration = {'expiration':{'days':0, 'years':0,
                       'minutes':0, 'hours':0, 'seconds':0}}


  mirrors = {'mirror1': {'url_prefix' : 'http://mirror1.com',
                         'metadata_path' : 'metadata',
                         'targets_path' : 'targets',
                         'confined_target_dirs' : ['']},
             'mirror2': {'url_prefix' : 'http://mirror2.com',
                         'metadata_path' : 'metadata',
                         'targets_path' : 'targets',
                         'confined_target_dirs' : ['']},
             'mirror3': {'url_prefix' : 'http://mirror3.com',
                         'metadata_path' : 'metadata',
                         'targets_path' : 'targets',
                         'confined_target_dirs' : ['']}}




  def setUp(self):
    self._cleanup = []


  def tearDown(self):
    for cleanup_function in self._cleanup:
      # Perform clean up by executing clean-up functions.
      try:
        # OSError will occur if the directory was already removed.
        cleanup_function()
      except OSError:
        pass





  def make_temp_directory(self, directory=None):
    """Creates and returns an absolute path of a directory."""
    prefix = self.__class__.__name__+'_'
    temp_directory = tempfile.mkdtemp(prefix=prefix, dir=directory)
    def _destroy_temp_directory():
      shutil.rmtree(temp_directory)
    self._cleanup.append(_destroy_temp_directory)
    return temp_directory





  def make_temp_file(self, suffix='.txt', directory=None):
    """Creates and returns an absolute path of an empty file."""
    prefix='tmp_file_'+self.__class__.__name__+'_'
    temp_file = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=directory)
    def _destroy_temp_file():
      os.unlink(temp_file[1])
    self._cleanup.append(_destroy_temp_file)
    return temp_file[1]





  def make_temp_data_file(self, suffix='', directory=None, data = junk_data):
    """Returns an absolute path of a temp file containing data."""
    temp_file_path = self.make_temp_file(suffix=suffix, directory=directory)
    temp_file = open(temp_file_path, 'wb')
    temp_file.write(data)
    temp_file.close()
    return temp_file_path





  def make_temp_config_file(self, suffix='', directory=None, config_dict={}, expiration=None):
    """
    Creates a temporary file and puts a simple config
    dictionary in it using ConfigParser.
    It then returns the temp file path, dictionary tuple.
    """
    config = ConfigParser.RawConfigParser()
    if not config_dict:
      # Using the fact that empty sequences are false.
      # Make some mock config data. Make sure it at least has 'keyid',
      # 'threshold' and 'days' keys.
      config_dict = {'expiration':{'days':100},
          'root':{'keyids':['123abc','123abc'], 'threshold':2}}
    if expiration:
      config_dict['expiration'] = {}
      config_dict['expiration'] = self.config_expiration['expiration']
      config_dict['expiration']['days'] = expiration
    for section in config_dict:
      config.add_section(section)
      for key in config_dict[section]:
        config.set(section, key, config_dict[section][key])
    config_path = self.make_temp_file(suffix=suffix, directory=directory)
    config_file = open(config_path, 'wb')
    config.write(config_file)
    config_file.close()
    return (config_path, config_dict)





  def make_temp_directory_with_data_files(self, _current_dir=None,
      directory_content=directory_dictionary, directory=None):
    """
      Creates a temp directory with files, directories and sub-directories
      based on the dictionary supplied. It returns a temp directory, which
      is parent of the structure supplied in the dictionary.  When nested
      directories desired use lists as values ex. {'dir_1':[{dir2:None}]}
      to get '/tmp/tmp_dir_Test_random/dir_1/dir_2' without files.

      <Arguments>
        directory: Specifies a path where to create the new directory in
        (like repository directory).  If 'None' temp directory would be
        created (recommended).

        _current_dir: Used internally.  Represents a current directory, for
          example '/tmp/tmp_dir_Test_random',
          '/tmp/tmp_dir_Test_random/targets/' and
          '/tmp/tmp_dir_Test_random/targets/more_targets' would all be
          current directories in turn since they all contain either files
          or other directories.

        directory_content: Represents a dictionary with desired tree
          structure to be attached to the 'directory'.

      Example:

        directory_dict = {'targets':[{'more_targets': junk_data},
                          junk_data, junk_data]}

        self.make_temp_directory_with_data_files(directory_content=
        directory_dict)
        Creates:
          /tmp/tmp_dir_Test_random/
          /tmp/tmp_dir_Test_random/targets/
          /tmp/tmp_dir_Test_random/targets/tmp_random1.txt
          /tmp/tmp_dir_Test_random/targets/tmp_random2.txt
          /tmp/tmp_dir_Test_random/targets/more_targets/
          /tmp/tmp_dir_Test_random/targets/more_targets/tmp_random3.txt
        Returns:
          ('/tmp/tmp_dir_Test_random/', [targets/tmp_random1.txt,
          targets/tmp_random2.txt, targets/more_targets/tmp_random3.txt])

    """

    if not _current_dir:
      if directory:
        _current_dir = directory
      else:
        _current_dir = self.make_temp_directory()

      # Calls itself with _current_dir set.
      self.make_temp_directory_with_data_files(_current_dir=_current_dir)
      temp_target_files = []

      for directory, _junk, files in os.walk(_current_dir):
        for target in files:
          full_path = os.path.join(directory, target)
          rel_path = os.path.relpath(full_path, _current_dir)
          temp_target_files.append(rel_path)

      return _current_dir, temp_target_files

    for key in directory_content:
      # Create directory 'key'.
      _new_current_dir = os.path.join(_current_dir, key)
      os.mkdir(_new_current_dir)

      # We have the directory.  Check if value of key is a list or a str.
      # If a list iterate through it.
      # Else create a file with content of the item/value.
      if isinstance(directory_content[key],list) and\
         len(directory_content[key]) > 1:

        # Check that there are more than 1 item in the list.
        # else create a file with content of the item.
        for item in range(len(directory_content[key])):
          if isinstance(directory_content[key][item], dict):
            # Pass current directory which is now '_new_current_dir' and the
            # dictionary 'directory_content[key][item]'
            self.make_temp_directory_with_data_files(
                            _current_dir=_new_current_dir,
                            directory_content=directory_content[key][item])
          else:
            # Create a file w/ data, returning its address.
            self.make_temp_data_file(suffix='.txt',
                                     directory=_new_current_dir,
                                     data=directory_content[key][item])

      else:
      # Create a file w/ data, returning its address.
        if directory_content[key]:
          if isinstance(directory_content[key], str):
            self.make_temp_data_file(suffix='.txt', directory=_new_current_dir,
                                     data=directory_content[key])

          elif isinstance(directory_content[key], list) and\
                          len(directory_content[key])==1:
            self.make_temp_data_file(suffix='.txt', directory=_new_current_dir,
                                     data=directory_content[key][0])





  def random_path(self, length = 7):
    """Generate a 'random' path consisting of random n-length strings."""

    rand_path = '/'+self.random_string(length)
    for i in range(2):
      rand_path = os.path.join(rand_path, self.random_string(length))

    return rand_path





  def get_keystore_key(self, keyid):
    """This is a monkey patch for keystore's get_key method."""

    return self.rsa_keystore[keyid]





  @staticmethod
  def generate_rsakey():
    """
    This method generates a rsa key as shown below. It puts it in
    'rsa_keystore' and returns the 'keyid' of the created rsa dictionary.

      {'keytype': 'rsa',
       'keyid': keyid,
       'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                  'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}
    """

    rsakey = rsa_key.generate()
    keyid = rsakey['keyid']
    Modified_TestCase.rsa_keyids.append(keyid)
    password = Modified_TestCase.random_string()
    Modified_TestCase.rsa_passwords[keyid] = password
    salt, derived_key = keystore._generate_derived_key(password)
    Modified_TestCase.rsa_derived_keys[keyid] = {'salt': salt,
                                                 'derived_key': derived_key}
    Modified_TestCase.rsa_keystore[keyid] = rsakey
    
    return keyid





  def create_temp_keystore_directory(self, keystore_dicts=False):

    if not self.rsa_keystore or not self.rsa_derived_keys:
      msg = 'Populate \'rsa_keystore\' and \'rsa_passwords\''+\
          ' before invoking this method.'
      sys.exit(msg)

    temp_keystore_directory = self.make_temp_directory()
    keystore._keystore = self.rsa_keystore
    keystore._derived_keys = self.rsa_derived_keys
    keystore.save_keystore_to_keyfiles(temp_keystore_directory)
    if not keystore_dicts:
      keystore._keystore={}
      keystore._derived_keys={}

    return temp_keystore_directory





  @staticmethod
  def bind_keys_to_a_role(role, threshold=1):
    """
    Binds a key to a 'role' thus modifying 'semi_roledict'
    and 'rsa_keystore' dictionaries.  If 'threshold' is given,
    'threshold' number of keys are added to the 'role', otherwise
    'threshold' is set to 1.  There might be existing keys bound
    to the role, this method will add 'threshold' amount of keys
    to already existing keys.
    """

    if not Modified_TestCase.semi_roledict.has_key(role):
      # If 'semi_roledict' doesn't contain the 'role', initialize it.
      Modified_TestCase.semi_roledict[role] = {}
      Modified_TestCase.semi_roledict[role]['keyids'] = []
      Modified_TestCase.semi_roledict[role]['threshold'] = threshold
    else:
      # Update the role's threshold.
      Modified_TestCase.semi_roledict[role]['threshold'] += threshold

    for number in range(threshold):
      # Create rsa keys and store their keyids in 'keyids' list.
      # Side effect: rsa_keystore gets populated with rsa keys.
      Modified_TestCase.semi_roledict[role]['keyids'].\
          append(Modified_TestCase.generate_rsakey())

    if role in Modified_TestCase.role_list:
      Modified_TestCase.top_level_role_info[role] = {}
      Modified_TestCase.top_level_role_info[role] = \
          Modified_TestCase.semi_roledict[role]





  @staticmethod
  def bind_keys_to_roles(role_thresholds={}):
    """
    Bind keys to top level roles.  If dictionary of roles-thresholds
    is supplied set - use it to create appropriate amount of keys.  If you
    want to set a dictionary specifying a threshold each role should have,
    the dictionary should look like this: {role : 2, ... }  where role
    might be 'root' and # is a threshold #.
    """

    list_of_all_roles = Modified_TestCase.role_list + \
        Modified_TestCase.delegated_role_list
    for role in list_of_all_roles:
      if role_thresholds:
        Modified_TestCase.bind_keys_to_a_role(role, 
                                              threshold=role_thresholds[role])
      else:
        Modified_TestCase.bind_keys_to_a_role(role)





  @staticmethod
  def random_string(length=15):
    """Generate a random string of specified length."""

    rand_str = ''
    for letter in range(length):
      rand_str += random.choice('abcdefABCDEF'+string.digits)

    return rand_str





  @staticmethod
  def clear_toolbox():
    Modified_TestCase.rsa_keyids = []
    Modified_TestCase.rsa_keystore.clear()
    Modified_TestCase.rsa_passwords.clear()
    Modified_TestCase.rsa_derived_keys.clear()
    Modified_TestCase.semi_roledict.clear()
    Modified_TestCase.top_level_role_info.clear()
