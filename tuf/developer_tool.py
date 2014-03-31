"""
<Program Name>
  tuf-devtoools.py

<Authors>
  Santiago Torres <torresariass@gmail.com>
  Zane Fisher <zanefisher@gmail.com>

  Based on the work done for the repository tools by Vladimir Diaz

<Started>
  January 22, 2014 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  See 'tuf/README' for a complete guide on using 'tuf.devtools.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

#this import is the interface to the whole tuf module, since the imports are 
# made there. 
import os
import errno
import sys
import logging
import shutil
import tempfile
import json

import tuf
import tuf.formats
import tuf.util
import tuf.keydb
import tuf.roledb
import tuf.keys
import tuf.sig
import tuf.log
import tuf.conf
import tuf.repository_tool

from tuf.repository_tool import Targets
from tuf.repository_tool import get_metadata_file_info
from tuf.repository_tool import get_metadata_filenames
from tuf.repository_tool import generate_and_write_rsa_keypair
from tuf.repository_tool import import_rsa_publickey_from_file
from tuf.repository_tool import import_rsa_privatekey_from_file
from tuf.repository_tool import generate_and_write_ed25519_keypair
from tuf.repository_tool import import_ed25519_publickey_from_file
from tuf.repository_tool import import_ed25519_privatekey_from_file
#from tuf.import _generate_and_write_metadata
from tuf.repository_tool import _remove_invalid_and_duplicate_signatures
from tuf.repository_tool import _check_role_keys
from tuf.repository_tool import _delete_obsolete_metadata
from tuf.repository_tool import generate_targets_metadata
from tuf.repository_tool import sign_metadata
from tuf.repository_tool import write_metadata_file
from tuf.repository_tool import _check_if_partial_loaded

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.devtools')

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1 
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.  2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# The algorithm used by the repository to generate the hashes of the
# target filepaths.  The repository may optionally organize targets into
HASH_FUNCTION = 'sha256'

# The extension of TUF metadata.
METADATA_EXTENSION = '.json'

# The metadata filename for the targets metadata information.
TARGETS_FILENAME = 'targets' + METADATA_EXTENSION

# Project configuration filename
PROJECT_FILENAME = 'project.cfg'

# The targets and metadata directory names.  Metadata files are written
# to the staged metadata directory instead of the "live" one.
METADATA_STAGED_DIRECTORY_NAME = 'metadata.staged'
METADATA_DIRECTORY_NAME = 'metadata'
TARGETS_DIRECTORY_NAME = 'targets' 

# The full list of supported TUF metadata extensions.
METADATA_EXTENSIONS = ['.json', '.json.gz']

# The recognized compression extensions. 
SUPPORTED_COMPRESSION_EXTENSIONS = ['.gz']

# Supported key types.
SUPPORTED_KEY_TYPES = ['rsa', 'ed25519']

# Expiration date delta, in seconds, of the top-level roles.  A metadata
# expiration date is set by taking the current time and adding the expiration
# seconds listed below.

# Initial 'targets.txt' expiration time of 3 months. 
TARGETS_EXPIRATION = 7889230 

# TODO: We should have a method like Describe to show the contents of the 
#       instance
class Project(Targets):
  """
  <Purpose>
    This class works as the abstraction of the developer's files. this module
    was created with the objective of simplifying the publishing process using
    TUF by taking care of all of the bookkeeping, signature handling and 
    metadata integrity verification.

    This class is the direct representation of a metadata file* with the 
    intention to provide the ability to modify this data in an OOP manner
    without messing with syntax and sanity-checking.

      
  <Arguments>
    project_directory:
      The root folder of the project that contains the metadata and targets
      sub-directories.

    metadata_directory:
      The metadata sub-directory contains the files of the top-level
      roles, including all roles delegated from 'targets.txt'. 

    targets_directory:
      The targets sub-directory contains all the target files that are
      downloaded by clients and are referenced in TUF Metadata.  The hashes and
      file lengths are listed in Metadata files so that they are securely
      downloaded.  Metadata files are similarly referenced in the top-level
      metadata.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    Creates top-level role objects and assigns them as attributes.

  <Returns>
    A project object that contains default Metadata objects for the top-level
    roles.
  """
 
  def __init__(self, metadata_directory, targets_directory, file_prefix):
  
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
    tuf.formats.PATH_SCHEMA.check_match(targets_directory)
    tuf.formats.PATH_SCHEMA.check_match(file_prefix)

    self._metadata_directory = metadata_directory
    self._targets_directory = targets_directory
    
    # layout type defaults to "flat" unless explicitly specified in 
    # create_new_project
    self.layout_type = "flat"

    # Set the top-level role objects.
    super(Project, self).__init__(self._targets_directory, 'targets')

    self.prefix = file_prefix



  def write(self, write_partial=False):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files.
      write() raises an exception if any of the role metadata to be written to
      disk is invalid, such as an insufficient threshold of signatures, missing
      private keys, etc.
    
    <Arguments>
      write_partial:
        A boolean indicating whether partial metadata should be written to
        disk.  Partial metadata may be written to allow multiple maintainters
        to independently sign and update role metadata.  write() raises an
        exception if a metadata role cannot be written due to not having enough
        signatures.

    <Exceptions>
      tuf.Error, if any of the top-level roles do not have a minimum
      threshold of signatures.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """
    
    # Does 'write_partial' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.BOOLEAN_SCHEMA.check_match(write_partial)
    
    # At this point the tuf.keydb and tuf.roledb stores must be fully
    # populated, otherwise write() throwns a 'tuf.Repository' exception if 
    # any of the top-level roles are missing signatures, keys, etc.

    # Write the metadata files of all the delegated roles.
    delegated_rolenames = tuf.roledb.get_delegated_rolenames('targets')
    for delegated_rolename in delegated_rolenames:
      roleinfo = tuf.roledb.get_roleinfo(delegated_rolename)
      delegated_filename = os.path.join(self._metadata_directory,
                                        delegated_rolename + METADATA_EXTENSION)

      # Ensure the parent directories of 'metadata_filepath' exist, otherwise an
      # IO exception is raised if 'metadata_filepath' is written to a
      # sub-directory.
      tuf.util.ensure_parent_dir(delegated_filename)
      
      _generate_and_write_metadata(delegated_rolename, delegated_filename,
                                   write_partial, self._targets_directory,
                                   self._metadata_directory,
                                   prefix=self.prefix)
      
    
    # Generate the 'targets.txt' metadata file.
    targets_filename = 'targets' + METADATA_EXTENSION 
    targets_filename = os.path.join(self._metadata_directory, targets_filename)
    release_signable, targets_filename = \
      _generate_and_write_metadata('targets', targets_filename, write_partial,
                                   self._targets_directory,
                                   self._metadata_directory,
                                   prefix=self.prefix)

    #save some other information that is not stored in the project's metadata 
    save_project_configuration(self._metadata_directory,self._targets_directory,
                       self.keys, self.prefix, self.threshold,
                       self.layout_type)
    
    # Delete the metadata of roles no longer in 'tuf.roledb'.  Obsolete roles
    # may have been revoked.
    _delete_obsolete_metadata(self._metadata_directory,
                              release_signable['signed'], False)



  def remove_verification_key(self,key):
    """
      <Purpose>
        Function as a thin wrapper call for the project._targets call
        with the same name. This wrapper is only for usability purposes

      <Arguments>
        Key:
          The role key to be removed, conformant to tuf.formats.anykey_schema

      <Exceptions>
        Tuf.FormatError, if the 'key' argument is improperly formatted.

      <Side Effects>
        The role's entries in 'tuf.roledb.py' are updated

      <Returns>
        None
    """
    try:
      super(Project, self).remove_verification_key(key)
    except tuf.FormatError:
      raise


  def add_verification_key(self,key):
    """
      <Purpose>
        Function as a thin wrapper call for the project._targets call
        with the same name. This wrapper is only for usability purposes

      <Arguments>
        Key:
          The role key to be added, conformant to tuf.formats.anykey_schema
          Adding a public key to a role means that its corresponding private
          key must generate and add its signture to the role. 

      <Exceptions>
        Tuf.FormatError, if the 'key' argument is improperly formatted.

        Tuf.Error, if the project already contains a key

      <Side Effects>
        The role's entries in 'tuf.keydb.py' and 'tuf.roledb.py' are updated

      <Returns>
        None
    """
    ### should check the number of keys for this role.
    if len(self.keys)>0:
      raise tuf.Error("This project already contains a key")

    try:
      super(Project, self).add_verification_key(key)
    except tuf.FormatError:
      raise



  def status(self):
    """
    <Purpose>
      Determine the status of the top-level roles, including those delegated.
      status() checks if each role provides sufficient public keys, signatures,
      and that a valid metadata file is generated if write() were to be called.
      Metadata files are temporary written to check that proper metadata files
      are written, where file hashes and lengths are calculated and referenced
      by the top-level roles.  status() does not do a simple check for number
      of threshold keys and signatures.

    <Arguments>
      None.

    <Exceptions>
      tuf.Error, if any of the top-level roles do not have a minimum
      threshold of signatures.

    <Side Effects>
      Generates and writes temporary metadata files.

    <Returns>
      None.
    """
    temp_project_directory = None

    try:
      temp_project_directory = tempfile.mkdtemp()
      metadata_directory = os.path.join(temp_project_directory,
                                        METADATA_STAGED_DIRECTORY_NAME)
      os.mkdir(metadata_directory)

      #filenames = get_metadata_filenames(metadata_directory)A
      # we should do the schema check
      filenames = {}
      filenames['targets'] = os.path.join(metadata_directory,TARGETS_FILENAME)
      
      # Delegated roles.
      delegated_roles = tuf.roledb.get_delegated_rolenames('targets')
      insufficient_keys = []
      insufficient_signatures = []
      
      for delegated_role in delegated_roles:
        try: 
          _check_role_keys(delegated_role)
        except tuf.InsufficientKeysError, e:
          insufficient_keys.append(delegated_role)
          continue
        
        roleinfo = tuf.roledb.get_roleinfo(delegated_role)
        try: 
          write_delegated_metadata_file(temp_project_directory,
                                        self._targets_directory,
                                        delegated_role, roleinfo,
                                        write_partial=False)
        except tuf.Error, e:
          insufficient_signatures.append(delegated_role)
      
      if len(insufficient_keys):
        message = 'Delegated roles with insufficient keys: '+ \
          repr(insufficient_keys)
        print(message)
        return

      if len(insufficient_signatures):
        message = 'Delegated roles with insufficient signatures: '+ \
          repr(insufficient_signatures)
        print(message) 
        return

      # Targets role.
      try: 
        _check_role_keys(self.targets.rolename)
      except tuf.InsufficientKeysError, e:
        print(str(e))
        return
      
      try:
        signable =  _generate_and_write_metadata(self.targets.rolename,
                                                filenames['targets'], False,
                                                self._targets_directory,
                                                self._metadata_directory,
                                                False)
        #_print_status(self.targets.rolename, signable)
      except tuf.Error, e:
        signable = e[1]
        #_print_status(self.targets.rolename, signable)
        return

    finally:
      shutil.rmtree(temp_project_directory, ignore_errors=True)



def _print_status(rolename, signable):
  """
  Non-public function prints the number of (good/threshold) signatures of
  'rolename'.
  """

  status = tuf.sig.get_signature_status(signable, rolename)
  
  message = repr(rolename)+' role contains '+ \
    repr(len(status['good_sigs']))+' / '+ \
    repr(status['threshold'])+' signatures.'
  print(message)

def _generate_and_write_metadata(rolename, metadata_filename, write_partial,
                                 targets_directory, metadata_directory,
                                 filenames=None,
                                 prefix=''):
  """
    Non-public function that can generate and write the metadata of the
    specified
    top-level 'rolename'.  It also increments version numbers if:
    
    1.  write_partial==True and the metadata is the first to be written.
              
    2.  write_partial=False (i.e., write()), the metadata was not loaded as
        partially written, and a write_partial is not needed.
  """

  metadata = None 
  # Retrieve the roleinfo of 'rolename' to extract the needed metadata
  # attributes, such as version number, expiration, etc.
  roleinfo = tuf.roledb.get_roleinfo(rolename) 
  #release_compressions = tuf.roledb.get_roleinfo('release')['compressions']
  metadata = generate_targets_metadata(targets_directory,
                                       roleinfo['paths'],
                                       roleinfo['version'],
                                       roleinfo['expires'],
                                       roleinfo['delegations'],
                                       False) 

  # preprend the prefix to the project's filepath to avoid signature errors
  # in upstream
  for element in metadata['targets'].keys():
    junk_path, relative_target = os.path.split(element)
    prefixed_path = os.path.join(prefix,relative_target)
    metadata['targets'][prefixed_path] = metadata['targets'][element]
    if prefix != '':
      del(metadata['targets'][element])

  signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                           metadata_filename)

  # Check if the version number of 'rolename' may be automatically incremented,
  # depending on whether if partial metadata is loaded or if the metadata is
  # written with write() / write_partial(). 
  # Increment the version number if this is the first partial write.
  if write_partial:
    temp_signable = sign_metadata(metadata, [], metadata_filename)
    temp_signable['signatures'].extend(roleinfo['signatures'])
    status = tuf.sig.get_signature_status(temp_signable, rolename)
    if len(status['good_sigs']) == 0:
      metadata['version'] = metadata['version'] + 1
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)
  
  # non-partial write()
  else:
    if tuf.sig.verify(signable, rolename) and not roleinfo['partial_loaded']:
      metadata['version'] = metadata['version'] + 1
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)

  # Write the metadata to file if contains a threshold of signatures. 
  signable['signatures'].extend(roleinfo['signatures']) 
  
  if tuf.sig.verify(signable, rolename) or write_partial:
    _remove_invalid_and_duplicate_signatures(signable)
    compressions = roleinfo['compressions']
    filename = write_metadata_file(signable, metadata_filename, compressions,
                                   False)
    
    
  # 'signable' contains an invalid threshold of signatures. 
  else:
    message = 'Not enough signatures for '+repr(metadata_filename)
    raise tuf.Error(message, signable)


  # The root and timestamp files should also be written without a digest if
  # 'consistent_snaptshots' is True.  Client may request a timestamp and root
  # file without knowing its digest and file size.
  return signable, filename 


def _prompt(message, result_type=str):
  """
    Non-public function that prompts the user for input by printing 'message',
    converting the input to 'result_type', and returning the value to the
    caller.
  """

  return result_type(raw_input(message))





def _get_password(prompt='Password: ', confirm=False):
  """
    Non-public function that returns the password entered by the user.  If
    'confirm' is True, the user is asked to enter the previously entered
    password once again.  If they match, the password is returned to the caller.
  """

  while True:
    # getpass() prompts the user for a password without echoing
    # the user input.
    password = getpass.getpass(prompt, sys.stderr)
    if not confirm:
      return password
    password2 = getpass.getpass('Confirm: ', sys.stderr)
    if password == password2:
      return password
    else:
      print('Mismatch; try again.')

# TODO: change prefix to something like location_in_repository.
def create_new_project(metadata_directory, location_in_repository = '',
      targets_directory=None, key=None):
  """
  <Purpose>
    Create a new project object, instantiate barebones metadata for the 
    targets, and return a blank project object.  On disk, create_new_project()
    only creates the directories needed to hold the metadata and targets files.
    The project object returned can be directly modified to meet the designer's
    criteria and then written using the method project.write().

  <Arguments>
    metadata_directory:
      The directory that will eventually hold the metadata and target files of
      the project.

    targets_directory:
      An optional argument to point the targets directory somewhere else than
      the metadata directory if, for example, a project structure already
      exists and the user does not want to move it.

    location_in_repository:
      An optional argument to hold the "prefix" or the expected location for 
      the project files in the "upstream" respository. This value is only
      used to sign metadata in a way that it matches the future location
      of the files.

    key:
      The public key to verify the project's metadata. Projects can only
      handle one key with a threshold of one. If a project were to modify it's
      key it should be removed and updated. 
  
  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    OSError, if the filepaths provided do not have write permissions

    tuf.FormatError, if the key is not a valid public key.

  <Side Effects>
    The 'metadata_directory' and 'targets_directory'  directories are created
    if they do not exist.
    
  <Returns>
    A 'tuf.devtools.Repository' object.
  """

  # Does 'metadata_directory' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
 
  # Do the same for the location in the repo, we first check for it to be
  # something valid
  tuf.formats.PATH_SCHEMA.check_match(location_in_repository)

  # for the targets directory we do the same, but first, let's find out what
  # layout the user needs, layout_type is a variable that is usually set to
  # 1, which means "flat" (i.e. the cfg file is where the metadata folder is 
  # located), with a two, the cfg file goes to the "metadata" folder, and a 
  # new metadata folder is created inside the tree, to separate targets and
  # metadata. 
  layout_type="flat"
  if targets_directory is None:
    targets_directory = os.path.join(metadata_directory,TARGETS_DIRECTORY_NAME)
    metadata_directory = \
        os.path.join(metadata_directory,METADATA_DIRECTORY_NAME)
    layout_type="repo-like"
    

  tuf.formats.PATH_SCHEMA.check_match(targets_directory);

  if key is not None:
    tuf.formats.KEY_SCHEMA.check_match(key)
  # Set the repository, metadata, and targets directories.  These directories
  # are created if they do not exist.
  metadata_directory = os.path.abspath(metadata_directory)
  targets_directory = os.path.abspath(targets_directory)
  
  # Try to create the metadata directory that will hold all of the metadata
  # files, such as 'root.txt' and 'release.txt'.
  try:
    message = 'Creating '+repr(metadata_directory)
    logger.info(message)
    os.makedirs(metadata_directory)
  
  # 'OSError' raised if the leaf directory already exists or cannot be created.
  # Check for case where 'repository_directory' has already been created. 
  except OSError, e:
    if e.errno == errno.EEXIST:
      # should check if we have wriite permissions here
      pass 
    else:
      raise

  # Try to create the targets directory that will hold all of the target files.
  try:
    message = 'Creating '+repr(targets_directory)
    logger.info(message)
    os.mkdir(targets_directory)
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise
 
  # Create the bare bones repository object, where only the top-level roles
  # have been set and contain default values (e.g., Root roles has a threshold
  # of 1, expires 1 year into the future, etc.)
  project = Project(metadata_directory, targets_directory,
      location_in_repository)

  # add the key to the project. 
  if key is not None:
    project.add_verification_key(key);
  
  # save the layout information
  project.layout_type = layout_type

  return project

def save_project_configuration(metadata_directory,targets_directory,
                                public_keys, prefix, threshold, layout_type):
  """
  <Purpose>
    Persist the project's information in a file to provide the information
    for the load routine

  <Arguments>
    metadata_directory:
      where the project's metadata is located
    
    public_keys:
      a list containing the public keys for the toplevel targets role
    
    prefix: 
      the project's prefix (if any)
    
    threshold: 
      the threshold value for the toplevel targets role
  
    layout_type:
      the layout type being used by the project, "flat" stands for separated
      targets and metadata directories, "repo-like" emulates the layout used
      by the repository tools

  <Exceptions>
    Exceptions may rise if the metadata_directory/project.cfg file exists and
    is non-writeable

    Exceptions are also expected if either the prefix or the metadata directory
    are malformed

  <Side Effects>
    A project.cfg file is created or overwritten

  <Returns>
    nothing
  """
  # schema check for metadata_directory and prefix
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.PATH_SCHEMA.check_match(prefix)
  tuf.formats.PATH_SCHEMA.check_match(targets_directory)

  # get the absolute filepath to our metadata_directory for consistency
  metadata_directory = os.path.abspath(metadata_directory)
  cfg_file_directory = metadata_directory

  # check wheter if the layout type is "flat" or "repo-like" 
  # if it is, the .cfg file should be saved in the previous directory.
  if(layout_type == "repo-like"):
    cfg_file_directory = os.path.dirname(metadata_directory)

  # is the file open-able? open for overwriting
  project_filename = os.path.join(cfg_file_directory,PROJECT_FILENAME)
  try:
    fp = open(project_filename,"wt")
  except OSError, e:
    raise
  
  # build the data structure
  project_config = {}
  project_config['prefix'] = prefix
  project_config['public_keys'] = {}
  project_config['metadata_location'] = metadata_directory
  project_config['targets_location'] = targets_directory
  project_config['threshold'] = threshold
  project_config['layout_type'] = layout_type
  # build a dictionary containing the actual keys
  for key in public_keys:
    key_info = tuf.keydb.get_key(key)
    project_config['public_keys'][key] = {}
    project_config['public_keys'][key]['keytype'] = key_info['keytype']
    project_config['public_keys'][key]['public'] = key_info['keyval']['public']

  # save the actual data
  json.dump(project_config,fp)

  # clean our mess
  fp.close()


def load_project(project_directory, prefix=''):
  """
  <Purpose>
    Return a project object initialized with the contents of the metadata 
    files loaded from the project_directory path

  <Arguments>
    project_directory: 
      The path to the project's folder
    prefix:
      the prefix for the metadata, if defined, it will replace the current
      prefix, by first removing the existing one (Saved) and setting the new
      one in the end. 

  <Exceptions>
    tuf.FormatError, if 'project_directory' or any of the metadata files
    are improperly formatted. 

  <Side Effects>
   All the metadata files found in the project are loaded and their contents
   stored in a libtuf.Repository object.

  <Returns>
    libtuf.Repository object.
  
  """
  # Does 'repository_directory' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(project_directory)
  # do the same for the prefix
  tuf.formats.PATH_SCHEMA.check_match(prefix)


  # Locate metadata filepaths and targets filepath.
  project_directory = os.path.abspath(project_directory)
  
  
  # load the cfg file and update the project.
  config_filename = os.path.join(project_directory,PROJECT_FILENAME)
  try:
    project_configuration = tuf.util.load_json_file(config_filename)
  except OSError, e:
    raise
  
  metadata_directory = project_configuration['metadata_location']
  targets_directory = project_configuration['targets_location']
  if prefix=='':
    prefix = project_configuration['prefix']
  

  # create a blank project on the target directory
  project = Project(metadata_directory,targets_directory , prefix)

  project.targets.threshold = project_configuration['threshold']
  project.prefix = project_configuration['prefix']
  project.layout_type = project_configuration['layout_type']

  # traverse the public keys and add them to the project
  keydict = project_configuration['public_keys']
  for keyid in keydict:
    if keydict[keyid]['keytype'] == 'rsa':
      temp_pubkey = tuf.keys.format_rsakey_from_pem(keydict[keyid]['public'])
    elif keydict[keyid]['keytype'] == 'ed25519':
      temp_pubkey = {}
      temp_pubkey['keytype'] = keydict[keyid]['keytype']
      temp_pubkey['keyval'] = {}
      temp_pubkey['keyval']['public'] = keydict[keyid]['public']
      temp_pubkey['keyval']['private'] = ''
    else:
      temp_pubkey = keydict
    project.add_verification_key(temp_pubkey)
  

  # load the toplevel metadata
  targets_metadata_path = os.path.join(metadata_directory, TARGETS_FILENAME)
  signable = tuf.util.load_json_file(targets_metadata_path)
  tuf.formats.check_signable_object_format(signable)
  targets_metadata = signable['signed']
  
  # remove the prefix from the metadata
  targets_metadata = _strip_prefix_from_targets_metadata(targets_metadata,
                                              project_configuration['prefix'])
  for signature in signable['signatures']:
    project.targets.add_signature(signature)

  # update roledb
  roleinfo = tuf.roledb.get_roleinfo('targets')
  roleinfo['signatures'].extend(signable['signatures'])
  roleinfo['version'] = targets_metadata['version']
  roleinfo['paths'] = targets_metadata['targets'].keys()
  roleinfo['delegations'] = targets_metadata['delegations']
  
  _check_if_partial_loaded('targets',signable,roleinfo)
  tuf.roledb.update_roleinfo('targets',roleinfo)

  
  
  for key_metadata in targets_metadata['delegations']['keys'].values():
    key_object = tuf.keys.format_metadata_to_key(key_metadata)
    tuf.keydb.add_key(key_object)

  for role in targets_metadata['delegations']['roles']:
    rolename = role['name']
    roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                'threshold': role['threshold'], 'compressions': [''],
                'signing_keyids': [], 'signatures': [], 'partial_loaded':False,
                'delegations': {'keys':{}, 'roles':[]}
                }
    tuf.roledb.add_role(rolename, roleinfo)
                                                        
  # Load delegated targets metadata.
  # Walk the 'targets/' directory and generate the fileinfo of all the files
  # listed.  This information is stored in the 'meta' field of the release
  # metadata object.
  targets_objects = {}
  loaded_metadata = []
  targets_objects['targets'] = project.targets
  targets_metadata_directory = os.path.join(metadata_directory,
                                            TARGETS_DIRECTORY_NAME)
  if os.path.exists(targets_metadata_directory) and \
                    os.path.isdir(targets_metadata_directory):
    for root, directories, files in os.walk(targets_metadata_directory):
      
      # 'files' here is a list of target file names.
      for basename in files:
        metadata_path = os.path.join(root, basename)
        metadata_name = \
          metadata_path[len(metadata_directory):].lstrip(os.path.sep)

        # strip the extension
        if metadata_name.endswith(METADATA_EXTENSION): 
          extension_length = len(METADATA_EXTENSION)
          metadata_name = metadata_name[:-extension_length]
        else:
          continue
        
        # Keep a store metadata previously loaded metadata to prevent
        # re-loading duplicate versions.  Duplicate versions may occur with
        # consistent_snapshots, where the same metadata may be available in
        # multiples files (the different hash is included in each filename.
        if metadata_name in loaded_metadata:
          continue

        signable = None
        try:
          signable = tuf.util.load_json_file(metadata_path)
        except (ValueError, IOError), e:
          continue
        
        # strip the extension from the 
        metadata_object = signable['signed']
        metadata_object = _strip_prefix_from_targets_metadata(metadata_object,
                                              project_configuration['prefix'])
  
        roleinfo = tuf.roledb.get_roleinfo(metadata_name)
        roleinfo['signatures'].extend(signable['signatures'])
        roleinfo['version'] = metadata_object['version']
        roleinfo['expires'] = metadata_object['expires']
        roleinfo['paths'] = metadata_object['targets'].keys()
        roleinfo['delegations'] = metadata_object['delegations']
      
        if os.path.exists(metadata_path+'.gz'):
          roleinfo['compressions'].append('gz')


        _check_if_partial_loaded(metadata_name, signable, roleinfo)
        tuf.roledb.update_roleinfo(metadata_name, roleinfo)

        # append to list of elements to avoid reloading repeated metadata
        loaded_metadata.append(metadata_name)

        # add the delegation
        new_targets_object = Targets(targets_directory, metadata_name, roleinfo)
        targets_object = \
          targets_objects[tuf.roledb.get_parent_rolename(metadata_name)]
        targets_objects[metadata_name] = new_targets_object
        
        targets_object._delegated_roles[(os.path.basename(metadata_name))] = \
                              new_targets_object

        # Add the keys specified in the delegations field of the Targets role.
        for key_metadata in metadata_object['delegations']['keys'].values():
          key_object = tuf.keys.format_metadata_to_key(key_metadata)
          try: 
            tuf.keydb.add_key(key_object)
          except tuf.KeyAlreadyExistsError, e:
            pass
        
        for role in metadata_object['delegations']['roles']:
          rolename = role['name'] 
          roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                      'threshold': role['threshold'],
                      'compressions': [''], 'signing_keyids': [],
                      'signatures': [],
                      'partial_loaded': False,
                      'delegations': {'keys': {},
                                      'roles': []}}
          tuf.roledb.add_role(rolename, roleinfo)
 
  return project

def _strip_prefix_from_targets_metadata(targets_metadata, prefix):
  """ non-public method that removes the prefix from the targets metadata
      so it can be used again in compliance with the local copies
  """
  unprefixed_targets_metadata = {}
  for targets in targets_metadata['targets'].keys():
    unprefixed_target = os.path.relpath(targets, prefix)
    unprefixed_target = '/' + unprefixed_target
    unprefixed_targets_metadata[unprefixed_target] = \
                            targets_metadata['targets'][targets] 
  targets_metadata['targets'] = unprefixed_targets_metadata
  
  return targets_metadata 

if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running libtuf.py as a standalone module:
  # $ python libtuf.py.
  import doctest
  doctest.testmod()
