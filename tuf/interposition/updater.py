"""
<Program Name>
  updater.py

<Author>
  Trishank Kuppusamy
  Pankhuri Goyal <pankhurigoyal02@gmail.com>

<Started>
  June 2014.
    Refactored and unit tested by Pankhuri.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Assist with high-level integrations, which means that all the processes that
  are taking place in the low-level 'tuf.client.updater.py' will be automated
  by this module. This layer of automation will be transparent to the software
  updater; urllib-type calls will be intercepted and TUF metadata automatically
  fetched along with the packages requested by the software updater.

  This module provides two classes: Updater and UpdaterController:

  'tuf.interposition.updater.Updater' contains those methods which are to be
  performed on each individual updater. For example: refresh(), cleanup(),
  download_target(target_filepath), get_target_filepath(source_url), open(url),
  retrieve(url), switch_context(); all these methods act on particular updater.

  'tuf.interposition.updater.UpdaterController' contains those methods which
  are performed on updaters as a group. It basically keeps track of all the
  updaters. For example: add(configuration), get(configuration),
  refresh(configuration), remove(configuration), all these are performed on the
  list of updaters. 'tuf.interposition.updater.UpdaterController' maintains a
  map of updaters and a set of its mirrors. The map of updaters contains the
  objects of 'tuf.interposition.updater.Updater' for each updater. The set
  contains all the mirrors. The addition and removal of these updaters and
  their mirrors depends on the methods of
  'tuf.interposition.updater.UpdaterController'.

<Example integration with interposition>

  To integrate TUF into a software updater with interposition, integrators only
  need to complete two main tasks:  First, a JSON configuration file for
  interposition is created.  Second, the software updater is modified to import
  the interposition library and configure interposition.

  1. 'interposition.py' (code included below) is a basic example software
     updater that is integrating TUF with interposition.

     # First import the interposition package, which contains all of the
     # required classes and functions to use TUF and interposition.
     import tuf.interposition

     # Next, explicitly import the urllib modules that interposition will be
     # interposing/overwriting.  'urllib_tuf' and 'urllib2_tuf' are TUF's
     # copies of urllib and urllib2 that are modified to perform updates using
     # the framework and the TUF metadata.
     from tuf.interposition import urllib_tuf as urllib
     from tuf.interposition import urllib2_tuf as urllib2

     # The configure() method must now be called.  It takes 3 optional
     # arguments, one of which is the filename of a JSON configuration file.
     # This JSON file contains a set of configurations. To make this file,
     # follow the second point below.  Ways to call this method are as follows:
     # First, configure() - By default, the configuration object is expected to
     # be located in the current working directory in the file with the name
     # "tuf.interposition.json".  Second, configure(filename="/path/to/json")
     # Configure() returns a dictionary of configurations. Internally,
     # configure() calls add(configuration) function which is in the
     # 'tuf.interposition.updater.UpdaterController' class.
     configurations = tuf.interposition.configure()

     url = 'http://example.com/path/to/file'

     # This is the standard way of opening and retrieving URLs in Python.
     # All three urllib calls below are intercepted by TUF's interposition.
     urllib.urlopen(url)
     urllib.urlretrieve(url)
     urllib2.urlopen(url)

     # Remove TUF interposition for previously read configurations. That is
     # remove the updater object.
     # Deconfigure() takes only one argument (i.e. configurations).
     # It calls the remove(configuration) function which is in
     # 'tuf.interposition.updater.UpdaterController'.
     tuf.interposition.deconfigure(configurations)


  2. The filename passed as a argument to configure() is a JSON file.
     It is loaded as a JSON object, which tells tuf.interposition which URLs to
     intercept, how to transform them (if necessary), and where to forward them
     (possibly over SSL) for secure responses via TUF. By default, the name of
     the file is tuf.interposition.json.  An example of a configuration file
     follows.

     # configurations are simply a JSON object that allows you to answer
     # these questions -
     # - Which network locations get intercepted?
     # - Given a network location, which TUF mirrors should we forward
     #   requests to?
     # - Given a network location, which paths should be intercepted?
     # - Given a TUF mirror, how do we verify its SSL certificate?
     {
     # This is a required root object.
     "configurations": {
       # Which network location should be intercepted?
       # Network locations may be specified as "hostname" or "hostname:port".
       "localhost": {

         # Where do we find the client copy of the TUF server metadata?
         "repository_directory": ".",

         # Where do we forward the requests to localhost?
         "repository_mirrors" : {
           "mirror1": {
             # In this case, we forward them to http://localhost:8001
             "url_prefix": "http://localhost:8001",

             # You do not have to worry about these default parameters.
             "metadata_path": "metadata",
             "targets_path": "targets",
             "confined_target_dirs": [""]
           }
         }
       }
     }

  # After creating 'settingsiguration.json' and the example updater module, run
  # 'interposition.py'.  The urllib calls will be intercepted, and information
  # about the update process is generated to a log file named 'tuf.log' in the
  # same directory, which can be reviewed.
"""

# Help with Python 3 compatibility where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division. Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import mimetypes
import os.path
import re
import shutil
import tempfile
import logging

import tuf.client.updater
import tuf.log

import securesystemslib
import six

from tuf.interposition.configuration import Configuration


logger = logging.getLogger('tuf.interposition.updater')


class Updater(object):
  """
  <Purpose>
    Provide a class that can download target files securely. It performs all
    the actions of 'tuf/client/updater.py', but adds methods to handle HTTP
    requests and multiple updater objects.

  <Updater Methods>
    refresh():
      This method refreshes top-level metadata. It calls the refresh() method of
      'tuf.client.updater'. refresh() method of 'tuf.client.updater' downloads,
      verifies, and loads metadata of the top-level roles in a specific order
      (i.e., timestamp -> snapshot -> root -> targets). The expiration time for
      downloaded metadata is also verified.

    cleanup():
      It will clean up all the temporary directories that are made following a
      download request. It also logs a message when a temporary file/directory
      is deleted.

    download_target(target_filepath):
      It downloads the 'target_filepath' repository file. It also downloads any
      required metadata to securely satisfy the 'target_filepath' request.

    get_target_filepath(source_url):
      'source_url' is the URL of the file to be updated.  This method will find
      the updated target for this file.

    open(url, data):
      Open the 'url' URL, which can either be a string or a request object.
      The file is opened in the binary read mode as a temporary file.

    retrieve(url, filename, reporthook, data):
      retrieve() method first gets the target file path by calling
      get_target_filepath(url), which is in 'tuf.interposition.updater.Updater'
      and then calls download_target() for the above file path.

    switch_context():
      There is an updater object for each network location that is interposed.
      Context switching is required because there are multiple
      'tuf.client.updater' objects and each one depends on settings settings
      that are shared.
  """


  def __init__(self, configuration):
    """
    <Purpose>
      Constructor for an updater object that may be used to satisfy TUF update
      requests, and can be used independent of other updater objects.  A
      temporary directory is created when this updater object is instantiated,
      which is needed by 'tuf.interposition.updater.Updater', and the top-level
      roles are refreshed.  The 'tuf.client.updater' module performs the
      low-level calls.

    <Arguments>
      configuration:
        A dictionary holding information like the following:

        - Which network location get intercepted?
        - Given a network location, which TUF mirrors should we forward requests
          to?
        - Given a network location, which paths should be intercepted?
        - Given a TUF mirror, how do we verify its SSL certificate?

      This dictionary holds repository mirror information, conformant to
      'tuf.formats.MIRRORDICT_SCHEMA'. Information such as the directory
      containing the metadata and target files, the server's URL prefix, and
      the target directories the client should be confined to.

      repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                        'metadata_path': 'metadata',
                                        'targets_path': 'targets',
                                        'confined_target_dirs': ['']}}

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If the arguments of 'tuf.client.updater.Updater' are improperly
        formatted.

      tuf.exceptions.RepositoryError:
        If there is an error with the updater's repository files, such
        as a missing 'root.json' file.

      tuf.exceptions.NoWorkingMirrorError:
        If while refreshing, the metadata for any of the top-level roles cannot
        be updated.

      tuf.exceptions.ExpiredMetadataError:
        While refreshing, if any metadata has expired.

    <Side Effects>
      The metadata files (e.g., 'root.json', 'targets.json') for the top-level
      roles are read from disk and stored in dictionaries.

    <Returns>
      None.
    """

    self.configuration = configuration

    # A temporary directory used for this updater over runtime.
    self.tempdir = tempfile.mkdtemp()
    logger.debug('Created temporary directory at ' + repr(self.tempdir))

    # Switching context before instantiating updater because updater depends
    # on some module (settings) variables.
    self.switch_context()

    # Instantiating a 'tuf.client.updater' object causes all the configurations
    # for the top-level roles to be read from disk, including the key and role
    # information for the delegated targets of 'targets'. The actual metadata
    # for delegated roles is not loaded in __init__.  The metadata for these
    # delegated roles, including nested delegated roles, are loaded, updated,
    # and saved to the 'self.metadata' store by the target methods, like
    # all_targets() and targets_of_role().
    self.updater = tuf.client.updater.Updater(self.configuration.hostname,
                                              self.configuration.repository_mirrors)

    # Update the client's top-level metadata.  The download_target() method
    # does not automatically refresh top-level prior to retrieving target files
    # and their associated Targets metadata, so update the top-level metadata
    # here.
    logger.info('Refreshing top-level metadata for interposed ' + repr(configuration))
    self.updater.refresh()


  def refresh(self):
    """
    <Purpose>
      This method refreshes the top-level metadata. It calls the refresh()
      method of 'tuf.client.updater'.  refresh() method of
      'tuf.client.updater.py' downloads, verifies, and loads metadata for the
      top-level roles in a specific order (i.e., timestamp -> snapshot -> root
      -> targets) The expiration time for downloaded metadata is also verified.

      This refresh() method should be called by the client before any target
      requests. Therefore to automate the process, it is called here.

    <Arguments>
      None

    <Exceptions>
      tuf.exceptions.NoWorkingMirrorError:
        If the metadata for any of the top-level roles cannot be updated.

      tuf.exceptions.ExpiredMetadataError:
        If any metadata has expired.

    <Side Effects>
      Updates the metadata files of the top-level roles with the latest
      information.

    <Returns>
      None
    """

    self.updater.refresh()


  def cleanup(self):
    """
    <Purpose>
      Remove the updater object's temporary directory (and any sub-directories)
      created when the updater object is instantiated to store downloaded
      targets and metadata.

    <Arguments>
      None

    <Exceptions>
      None

    <Side Effects>
      Removal of the temporary 'self.tempdir' directory.

    <Returns>
      None
    """

    shutil.rmtree(self.tempdir)
    logger.debug('Deleted temporary directory at ' + repr(self.tempdir))


  def download_target(self, target_filepath):
    """
    <Purpose>
      Download the 'target_filepath' target file.  Everything here is performed
      in a temporary directory.  It identifies the target information for
      'target_filepath' by calling the get_one_valid_targetinfo() method of
      'tuf.client.updater'.  This method also downloads the metadata of the
      updated targets. By doing this, the client retrieves the target
      information for the targets they want to update. When client retrieves
      all the information, the updated_targets() method of 'tuf.client.updater'
      is called to determine the list of targets which have been changed from
      those saved locally on disk.  tuf.client.upater.download_target()
      downloads all the targets in the list in the destination directory, which
      is our temporary directory.

      This will only store the file in the temporary directory if the
      downloaded file matches the description of the file in the trusted
      metadata.

    <Arguments>
      target_filepath:
        The target's relative path on the remote repository.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If 'target_filepath', 'updated_target' in
        'tuf.client.updater.download_target', is  improperly formatted.

      tuf.exceptions.UnknownTargetError:
        If 'target_filepath' was not found.

      tuf.exceptions.NoWorkingMirrorError:
        If a 'target_filepath' could not be downloaded from any of the mirrors.

    <Side Effects>
      A target file is saved to the local system.

    <Returns>
      It returns  a (destination directory, filename) tuple where the target is
      been stored and filename of the target file been stored in the directory.
    """

    securesystemslib.formats.RELPATH_SCHEMA.check_match(target_filepath)

    # Download file into a temporary directory shared over runtime
    destination_directory = self.tempdir

    # A new path is generated by joining the destination directory path that is
    # our temporary directory path and target file path.
    # Note: join() discards 'destination_directory' if 'target_filepath'
    # contains a leading path separator (i.e., is treated as an absolute path).
    filename = \
      os.path.join(destination_directory, target_filepath.lstrip(os.sep))

    # Switch TUF context. Switching context before instantiating updater
    # because updater depends on some module (settings) variables.
    self.switch_context()

    # Locate the fileinfo of 'target_filepath'.
    # updater.get_one_valid_targetinfo() searches targets metadata in order of
    # trust, according to the currently trusted snapshot.  To prevent
    # consecutive target file requests from referring to different snapshots,
    # top-level metadata is not automatically refreshed.  It returns the target
    # information for a specific file identified by its file path.  This target
    # method also downloads the metadata of updated targets.
    targets = [self.updater.get_one_valid_targetinfo(target_filepath)]

    # TODO: targets are always updated if destination directory is new, right?
    # After the client has retrieved the target information for those targets
    # they are interested in updating, updated_targets() method is called to
    # determine which targets have changed from those saved locally on disk.
    # All the targets that have changed are returned in a list. From this list,
    # a request to download is made by calling 'download_target()'.
    updated_targets = \
      self.updater.updated_targets(targets, destination_directory)

    # The download_target() method in tuf.client.updater performs the actual
    # download of the specified target. The file is saved to the
    # 'destination_directory' argument.
    for updated_target in updated_targets:
      self.updater.download_target(updated_target, destination_directory)

    return destination_directory, filename


  # TODO: decide prudent course of action in case of failure.
  def get_target_filepath(self, source_url):
    """
    <Purpose>
      Given source->target map, this method will figure out what TUF should
      download when a URL is given.

    <Arguments>
      source_url:
        The URL of the target we want to retrieve.

    <Exceptions>
      tuf.exceptions.URLMatchesNoPatternError:
        This exception is raised when no target_path url pattern is wrong and
        does match regular expression.

    <Side Effects>
      None

    <Returns>
      If the target filepath is matched, return the filepath, otherwise raise
      an exception.
    """

    parsed_source_url = six.moves.urllib.parse.urlparse(source_url)
    target_filepath = None

    try:
      # Does this source URL match any regular expression which tells us
      # how to map the source URL to a target URL understood by TUF?
      for target_path in self.configuration.target_paths:

        #TODO: What these two lines are doing?
        # target_path: { "regex_with_groups", "target_with_group_captures" }
        # e.g. { ".*(/some/directory)/$", "{0}/index.html" }
        source_path_pattern, target_path_pattern = list(target_path.items())[0]
        source_path_match = \
          re.match(source_path_pattern, parsed_source_url.path)

        # TODO: A failure in string formatting is *critical*.
        if source_path_match is not None:
          target_filepath = \
            target_path_pattern.format(*source_path_match.groups())

          # If there is more than one regular expression which
          # matches source_url, we resolve ambiguity by order of
          # appearance.
          break

      # If source_url does not match any regular expression...
      if target_filepath is None:
        # ...then we raise a predictable exception.
        raise tuf.exceptions.URLMatchesNoPatternError(source_url)

    except:
      logger.exception('Possibly invalid target_paths for ' + \
        repr(self.configuration.network_location) + \
        '! No TUF interposition for ' + repr(source_url))
      raise

    else:
      return target_filepath


  # TODO: distinguish between urllib and urllib2 contracts.
  def open(self, url, data=None):
    """
    <Purpose>
      Open the URL url which can either be a string or a request object.
      The file is opened in the binary read mode as a temporary file. This is
      called when TUF wants to open an already existing updater's 'url'.

    <Arguments>
      url:
        The one which is to be opened.

      data:
        Must be a bytes object specifying additional data to be sent to the
        server or None, if no such data needed.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        TODO: validate arguments.

      tuf.exceptions.NoWorkingMirrorError:
        If a 'target_filepath' could not be downloaded from any of the mirrors.

      tuf.exceptions.URLMatchesNoPatternError:
        This exception is raised when no target_path url pattern is wrong and
        does match regular expression.

    <Side Effects>
      None

    <Returns>
      'response' which is a file object with info() and geturl() methods added.
    """

    # TODO: validate arguments.

    filename, headers = self.retrieve(url, data=data)

    # TUF should always open files in binary mode and remain transparent to the
    # software updater.  Opening files in text mode slightly alters the
    # end-of-line characters and prevents binary files from properly loading on
    # Windows.
    # http://docs.python.org/2/tutorial/inputoutput.html#reading-and-writing-files
    # TODO: like tempfile, ensure file is deleted when closed?  open() in the
    # line below is a predefined function in python.
    temporary_file = open(filename, 'rb')

    #TODO: addinfourl is not in urllib package anymore. We need to check if
    # other option for this is working or not.
    # Extend temporary_file with info(), getcode(), geturl()
    # http://docs.python.org/2/library/urllib.html#urllib.urlopen
    # addinfourl() works as a context manager.
    response = six.moves.urllib.response.addinfourl(temporary_file, headers,
                                                    url, code=200)

    return response


  # TODO: distinguish between urllib and urllib2 contracts
  def retrieve(self, url, filename=None, reporthook=None, data=None):
    """
    <Purpose>
      Get the target file path by calling self.get_target_filepath(url)  and
      then self.download_target() method for the above file path.

    <Arguments>
      url:
        The URL of the target file to retrieve.

      filename:
        If given, then the given filename is used.  If the filename is none,
        then temporary file is used.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If 'target_filepath', 'updated_target' in
        tuf.client.updater.download_target and arguments of updated_targets are
        improperly formatted.

      tuf.exceptions.UnknownTargetError:
        If 'target_filepath' was not found.

      tuf.exceptions.NoWorkingMirrorError:
        If a 'target_filepath' could not be downloaded from any of the mirrors.

      tuf.exceptions.URLMatchesNoPatternError:
        This exception is raised when no target_path url pattern is wrong and
        does match regular expression.

    <Side Effects>
      A target file is saved to the local system when the
      download_target(target_filepath) is called.

    <Returns>
      It returns the filename and the headers of the file just retrieved.
    """

    logger.info('Interposing for '+ repr(url))

    # What is the actual target to download given the URL? Sometimes we would
    # like to transform the given URL to the intended target; e.g. "/simple/"
    # => "/simple/index.html".
    target_filepath = self.get_target_filepath(url)

    # TODO: Set valid headers fetched from the actual download.
    # NOTE: Important to guess the mime type from the target_filepath, not the
    # unmodified URL.
    content_type, content_encoding = mimetypes.guess_type(target_filepath)
    headers = {
      # NOTE: pip refers to this same header in at least these two duplicate
      # ways.
      "content-type": content_type,
      "Content-Type": content_type,
    }

    # Download the target filepath determined by the original URL.
    temporary_directory, temporary_filename = \
      self.download_target(target_filepath)

    if filename is None:
      # If no filename is given, use the temporary file.
      filename = temporary_filename
    else:
      # Otherwise, copy TUF-downloaded file in its own directory
      # to the location user specified.
      shutil.copy2(temporary_filename, filename)

    return filename, headers


  # TODO: thread-safety, perhaps with a context manager.
  def switch_context(self):
    """
    <Purpose>
      There is an updater object for each network location that is interposed.
      Context switching is required because there are multiple
      'tuf.client.updater' objects and each one depends on settings settings
      that are shared.

      For this, two settings are required:

      1. Setting local repository directory in 'settings'.
      2. Setting the local SSL certificate PEM file.

    <Arguments>
      None

    <Exceptions>
      None

    <Side Effects>
      The given configuration's 'repository_directory' and ssl_certificates
      settings are set to 'tuf.settings.repositories_directory' and
      'tuf.settings.ssl_certificates', respectively.

    <Returns>
      None
    """

    # Set the local repositories directory containing the metadata files.
    tuf.settings.repositories_directory = self.configuration.repository_directory

    # Set the local SSL certificates PEM file.
    tuf.settings.ssl_certificates = self.configuration.ssl_certificates



class UpdaterController(object):
  """
  <Purpose>
    A controller of Updater() objects.  Given a configuration, it can build and
    store an Updater, which can be used later with the help of get() method.

  <UpdaterController's Methods>

    __init__():
      It creates and initializes an empty private map of updaters and an empty
      private set of repository mirror network locations (hostname:port). This
      is used to store the updaters added by TUF and later on TUF can get these
      updater to reutilize.

    __check_configuration_on_add(configuration):
      It checks if the given configuration is valid or not.

    add(configuration):
      This method adds the updater by adding an object of
      'tuf.interposition.updater.Updater' in the __updater map and by adding
      repository mirror's network location in the empty set initialized when
      the object of 'tuf.interposition.updater.UpdaterController' is created.

    get(url):
      Get the updater if it already exists. It takes the url and parses it.
      Then it utilizes hostname and port of that url to check if it already
      exists or not. If the updater exists, then it calls the
      get_target_filepath() method which returns a target file path to be
      downloaded.

    refresh(configuration):
      Refreshes the top-level metadata of the given 'configuration'.  It
      updates the latest copies of the metadata of the top-level roles.

    remove(configuration):
      Remove an Updater matching the given 'configuration' as well as its
      associated mirrors.
  """

  def __init__(self):
    """
    <Purpose>
      Initalize a private map of updaters and a private set of repository
      mirror network locations (hostname:port) once the object of
      'tuf.interposition.updater.UpdaterController' is created. This empty map
      and set is later used to add, get, and remove updaters and their mirrors.

    <Arguments>
      None

    <Exceptions>
      None

    <Side Effects>
      An empty map called '__updaters' and an empty set called
      '__repository_mirror_network_locations' is created.

    <Returns>
      None
    """

    # A private map of Updaters (network_location: str -> updater: Updater)
    self.__updaters = {}

    # A private set of repository mirror network locations
    self.__repository_mirror_network_locations = set()


  def __check_configuration_on_add(self, configuration):
    """
    <Purpose>
      If the given Configuration is invalid, an exception is raised.
      Otherwise, repository mirror network locations are returned.

    <Arguments>
      'configuration' contains hostname, port number, repository mirrors which
      are to be checked if they are valid or not.

    <Exceptions>
      tuf.exceptions.InvalidConfigurationError:
        If the configuration is invalid. For example - wrong hostname, invalid
        port number, wrong mirror format.

      securesystemslib.exceptions.FormatError:
        If the network_location is not unique or configuration.network_location
        is same as repository_mirror_network_locations.

    <Side Effects>
      It logs the error message.

    <Returns>
      'repository_mirror_network_locations'
        In order to prove that everything worked well, a part of configuration
        is returned which is the list of repository mirrors.
    """

    # Updater has a "global" view of configurations, so it performs
    # additional checks after Configuration's own local checks. This will
    # check if everything in tuf.interposition.configuration.ConfigurationParser
    # worked or not.

    # According to __read_configuration() method in
    # tuf.interposition.__init__,
    # configuration is an instance of
    # tuf.interposition.configuration.Configuration because in this method -
    # configuration = configuration_parser.parse()
    # configuration_parser is an instance of
    # tuf.interposition.configuration.ConfigurationParser
    # The configuration_parser.parse() returns
    # tuf.interposition.configuration.Configuration as an object which makes
    # configuration an instance of tuf.interposition.configuration.Configuration
    if not isinstance(configuration, Configuration):
      raise tuf.exceptions.InvalidConfigurationError('Invalid configuration')

    # Restrict each (incoming, outgoing) network location pair to be unique across
    # configurations; this prevents interposition cycles, amongst other
    # things.
    # GOOD: A -> { A:X, A:Y, B, ... }, C -> { D }, ...
    # BAD: A -> { B }, B -> { C }, C -> { A }, ...
    if configuration.network_location in self.__updaters:
      message = 'Updater with ' + repr(configuration.network_location) + \
                ' already exists as an updater.'
      raise securesystemslib.exceptions.FormatError()

    if configuration.network_location in self.__repository_mirror_network_locations:
      message = 'Updater with ' + repr(configuration.network_location) + \
                ' already exists as a mirror.'
      raise securesystemslib.exceptions.FormatError(message)

    # Check for redundancy in server repository mirrors.
    repository_mirror_network_locations = \
      configuration.get_repository_mirror_hostnames()

    for mirror_network_location in repository_mirror_network_locations:
      try:
        # Restrict each network location in every (incoming, outgoing) pair to be
        # unique across configurations; this prevents interposition cycles,
        # amongst other things.
        if mirror_network_location in self.__updaters:
          message = 'Mirror with ' + repr(mirror_network_location) + \
                    ' already exists as an updater.'
          raise securesystemslib.exceptions.FormatError(message)

        if mirror_network_location in self.__repository_mirror_network_locations:
          message = 'Mirror with ' + repr(mirror_network_location) + \
                    ' already exists as a mirror.'
          raise securesystemslib.exceptions.FormatError(message)

      except (securesystemslib.exceptions.FormatError) as e:
        error_message = 'Invalid repository mirror ' + \
                        repr(mirror_network_location)
        logger.exception(error_message)
        raise

    return repository_mirror_network_locations


  def add(self, configuration):
    """
    <Purpose>
      Add an Updater based on the given 'configuration'. TUF keeps track of the
      updaters so that it can be fetched for later use.

    <Arguments>
      'configuration' is an object and on the basis of this configuration, an
      updater will be added.

    <Exceptions>
      tuf.exceptions.InvalidConfigurationError:
        If the configuration is invalid. For example - wrong hostname, invalid
        port number, wrong mirror format.

      securesystemslib.exceptions.FormatError:
        This exception is raised if the network location which tuf is trying to
        add is not unique.

    <Side Effects>
      The object of 'tuf.interposition.updater.Updater' is added in the list of
      updaters.  Also, the mirrors of this updater are added to
      'repository_mirror_network_locations'.

    <Returns>
      None
    """

    repository_mirror_network_locations = \
      self.__check_configuration_on_add(configuration)

    # If all is well, build and store an Updater, and remember network
    # locations.
    logger.info('Adding updater for interposed ' + repr(configuration))

    # Adding an object of the tuf.interposition.updater.Updater with the given
    # configuration.
    self.__updaters[configuration.network_location] = Updater(configuration)

    # Adding the new the repository mirror network locations to the list.
    self.__repository_mirror_network_locations.update(repository_mirror_network_locations)


  def refresh(self, configuration):
    """
    <Purpose>
      To refresh the top-level metadata of the given 'configuration'.
      It updates the latest copies of the metadata for the top-level roles.

    <Arguments>
      'configuration' is the object containing the configurations of the updater
      to be refreshed.

    <Exceptions>
      tuf.exceptions.InvalidConfigurationError:
        If there is anything wrong with the Format of the configuration, this
        exception is raised.

      tuf.exceptions.NotFoundError:
        If the updater to be refreshed is not found in the list of updaters or
        mirrors, then tuf.exceptions.NotFoundError exception is raised.

      tuf.exceptions.NoWorkingMirrorError:
        If the metadata for any of the top-level roles cannot be updated.

      tuf.exceptions.ExpiredMetadataError:
        If any metadata has expired.

    <Side Effects>
      It refreshes the updater and indicate this in the log file.

    <Returns>
      None
    """

    # Check if the configuration is valid else raise an exception.
    if not isinstance(configuration, Configuration):
      raise tuf.exceptions.InvalidConfigurationError('Invalid configuration')

    # Get the repository mirrors of the given configuration.
    repository_mirror_network_locations = \
      configuration.get_repository_mirror_hostnames()

    # Check if the configuration.network_location is available in the updater
    # or mirror list.
    if configuration.network_location not in self.__updaters:
      message = 'Update with ' + repr(configuration.network_location) + \
                ' not found.'
      raise tuf.exceptions.NotFoundError(message)

    if not repository_mirror_network_locations.issubset(self.__repository_mirror_network_locations):
      message = 'Mirror with ' + repr(repository_mirror_network_locations) + \
                ' not found.'
      raise tuf.exceptions.NotFoundError(message)

    # Get the updater and refresh its top-level metadata.  In the majority of
    # integrations, a software updater integrating TUF with interposition will
    # usually only require an initial refresh() (i.e., when configure() is
    # called).  A series of target file requests may then occur, which are all
    # referenced by the latest top-level metadata updated by configure().
    # Although interposition was designed to remain transparent, for software
    # updaters that require an explicit refresh of top-level metadata, this
    # method is provided.
    logger.info('Refreshing top-level metadata for ' + repr(configuration))

    # If everything is good then fetch the updater from __updaters with the
    # given configurations.
    updater = self.__updaters.get(configuration.network_location)

    # Refresh the fetched updater.
    updater.refresh()


  def get(self, url):
    """
    <Purpose>
      This method is to get the updater if it already exists. It takes the url
      and parse it. Then it utilizes hostname and port of that url to check if
      it already exists or not. If the updater exists, then it calls the
      get_target_filepath() method which returns a target file path to be
      downloaded.

    <Arguments>
      url:
        URL which TUF is trying to get an updater. Assumption that url is a
      string.

    <Exceptions>
      None

    <Side Effects>
      This method logs the messages in a log file if updater is not found or
      not for the given url.

    <Returns>
      The get() method returns the updater with the given configuration. If
      updater does not exists, it returns None.
    """

    updater = None

    try:
      # Parse the given url to access individual parts of it.
      parsed_url = six.moves.urllib.parse.urlparse(url)
      hostname = parsed_url.hostname
      port = parsed_url.port or 80
      netloc = parsed_url.netloc

      # Combine the hostname and port number and assign it to network_location.
      # The combination of hostname and port is used to identify an updater.
      network_location = \
        "{hostname}:{port}".format(hostname=hostname, port=port)

      # There can be a case when parsed_url.netloc does not have a port (e.g.
      # 80). To avoid errors because of this case, tuf.interposition again set
      # the parameters.
      network_locations = set((netloc, network_location))

      updater = self.__updaters.get(network_location)

      if updater is None:
        logger.warning('No updater for ' + repr(hostname))

      else:

        # Ensure that the updater is meant for this (hostname, port).
        if updater.configuration.network_location in network_locations:
          logger.info('Found updater for interposed network location: '+ \
            repr(network_location))

          # Raises an exception in case we do not recognize how to
          # transform this URL for TUF. In that case, there will be no
          # updater for this URL.
          target_filepath = updater.get_target_filepath(url)

        else:
          # Same hostname, but different (not user-specified) port.
          logger.warning('We have an updater for ' + \
            repr(updater.configuration.network_location) + \
              'but not for ' + repr(network_locations))
          updater = None

    except:
      logger.exception('No updater or interposition for ' + repr(url))
      updater = None

    finally:
      if updater is None:
        logger.warning('No updater or interposition for ' + repr(url))

      return updater


  def remove(self, configuration):
    """
    <Purpose>
      Remove an Updater matching the given 'configuration', as well as its
      associated mirrors.

    <Arguments>
      'configuration' is the configuration object of the updater to be removed.

    <Exceptions>
      tuf.exceptions.InvalidConfigurationError:
        If there is anything wrong with the configuration for example invalid
        hostname, invalid port number etc, tuf.exceptions.InvalidConfigurationError is
        raised.

      tuf.exceptions.NotFoundError:
        If the updater with the given configuration does not exists,
        tuf.exceptions.NotFoundError exception is raised.

    <Side Effects>
      Removes the stored updater and the mirrors associated with that updater.
      Then tuf logs this information in a log file.

    <Returns>
      None
    """

    # Check if the given configuration is valid or not.
    if not isinstance(configuration, Configuration):
      raise tuf.exceptions.InvalidConfigurationError('Invalid configuration')

    # If the configuration is valid, get the repository mirrors associated with
    # it.
    repository_mirror_network_locations = \
      configuration.get_repository_mirror_hostnames()

    # Check if network location of the given configuration exists or not.
    if configuration.network_location not in self.__updaters:
      raise tuf.exceptions.NotFoundError('Network location not found')

    # Check if the associated mirrors exists or not.
    if not repository_mirror_network_locations.issubset(self.__repository_mirror_network_locations):
      raise tuf.exceptions.NotFoundError('Repository mirror does not exists')

    # Get the updater.
    updater = self.__updaters.get(configuration.network_location)

    # If everything works well, remove the stored Updater as well as its
    # associated repository mirror network locations.
    updater.cleanup()

    # Delete the updater from the list of updaters.
    del self.__updaters[configuration.network_location]

    # Remove the associated mirrors from the repository mirror set.
    self.__repository_mirror_network_locations.difference_update(repository_mirror_network_locations)

    # Log the message that the given updater is removed.
    logger.info('Updater removed for interposed ' + repr(configuration))
