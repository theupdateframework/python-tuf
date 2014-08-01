#!/usr/bin/env python

"""
<Program Name>
  updater.py

<Author>
  Pankhuri Goyal <pankhurigoyal02@gmail.com>

<Started>
  June 2014.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Interposition is the high-level integration of TUF. 'updater.py' is used to
  perform high-level integration of TUF to the software updater. This means 
  that all the processes which are taking place in the low-level integration 
  will be done automatically. This layer of processes will be transparent to 
  the client.
  Updater.py have two classes named as Updater and UpdaterController.
  #TODO: Add more description to purpose.
  #TODO: Add Pros and Cons of using interposition.

<Example Integration with Interposition>

  To implement interpostion client only need to have-
  First, a client module which is modified to include interposition library and 
  code and second, a JSON configuration file is created, each of which is 
  explained below - 
  1. "interposition.py" is an example client updater module that is integrating
     TUF with interposition.

     # First import the main module called interposition which contains all 
     # the required directories and classes.
     import tuf.interposition              
    
     # urllib_tuf and urllib2_tuf are TUF's copy of urllib and urllib2
     from tuf.interposition import urllib_tuf as urllib
     from tuf.interposition import urllib2_tuf as urllib2
     
     # From tuf.interposition, configure() method is called.
     # configure() is within __init__.py
     # It takes 3 arguments, one of which is filename of a JSON file.
     # This JSON file contains a set of configurations. To make this file,
     # follow the second point below.
     # Ways to call this method are as follows :
     # First, configure() - By default, the configuration object is expected 
     # to be situated in the current working directory in the file with the 
     # name "tuf.interposition.json".
     # Second, configure(filename="/path/to/json")
     # Configure() returns a dictionary of configurations
     # Internally, configure() calls add(configuration) function which is in 
     # the tuf.interposition.updater.UpdaterController.
     configurations = tuf.interposition.configure()

     url = 'http://example.com/path/to/document'
     # This is the standard way of opening and retrieving url in python.
     urllib.urlopen(url)
     urllib.urlretrieve(url)
     urllib2.urlopen(url)

     # Remove TUF interposition for previously read configurations. That is 
     # remove the updater object.
     # Deconfigure() takes only one argument i.e. configurations.
     # It calls remove(configuration) function which is in 
     # tuf.interposition.updater.UpdaterController.
     tuf.interposition.deconfigure(configurations)


  2. The filename passed as a parameter in configure function is a JSON file. 
     It is called as configurations. It is a JSON object which tells 
     tuf.interposition which URLs to intercept, how to transform them (if 
     necessary), and where to forward them (possibly over SSL) for secure 
     responses via TUF. By default, the name of the file is 
     tuf.interposition.json which is as follows -
    
     # configurations are simply a JSON object which allows you to answer 
     # these questions -
     # - Which network location get intercepted?
     # - Given a network location, which TUF mirrors should we forward 
     #   requests to?
     # - Given a network location, which paths should be intercepted?
     # - Given a TUF mirror, how do we verify its SSL certificate?
     {
     # This is required root object.
       "configurations": {
       # Which network location should be intercepted?
       # Network locations may be specified as "hostname" or "hostname:port".
         "localhost": {
         # Where do we find the client copy of the TUF server metadata?
           "repository_directory": ".",
           # Where do we forward the requests to localhost?
             "repository_mirrors" : {
           gg     "mirror1": {
                # In this case, we forward them to http://localhost:8001
                  "url_prefix": "http://localhost:8001",
                  # You do not have to worry about these default parameters.
                  "metadata_path": "metadata",
                  "targets_path": "targets",
                  "confined_target_dirs": [ "" ]
             }
           }
         }
       }
     }

  # After making these two files on the client side, run interposition.py. This
  # will start the interposition process. It generates a log file named tuf.log
  # in the same directory, which can be used for a review.
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
import urllib
import urlparse
import logging

import tuf.client.updater
import tuf.conf
import tuf.log

# We import them directly into our namespace so that there is no name conflict.
from tuf.interposition.configuration import Configuration


Logger = logging.getLogger('tuf.interposition.updater')


class Updater(object):
  """
  <Purpose>
    Provide a class that can download target files securely. It performs all
    those things which client/updator.py performs. But it performs it in the 
    background, transparent to the client.

  <Updater Methods>
    refresh(): 
      This method refresh top-level metadata. It calls the refresh() method of  
      tuf.client.updater. refresh() method of tuf.client.updater downloads, 
      verifies, and loads metadata for the top-level roles in a specific order
      (i.e., timestamp -> snapshot -> root -> targets). The expiration time for 
      downloaded metadata is also verified. 
    
    cleanup():
      It will clean up all the temporary directories which were made as a result
      of download. It then prints a message of deletion and also mentions the 
      name of the deleted directory. 
      
    download_target(target_filepath):
      It downloads the target from the target_filepath. It also downloads the 
      metadata of the updated targets.
    
    get_target_filepath(source_url):
      source_url is the url of the file to be updated. This method will find the
      updated target for this file.
   
    open(url, data):
      Open the URL url which can either be a string or a request object.        
      The file is opened in the binary read mode as a temporary file.  
    
    retrieve(url, filename, reporthook, data):
      retrieve() method first get the target file path by calling               
      get_target_filepath(url) which in tuf.interposition.updater.Updater and 
      then calls download_target() method for the above file path.   
    
    switch_context():
      There is an updater object for each network location that is interposed.  
      Context switching is required because there are multiple                  
      tuf.client.updater objects and each one depends on tuf.conf settings    
      that are shared.      
  """


  def __init__(self, configuration):
    """
    <Purpose>
      Constructor. Instantiating an updater object causes creation of a 
      temporary directory. This temporary directory is used for the 
      tuf.interposition.updater.Updater. After that the tuf.client.updater module which 
      performs the low-level integration is called.

    <Arguments>
      configuration:
      A dictionary holding information like the following -
      - Which network location get intercepted?                                
      - Given a network location, which TUF mirrors should we forward requests 
        to?                                                           
      - Given a network location, which paths should be intercepted?           
      - Given a TUF mirror, how do we verify its SSL certificate? 
      
      This dictionary holds repository mirror information, conformant to       
      'tuf.formats.MIRRORDICT_SCHEMA'. Information such as the directory 
      containing the metadata and target files, the server's URL prefix, and 
      the target content directories the client should be confined to.                                                  
      
      repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                              'metadata_path': 'metadata',          
                              'targets_path': 'targets',            
                              'confined_target_dirs': ['']}} 

    <Exceptions>
      #TODO: Exceptions

    <Side Effects>
      The metadata files (e.g., 'root.json', 'targets.json') for the top-level 
      roles are read from disk and stored in dictionaries. 
 
    <Returns>
      None.
    """

    CREATED_TEMPDIR_MESSAGE = "Created temporary directory at {tempdir}"

    self.configuration = configuration
    # A temporary directory used for this updater over runtime.
    self.tempdir = tempfile.mkdtemp()
    Logger.debug(CREATED_TEMPDIR_MESSAGE.format(tempdir=self.tempdir))

    # Switching context before instantiating updater because updater depends 
    # on some module (tuf.conf) variables.
    self.switch_context()

    # Instantiating an tuf.client.updater object causes all the configurations 
    # for the top-level roles to be read from disk, including the key and role 
    # information for the delegated targets of 'targets'. The actual metadata 
    # for delegated roles is not loaded in __init__.  The metadata for these 
    # delegated roles, including nested delegated roles, are loaded, updated, 
    # and saved to the 'self.metadata' store by the target methods, like 
    # all_targets() and targets_of_role().     
    self.updater = tuf.client.updater.Updater(self.configuration.hostname,
                                              self.configuration.repository_mirrors)
    
    # Update the client's top-level metadata.  The download_target() method does
    # not automatically refresh top-level prior to retrieving target files and
    # their associated Targets metadata, so update the top-level metadata here.
    Logger.info('Refreshing top-level metadata for interposed '+repr(configuration))
    self.updater.refresh()
  
 
  def refresh(self):
    """
    <Purpose>
      This method refresh top-level metadata. It calls the refresh() method of 
      tuf.client.updater.
      refresh() method of tuf.client.updater.py downloads, verifies, and loads 
      metadata for the top-level roles in a specific order (i.e., timestamp -> 
      snapshot -> root -> targets)
      The expiration time for downloaded metadata is also verified.             
                                                                                     
      This refresh() method should be called by the client before any target     
      requests. Therefore to automate the process, it is called here.

    <Arguments>
      None

    <Exceptions>
      tuf.NoWorkingMirrorError:                                                 
        If the metadata for any of the top-level roles cannot be updated.       
                                                                                     
      tuf.ExpiredMetadataError:                                                 
        if any metadata has expired.

    <Side Effects>
      Updates the metadata files of the top-level roles with the latest 
      information

    <Returns>
      None
    """

    self.updater.refresh()


  def cleanup(self):
    """
    <Purpose>
      It will clean up all the temporary directories which were made as a 
      result of download. It then prints a message of deletion and also 
      mentions the name of the deleted directory.   
    """

    DELETED_TEMPDIR_MESSAGE = "Deleted temporary directory at {tempdir}"
    shutil.rmtree(self.tempdir)
    Logger.debug(DELETED_TEMPDIR_MESSAGE.format(tempdir=self.tempdir))


  def download_target(self, target_filepath):
    """
    <Purpose>
      It downloads the target files from the path provided named 
      target_filepath. 
      Everything here is performed in a temporary directory. 
      It identifies the target information for target_filepath by calling
      target() method of tuf.client.updater. This method also downloads the 
      metadata of the updated targets. By doing this, the client retrieves the 
      target information for the targets they want to update. When client 
      retrieves all the information, the updated_targets() method of 
      tuf.client.updater is called to determine the list of targets which have 
      been changed from those saved locally on disk. 
      tuf.client.upater.download_target() downloads all the targets in the list
      in the destination directory which is our temporary directory.
                                                                                      
      This will only store the file at 'destination_directory' if the downloaded
      file matches the description of the file in the trusted metadata. 

    <Arguments>
      'target_filepath' is the target's relative path on the remote repository.   

    <Exceptions>
      #TODO: Exceptions

    <Side Effects>
      A target file is saved to the local system.

    <Returns>
      It returns destination_directory where the target is been stored and 
      filename of the target file been stored in the directory.
    
    """

    # Download file into a temporary directory shared over runtime
    destination_directory = self.tempdir
    
    # A new path is generated by joining the destination directory path that is 
    # our temporary directory path and target file path.
    # Note: join() discards 'destination_directory' if 'target_filepath'
    # contains a leading path separator (i.e., is treated as an absolute path).
    filename = os.path.join(destination_directory, target_filepath.lstrip(os.sep))
    
    # Switch TUF context. Switching context before instantiating updater 
    # because updater depends on some module (tuf.conf) variables. 
    self.switch_context()
    
    # Locate the fileinfo of 'target_filepath'.  updater.target() searches
    # targets metadata in order of trust, according to the currently trusted
    # snapshot.  To prevent consecutive target file requests from referring to
    # different snapshots, top-level metadata is not automatically refreshed.
    # It returns the target information for a specific file identified by its 
    # file path.  This target method also downloads the metadata of updated 
    # targets. 
    targets = [self.updater.target(target_filepath)]

    # TODO: targets are always updated if destination directory is new, right?
    # After the client has retrieved the target information for those targets   
    # they are interested in updating, updated_targets() method is called to 
    # determine which targets have changed from those saved locally on disk. 
    # All the targets that have changed are returned in a list. From this list, 
    # a request to download is made by calling 'download_target()'.    
    updated_targets = self.updater.updated_targets(targets, destination_directory)

    # The download_target() method in tuf.client.updater performs the actual 
    # download of the specified target. The file is saved to the 
    # 'destination_directory' argument. 
    for updated_target in updated_targets:
      self.updater.download_target(updated_target, destination_directory)

    return destination_directory, filename


  # TODO: decide prudent course of action in case of failure
  def get_target_filepath(self, source_url):
    """
    <Purpose>
      Given source->target map, this method will figure out what TUF should 
      download when a URL is given.
    
    <Arguments>
      source_url is passed while calling the function. This is the url which 
      we want to retrieve. For this url, get_target_filepath() method is called.

    <Returns>
      It returns target_filepath. This is the target which TUF should download.
   
   """

    WARNING_MESSAGE = "Possibly invalid target_paths for " + \
        "{network_location}! No TUF interposition for {url}"

    parsed_source_url = urlparse.urlparse(source_url)
    target_filepath = None

    try:
      # Does this source URL match any regular expression which tells us
      # how to map the source URL to a target URL understood by TUF?
      for target_path in self.configuration.target_paths:

        #TODO: What these two lines are doing?
        # target_path: { "regex_with_groups", "target_with_group_captures" }
        # e.g. { ".*(/some/directory)/$", "{0}/index.html" }
        source_path_pattern, target_path_pattern = target_path.items()[0]
        source_path_match = re.match(source_path_pattern, parsed_source_url.path)

        # TODO: A failure in string formatting is *critical*.
        if source_path_match is not None:
          target_filepath = target_path_pattern.format(*source_path_match.groups())

          # If there is more than one regular expression which
          # matches source_url, we resolve ambiguity by order of
          # appearance.
          break

      # If source_url does not match any regular expression...
      if target_filepath is None:
        # ...then we raise a predictable exception.
        raise tuf.URLMatchesNoPattern(source_url)

    except:
      Logger.exception(WARNING_MESSAGE.format(
        network_location=self.configuration.network_location, url=source_url))
      raise

    else:
      return target_filepath


  # TODO: distinguish between urllib and urllib2 contracts
  def open(self, url, data=None):
    """
    <Purpose>
      Open the URL url which can either be a string or a request object. 
      The file is opened in the binary read mode as a temporary file.
  
    <Arguments>
      url, the one which is to be opened.

      data must be a bytes object specifying additional data to be sent to the  
      server or None, if no such data needed. 

    """
    filename, headers = self.retrieve(url, data=data)

    # TUF should always open files in binary mode and remain transparent to the
    # software updater.  Opening files in text mode slightly alters the
    # end-of-line characters and prevents binary files from properly loading on
    # Windows.
    # http://docs.python.org/2/tutorial/inputoutput.html#reading-and-writing-files
    # TODO: like tempfile, ensure file is deleted when closed?
    # open() in the line below is a predefined function in python.
    temporary_file = open(filename, 'rb')

    #TODO: addinfourl is not in urllib package anymore. We need to check if
    # other option for this is working or not.
    # Extend temporary_file with info(), getcode(), geturl()
    # http://docs.python.org/2/library/urllib.html#urllib.urlopen
    # addinfourl() works as a context manager.
    response = urllib.addinfourl(temporary_file, headers, url, code=200)

    return response


  # TODO: distinguish between urllib and urllib2 contracts
  def retrieve(self, url, filename=None, reporthook=None, data=None):
    """
    <Purpose>
      retrieve() method first get the target file path by calling 
      get_target_filepath(url) which is in tuf.interposition.updater.Updater 
      and then calls download_target() method for the above file path.

    <Arguments>
      url, which is to be retrieved. 

      filename, if the is given then everywhere the given filename is used. 
      If the filename is none, then temporary file is used.
                     
    <Returns>
      It returns the filename and the headers of the file just retrieved.

    """
    INTERPOSITION_MESSAGE = "Interposing for {url}"

    Logger.info(INTERPOSITION_MESSAGE.format(url=url))

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
    temporary_directory, temporary_filename = self.download_target(target_filepath)

    if filename is None:
        # If no filename is given, use the temporary file.
        filename = temporary_filename
    else:
        # Otherwise, copy TUF-downloaded file in its own directory
        # to the location user specified.
        shutil.copy2(temporary_filename, filename)

    return filename, headers


  # TODO: thread-safety, perhaps with a context manager
  def switch_context(self):
    """
    <Purpose>
      There is an updater object for each network location that is interposed. 
      Context switching is required because there are multiple 
      tuf.client.updater objects and each one depends on tuf.conf settings 
      that are shared.

      For this, two settings are required -
      1. Setting local repository directory
      2. Setting the local SSL certificate PEM file
    """
    # Set the local repository directory containing the metadata files.
    tuf.conf.repository_directory = self.configuration.repository_directory

    # Set the local SSL certificates PEM file.
    tuf.conf.ssl_certificates = self.configuration.ssl_certificates





class UpdaterController(object):
  """
  <Purpose>
    tuf.interposition.updater.UpdaterController is a controller of the Updaters.
    Given a configuration, it can build and store an Updater, which can be 
    used later with the help of get() method.

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
      tuf.interposition.updater.Updater in the __updater map and by adding repository
      mirror's network location in the empty set initialized when the object of 
      tuf.interposition.updater.UpdaterController is created.

    get(url):
    refresh(configuration):
    remove(configuration):

  """

  def __init__(self):
    """
    <Purpose>
      To initalize a private map of updaters and a private set of repository
      mirror network locations (hostname:port) once the object of 
      tuf.interposition.updater.UpdaterController is created. This empty map and set is 
      later used to add, get and remove updaters and their mirrors.

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
      tuf.InvalidConfiguration:
        If the configuration is invalid. For example - wrong hostname, invalid
        port number, wrong mirror format.

      tuf.FormatError:
        If the network_location is not unique or configuration.network_location
        is same as repository_mirror_network_locations.

    <Side Effects>
      It logs the error message.
   
    <Returns>
      'repository_mirror_network_locations'
        In order to prove that everything worked well, a part of configuration
        is returned which is the list of repository mirrors.
    """

    INVALID_REPOSITORY_MIRROR = "Invalid repository mirror {repository_mirror}!"

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
      raise tuf.InvalidConfiguration("Invalid Configuration")

    # Restrict each (incoming, outgoing) network location pair to be unique across
    # configurations; this prevents interposition cycles, amongst other
    # things.
    # GOOD: A -> { A:X, A:Y, B, ... }, C -> { D }, ...
    # BAD: A -> { B }, B -> { C }, C -> { A }, ...
    if configuration.network_location in self.__updaters:
      raise tuf.FormatError("Updater with "+repr(configuration.network_location)+" Already Exists as an updater")
    if configuration.network_location in self.__repository_mirror_network_locations:
      raise tuf.FormatError("Updater with "+repr(configuration.network_location)+" Already Exists as a mirror")

    # Check for redundancy in server repository mirrors.
    repository_mirror_network_locations = configuration.get_repository_mirror_hostnames()

    for mirror_network_location in repository_mirror_network_locations:
      try:
        # Restrict each network location in every (incoming, outgoing) pair to be
        # unique across configurations; this prevents interposition cycles,
        # amongst other things.
        if mirror_network_location in self.__updaters:
          raise tuf.FormatError("Mirror with "+repr(mirror_network_location)+" Already Exists as an updater")
        if mirror_network_location in self.__repository_mirror_network_locations:
          raise tuf.FormatError("Mirror with "+repr(mirror_network_location)+" Already Exists as a mirror")

      except (tuf.FormatError) as e:
        error_message = \
          INVALID_REPOSITORY_MIRROR.format(repository_mirror=mirror_network_location)
        Logger.exception(error_message)
        raise

    return repository_mirror_network_locations


  def add(self, configuration):
    """
    <Purpose>
      Add an Updater based on the given Configuration. Tuf keeps the track of
      the updaters so that it can be fetched for later use.
    
    <Arguments>
      'configuration' is an object and on the basis of this configuration, an
      updater will be added.

    <Exceptions>
      tuf.FormatError
        This exception is raised if the network location which tuf is trying to 
        add is not unique.
    
    <Side Effects>
      The object of tuf.interposition.updater.Updater is added in the list of updaters.
      Also, the mirrors of this updater are added into a 
      repository_mirror_network_locations are added.

    <Returns>
      None
    """

    repository_mirror_network_locations = self.__check_configuration_on_add(configuration)
    
    # If all is well, build and store an Updater, and remember network locations.
    Logger.info('Adding updater for interposed '+repr(configuration))
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
      tuf.InvalidConfiguration:
        If there is anything wrong with the Format of the configuration, this 
        exception is raised.

      tuf.NotFound:
        If the updater to be refreshed is not found in the list of updaters or 
        mirrors, then tuf.NotFound exception is raised.
      
      tuf.NoWorkingMirrorError:
        If the metadata for any of the top-level roles cannot be updated.

      tuf.ExpiredMetadataError:
        If any metadata has expired.

    <Side Effects>
      It refreshes the updater and indicate this in the log file.

    <Returns>
      None
    """
    
    # Check if the configuration is valid else raise an exception.
    if not isinstance(configuration, Configuration):
      raise tuf.InvalidConfiguration("Invalid Configuration")

    # Get the repository mirrors of the given configuration.
    repository_mirror_network_locations = configuration.get_repository_mirror_hostnames()

    # Check if the configuration.network_location is available in the updater or mirror
    # list.
    if not configuration.network_location in self.__updaters:
      raise tuf.NotFound("Network Location Not Found")
    if not repository_mirror_network_locations.issubset(self.__repository_mirror_network_locations):
      raise tuf.NotFound("Network Location Not Found")

    # Get the updater and refresh its top-level metadata.  In the majority of
    # integrations, a software updater integrating TUF with interposition will
    # usually only require an initial refresh() (i.e., when configure() is
    # called).  A series of target file requests may then occur, which are all
    # referenced by the latest top-level metadata updated by configure().
    # Although interposition was designed to remain transparent, for software
    # updaters that require an explicit refresh of top-level metadata, this
    # method is provided.
    Logger.info('Refreshing top-level metadata for '+ repr(configuration))
    
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
      url, for which tuf is trying to get an updater. Assumption that url is a
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

    GENERIC_WARNING_MESSAGE = "No updater or interposition for url={url}"
    DIFFERENT_NETLOC_MESSAGE = "We have an updater for netloc={netloc1} but not for netlocs={netloc2}"
    HOSTNAME_FOUND_MESSAGE = "Found updater for interposed network location: {netloc}"
    HOSTNAME_NOT_FOUND_MESSAGE = "No updater for hostname={hostname}"

    updater = None

    try:
      # Parse the given url to access individual parts of it.
      parsed_url = urlparse.urlparse(url)
      hostname = parsed_url.hostname
      port = parsed_url.port or 80
      netloc = parsed_url.netloc

      # Combine the hostname and port number and assign it to network_location.
      # The combination of hostname and port is used to identify an updater.
      network_location = "{hostname}:{port}".format(hostname=hostname, port=port)

      # There can be a case when parsed_url.netloc does not have a port (e.g. 
      # 80). To avoid errors because of this case, tuf.interposition again set
      # the parameters.
      network_locations = set((netloc, network_location))

      updater = self.__updaters.get(network_location)

      if updater is None:
        Logger.warn(HOSTNAME_NOT_FOUND_MESSAGE.format(hostname=hostname))

      else:

        # Ensure that the updater is meant for this (hostname, port).
        if updater.configuration.network_location in network_locations:
          Logger.info(HOSTNAME_FOUND_MESSAGE.format(netloc=network_location))
          # Raises an exception in case we do not recognize how to
          # transform this URL for TUF. In that case, there will be no
          # updater for this URL.
          target_filepath = updater.get_target_filepath(url)

        else:
          # Same hostname, but different (not user-specified) port.
          Logger.warn(DIFFERENT_NETLOC_MESSAGE.format(
            netloc1=updater.configuration.network_location, netloc2=network_locations))
          updater = None

    except:
      Logger.exception(GENERIC_WARNING_MESSAGE.format(url=url))
      updater = None

    finally:
      if updater is None:
        Logger.warn(GENERIC_WARNING_MESSAGE.format(url=url))

      return updater


  def remove(self, configuration):
    """
    <Purpose>
      Remove an Updater matching the given Configuration as well as its 
      associated mirrors.
    
    <Arguments>
      'configuration' is the configuration object of the updater to be removed.

    <Exceptions>
      tuf.InvalidConfiguration:
        If there is anything wrong with the configuration for example invalid 
        hostname, invalid port number etc, tuf.InvalidConfiguration is raised.

      tuf.NotFound:
        If the updater with the given configuration does not exists, 
        tuf.NotFound exception is raised.

    <Side Effects>
      Removes the stored updater and the mirrors associated with that updater.
      Then tuf logs this information in a log file.

    <Returns>
      None
    """

    UPDATER_REMOVED_MESSAGE = "Updater removed for interposed {configuration}."

    # Check if the given configuration is valid or not.
    if not isinstance(configuration, Configuration):
      raise tuf.InvalidConfiguration('Invalid Configuration')
    
    # If the configuration is valid, get the repository mirrors associated with 
    # it.
    repository_mirror_network_locations = configuration.get_repository_mirror_hostnames()

    # Check if network location of the given configuration exists or not.
    if configuration.network_location not in self.__updaters:
      raise tuf.NotFound('Network Location Not Found')

    # Check if the associated mirrors exists or not.
    if not repository_mirror_network_locations.issubset(self.__repository_mirror_network_locations):
      raise tuf.NotFound('Repository Mirror Does Not Exists')

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
    Logger.info(UPDATER_REMOVED_MESSAGE.format(configuration=configuration))
