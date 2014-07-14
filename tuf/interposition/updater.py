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

<Example Interpostion>

  To implement interpostion client only need to have two files -
  1. A python file which client will have to run in order to perform 
     interposition. For example - interposition.py.

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
     # the class UpdaterController.
     configurations = tuf.interposition.configure()

     url = 'http://example.com/path/to/document'
     # This is the standard way of opening and retrieving url in python.
     urllib.urlopen(url)
     urllib.urlretrieve(url)
     urllib2.urlopen(url)

     # Remove TUF interposition for previously read configurations. That is 
     # remove the updater object.
     # Deconfigure() takes only one argument i.e. configurations.
     # It calls remove(configuration) function which is in UpdaterController
     # class in updater.py.
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
                "mirror1": {
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
  # will start the interposition process. It generates a log file in the same 
  # directory which can be used for a review.

"""

import mimetypes
import os.path
import re
import shutil
import tempfile
import urllib
import urlparse


import tuf.client.updater
import tuf.conf


# We import them directly into our namespace so that there is no name conflict.
from configuration import Configuration, InvalidConfiguration
from utility import Logger, InterpositionException
#TODO: Remove utility because the Logger is at two places. 




################################ GLOBAL CLASSES ################################


#TODO: Put this class in the Exception file of TUF.
class URLMatchesNoPattern(InterpositionException):
  """URL matches no user-specified regular expression pattern."""
  pass





class Updater(object):
  """
  <Purpose>
    Provide a class that can download target files securely. It performs all
    those things which client/updator.py performs. But it performs it in the 
    background, transparent to the client.

  <Updater Methods>
    refresh(): 
      This method refresh top-level metadata. It calls the refresh() method of  
      client/updater. refresh() method of client/updater.py downloads, verifies,
      and loads metadata for the top-level roles in a specific order (i.e., 
      timestamp -> snapshot -> root -> targets). The expiration time for 
      downloaded metadata is also verified. 
    
    cleanup():
      It will clean up all the temporary directories which were made as a result
      of download. It then prints a message of deletion and also mentions the 
      name of the deleted directory. 
      
    download_target(target_filepath):
      It downloads the 'target' and verify it is trusted. This procedure happens 
      in the background, transparent to the client. This will only store the 
      file at 'destination_directory' if the downloaded file matches the 
      description of the file in the trusted metadata.     
    
    get_target_filepath(source_url):
      Given source->target map, this method will figure out what TUF should     
      download when a URL is given.   
   
    open(url, data):
      Open the URL url which can either be a string or a request object.        
      The file is opened in the binary read mode as a temporary file.  
    
    retrieve(url, filename, reporthook, data):
      retrieve() method first get the target file path by calling               
      get_target_filepath(url) which in tuf.interposition.updater and then      
      calls download_target() method for the above file path.   
    
    switch_context():
      There is an updater object for each network location that is interposed.  
      Context switching is required because there are multiple                  
      tuf.client.Updater() objects and each one depends on tuf.conf settings    
      that are shared.      
  """


  def __init__(self, configuration):
  """
  <Purpose>
    Constructor. Instantiating an updater object causes creation of a temporary
    directory. This temporary directory is used for the interposition updater.
    After that the updater of client module which performs the low-level 
    integration is called.

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

    # Instantiating an client/updater object causes all the configurations for 
    # the top-level roles to be read from disk, including the key and role 
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
      client/updater.
      refresh() method of client/updater.py downloads, verifies, and loads 
      metadata for the top-level roles in a specific order (i.e., timestamp -> 
      snapshot -> root -> targets)
      The expiration time for downloaded metadata is also verified.             
                                                                                     
      This refresh() method should be called by the client before any target     
      requests. Therefore to automate the process, it is called here.         
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
      It downloads the 'target' and verify it is trusted. This procedure 
      happens in the background, transparent to the client.
                                                                                      
      This will only store the file at 'destination_directory' if the downloaded
      file matches the description of the file in the trusted metadata. 

    <Arguments>
      target_filepath contains the path to the target to be downloaded.   

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
    # Targets metadata in order of trust, according to the currently trusted
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
    # All the targets that have changed are returns in a list. From this list, 
    # a request to download is made by calling 'download_target()'.    
    updated_targets = self.updater.updated_targets(targets, destination_directory)

    # The download_target() method in client/updater.py  performs the actual 
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
        raise URLMatchesNoPattern(source_url)

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
  
    <Returns>
  
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
      get_target_filepath(url) which in tuf.interposition.updater and then 
      calls download_target() method for the above file path.

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
      tuf.client.Updater() objects and each one depends on tuf.conf settings 
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
  I am a controller of Updaters; given a Configuration, I will build and
  store an Updater which you can get and use later.
  """

  def __init__(self):
    # A private map of Updaters (network_location: str -> updater: Updater)
    self.__updaters = {}

    # A private set of repository mirror hostnames
    self.__repository_mirror_hostnames = set()


  def __check_configuration_on_add(self, configuration):
    """
    If the given Configuration is invalid, I raise an exception.
    Otherwise, I return some information about the Configuration,
    such as repository mirror hostnames.
    """

    INVALID_REPOSITORY_MIRROR = "Invalid repository mirror {repository_mirror}!"

    # Updater has a "global" view of configurations, so it performs
    # additional checks after Configuration's own local checks.
    assert isinstance(configuration, Configuration)

    # Restrict each (incoming, outgoing) hostname pair to be unique across
    # configurations; this prevents interposition cycles, amongst other
    # things.
    # GOOD: A -> { A:X, A:Y, B, ... }, C -> { D }, ...
    # BAD: A -> { B }, B -> { C }, C -> { A }, ...
    assert configuration.hostname not in self.__updaters
    assert configuration.hostname not in self.__repository_mirror_hostnames

    # Check for redundancy in server repository mirrors.
    repository_mirror_hostnames = configuration.get_repository_mirror_hostnames()

    for mirror_hostname in repository_mirror_hostnames:
      try:
        # Restrict each hostname in every (incoming, outgoing) pair to be
        # unique across configurations; this prevents interposition cycles,
        # amongst other things.
        assert mirror_hostname not in self.__updaters
        assert mirror_hostname not in self.__repository_mirror_hostnames

      except:
        error_message = \
          INVALID_REPOSITORY_MIRROR.format(repository_mirror=mirror_hostname)
        Logger.exception(error_message)
        raise InvalidConfiguration(error_message)

    return repository_mirror_hostnames


  def add(self, configuration):
    """Add an Updater based on the given Configuration."""

    repository_mirror_hostnames = self.__check_configuration_on_add(configuration)
    
    # If all is well, build and store an Updater, and remember hostnames.
    Logger.info('Adding updater for interposed '+repr(configuration))
    self.__updaters[configuration.hostname] = Updater(configuration)
    self.__repository_mirror_hostnames.update(repository_mirror_hostnames)
  
  
  def refresh(self, configuration):
    """Refresh the top-level metadata of the given Configuration."""

    assert isinstance(configuration, Configuration)

    repository_mirror_hostnames = configuration.get_repository_mirror_hostnames()

    assert configuration.hostname in self.__updaters
    assert repository_mirror_hostnames.issubset(self.__repository_mirror_hostnames)

    # Get the updater and refresh its top-level metadata.  In the majority of
    # integrations, a software updater integrating TUF with interposition will
    # usually only require an initial refresh() (i.e., when configure() is
    # called).  A series of target file requests may then occur, which are all
    # referenced by the latest top-level metadata updated by configure().
    # Although interposition was designed to remain transparent, for software
    # updaters that require an explicit refresh of top-level metadata, this
    # method is provided.
    Logger.info('Refreshing top-level metadata for '+ repr(configuration))
    updater = self.__updaters.get(configuration.hostname)
    updater.refresh()


  def get(self, url):
    """Get an Updater, if any, for this URL.

    Assumptions:
      - @url is a string."""

    GENERIC_WARNING_MESSAGE = "No updater or interposition for url={url}"
    DIFFERENT_NETLOC_MESSAGE = "We have an updater for netloc={netloc1} but not for netlocs={netloc2}"
    HOSTNAME_FOUND_MESSAGE = "Found updater for interposed network location: {netloc}"
    HOSTNAME_NOT_FOUND_MESSAGE = "No updater for hostname={hostname}"

    updater = None

    try:
      parsed_url = urlparse.urlparse(url)
      hostname = parsed_url.hostname
      port = parsed_url.port or 80
      netloc = parsed_url.netloc
      network_location = "{hostname}:{port}".format(hostname=hostname, port=port)

      # Sometimes parsed_url.netloc does not have a port (e.g. 80),
      # so we do a double check.
      network_locations = set((netloc, network_location))

      updater = self.__updaters.get(hostname)

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
    """Remove an Updater matching the given Configuration."""

    UPDATER_REMOVED_MESSAGE = "Updater removed for interposed {configuration}."

    assert isinstance(configuration, Configuration)

    repository_mirror_hostnames = configuration.get_repository_mirror_hostnames()

    assert configuration.hostname in self.__updaters
    assert repository_mirror_hostnames.issubset(self.__repository_mirror_hostnames)

    # Get the updater.
    updater = self.__updaters.get(configuration.hostname)

    # If all is well, remove the stored Updater as well as its associated
    # repository mirror hostnames.
    updater.cleanup()
    del self.__updaters[configuration.hostname]
    self.__repository_mirror_hostnames.difference_update(repository_mirror_hostnames)

    Logger.info(UPDATER_REMOVED_MESSAGE.format(configuration=configuration))
