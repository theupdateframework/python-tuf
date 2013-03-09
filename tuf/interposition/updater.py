import mimetypes
import os.path
import re
import shutil
import urllib
import urlparse


import tuf.client.updater
import tuf.conf


# We import them directly into our namespace so that there is no name conflict.
from configuration import Configuration, InvalidConfiguration
from utility import Logger, InterpositionException





################################ GLOBAL CLASSES ################################





class URLMatchesNoPattern(InterpositionException):
  """URL matches no user-specified regular expression pattern."""
  pass





class Updater(object):
  """I am an Updater model."""


  def __init__(self, configuration):
    self.configuration = configuration

    # must switch context before instantiating updater
    # because updater depends on some module (tuf.conf) variables
    self.switch_context()
    self.updater = tuf.client.updater.Updater(self.configuration.hostname,
                                              self.configuration.repository_mirrors)


  def download_target(self, target_filepath):
    """Downloads target with TUF as a side effect."""

    # download file into a temporary directory shared over runtime
    destination_directory = self.configuration.tempdir
    filename = os.path.join(destination_directory, target_filepath)

    self.switch_context()   # switch TUF context
    self.updater.refresh()  # update TUF client repository metadata

    # then, update target at filepath
    targets = [self.updater.target(target_filepath)]

    # TODO: targets are always updated if destination directory is new, right?
    updated_targets = self.updater.updated_targets(targets, destination_directory)

    for updated_target in updated_targets:
      self.updater.download_target(updated_target, destination_directory)

    return destination_directory, filename


  # TODO: decide prudent course of action in case of failure
  def get_target_filepath(self, source_url):
    """Given source->target map, figure out what TUF *should* download given a
    URL."""

    WARNING_MESSAGE = "Possibly invalid target_paths for " + \
        "{network_location}! No TUF interposition for {url}"

    parsed_source_url = urlparse.urlparse(source_url)
    target_filepath = None

    try:
      # Does this source URL match any regular expression which tells us
      # how to map the source URL to a target URL understood by TUF?
      for target_path in self.configuration.target_paths:

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
      Logger.warn(WARNING_MESSAGE.format(
        network_location=self.configuration.network_location, url=source_url))
      raise

    else:
      # TUF assumes that target_filepath does not begin with a '/'.
      target_filepath = target_filepath.lstrip('/')
      return target_filepath


  # TODO: distinguish between urllib and urllib2 contracts
  def open(self, url, data=None):
    filename, headers = self.retrieve(url, data=data)

    # TODO: like tempfile, ensure file is deleted when closed?
    temporary_file = open(filename)

    # extend temporary_file with info(), getcode(), geturl()
    # http://docs.python.org/2/library/urllib.html#urllib.urlopen
    response = urllib.addinfourl(temporary_file, headers, url, code=200)

    return response


  # TODO: distinguish between urllib and urllib2 contracts
  def retrieve(self, url, filename=None, reporthook=None, data=None):
    # TODO: set valid headers
    content_type, content_encoding = mimetypes.guess_type(url)
    headers = {"content-type": content_type}

    target_filepath = self.get_target_filepath(url)

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


  def __check_configuration(self, configuration):
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

    # Parse TUF server repository mirrors.
    repository_mirrors = configuration.repository_mirrors
    repository_mirror_hostnames = set()

    for repository_mirror in repository_mirrors:
      mirror_configuration = repository_mirrors[repository_mirror]

      try:
        url_prefix = mirror_configuration["url_prefix"]
        parsed_url = urlparse.urlparse(url_prefix)
        mirror_hostname = parsed_url.hostname

        # Restrict each (incoming, outgoing) hostname pair to be unique
        # across configurations; this prevents interposition cycles,
        # amongst other things.
        assert mirror_hostname not in self.__updaters
        assert mirror_hostname not in self.__repository_mirror_hostnames

        # Remember this mirror's hostname for the next network_location.
        repository_mirror_hostnames.add(mirror_hostname)

      except:
        error_message = \
          INVALID_REPOSITORY_MIRROR.format(repository_mirror=repository_mirror)
        Logger.error(error_message)
        raise InvalidConfiguration(error_message)

    return repository_mirror_hostnames


  def add(self, configuration):
    """Add an Updater based on the given Configuration."""

    repository_mirror_hostnames = self.__check_configuration(configuration)

    # If all is well, build and store an Updater, and remember hostnames.
    self.__updaters[configuration.hostname] = Updater(configuration)
    self.__repository_mirror_hostnames.update(repository_mirror_hostnames)


  def get(self, url):
    """Get an Updater, if any, for this URL."""

    WARNING_MESSAGE = "No updater and, hence, TUF interposition for {url}!"

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

      # Ensure that the updater is meant for this (hostname, port).
      if updater is not None:

          if updater.configuration.network_location in network_locations:
              # Raises an exception in case we do not recognize how to
              # transform this URL for TUF. In that case, there will be no
              # updater for this URL.
              target_filepath = updater.get_target_filepath(url)

          else:
              # Same hostname, but different (not user-specified) port.
              updater = None

    except:
        Logger.warn(WARNING_MESSAGE.format(url=url))
        updater = None

    finally:
        return updater
