"""
<Program Name>
  configuration.py

<Author>
  Trishank Kuppusamy
  Pankhuri Goyal <pankhurigoyal02@gmail.com>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>

<Copyright>
  See LICENSE for licensing information.

<Purpose>

"""

# Help with Python 3 compatibility where the print statement is a function, an  
# implicit relative import is invalid, and the '/' operator performs true       
# division. Example:  print 'hello world' raises a 'SyntaxError' exception.     
from __future__ import print_function                                           
from __future__ import absolute_import                                          
from __future__ import division                                                 
from __future__ import unicode_literals         

import os.path
import logging

import tuf.log
import six

logger = logging.getLogger('tuf.interposition.configuration')


class Configuration(object):
  """
  <Purpose>
    Holds TUF interposition configuration information about a network
    location which is important to an updater for that network location.
  """

  def __init__(self, hostname, port, repository_directory, repository_mirrors,
               target_paths, ssl_certificates):

    """
    <Purpose>
      Constructor assumes that its parameters are valid.

    <Arguments>
      hostname:

      port:

      repository_directory:

      repository_mirrors:

      target_paths:

      ssl_certificates:

    <Exceptions>

    <Side Effects>

    <Returns>
    """

    self.hostname = hostname
    self.port = port
    self.network_location = \
      "{hostname}:{port}".format( hostname = hostname, port = port )
    self.repository_directory = repository_directory
    self.repository_mirrors = repository_mirrors
    self.target_paths = target_paths
    self.ssl_certificates = ssl_certificates


  def __repr__(self):
    MESSAGE = "network location: {network_location}"
    return MESSAGE.format(network_location=self.network_location)


  def get_repository_mirror_hostnames(self):
    """
    <Purpose>
      Get a set of hostnames of every repository mirror of this configuration.

    <Arguments>
      None.

    <Exceptions>

    <Side Effects>

    <Returns>
    """

    # Parse TUF server repository mirrors.
    repository_mirrors = self.repository_mirrors
    repository_mirror_hostnames = set()

    for repository_mirror in repository_mirrors:
      mirror_configuration = repository_mirrors[repository_mirror]
      
      url_prefix = mirror_configuration["url_prefix"]
      parsed_url = six.moves.urllib.parse.urlparse(url_prefix)
      mirror_hostname = parsed_url.hostname
      mirror_port = parsed_url.port
      mirror_network_location = \
        "{hostname}:{port}".format(hostname=mirror_hostname, port = mirror_port)
      repository_mirror_hostnames.add(mirror_network_location)

    return repository_mirror_hostnames





class ConfigurationParser(object):
  """
  <Purpose>
    Parses TUF interposition configuration information about a network
    location, stored as a JSON object, and returns it as a Configuration.
  """


  def __init__(self, network_location, configuration,
               parent_repository_directory=None,
               parent_ssl_certificates_directory=None):
    """
    <Purpose>

    <Arguments>
      network_location:

      configuration:

      parent_repository_directory:

      parent_ssl_certificates_directory:

    <Exceptions>

    <Side Effects>

    <Returns>
      None.
    """
    
    self.network_location = network_location
    self.configuration = configuration
    self.parent_repository_directory = parent_repository_directory
    self.parent_ssl_certificates_directory = parent_ssl_certificates_directory


  def get_network_location(self):
    """
    <Purpose>
      Check network location.

    <Arguments>
      None.

    <Exceptions>

    <Side Effects>

    <Returns>

    """

    INVALID_NETWORK_LOCATION = "Invalid network location {network_location}!"

    network_location_tokens = self.network_location.split(':', 1)
    hostname = network_location_tokens[0]
    port = 80

    if len(network_location_tokens) > 1:
      port = int(network_location_tokens[1], 10)
      if port <= 0 or port >= 2**16:
        raise tuf.ssl_commons.exceptions.InvalidConfigurationError(INVALID_NETWORK_LOCATION.format(
          network_location=self.network_location))

    return hostname, port


  def get_repository_directory(self):
    """
    <Purpose>
      Locate TUF client metadata repository.

    <Arguments>
      None.

    <Exceptions>

    <Side Effects>

    <Returns>

    """

    INVALID_PARENT_REPOSITORY_DIRECTORY = \
        "Invalid parent_repository_directory for {network_location}!"

    repository_directory = self.configuration["repository_directory"]

    if self.parent_repository_directory is not None:
      parent_repository_directory = \
        os.path.abspath(self.parent_repository_directory)

      if os.path.isdir(parent_repository_directory):
        repository_directory = os.path.join(parent_repository_directory,
                                            repository_directory)
        # TODO: assert os.path.isdir(repository_directory)

      else:
        raise tuf.ssl_commons.exceptions.InvalidConfigurationError(INVALID_PARENT_REPOSITORY_DIRECTORY.format(
          network_location=self.network_location))

    return repository_directory


  def get_ssl_certificates(self):
    """
    <Purpose>
      Get any PEM certificate bundle.

    <Arguments>
      None.

    <Exceptions>

    <Side Effects>

    <Returns>

    """

    INVALID_SSL_CERTIFICATES = \
      "Invalid ssl_certificates for {network_location}!"
    INVALID_PARENT_SSL_CERTIFICATES_DIRECTORY = \
      "Invalid parent_ssl_certificates_directory for {network_location}!"

    ssl_certificates = self.configuration.get("ssl_certificates")

    if ssl_certificates is not None:
      if self.parent_ssl_certificates_directory is not None:
        parent_ssl_certificates_directory = \
          os.path.abspath(self.parent_ssl_certificates_directory)

        if os.path.isdir(parent_ssl_certificates_directory):
          ssl_certificates = os.path.join(parent_ssl_certificates_directory,
                                          ssl_certificates)

          if not os.path.isfile(ssl_certificates):
            raise tuf.ssl_commons.exceptions.InvalidConfigurationError(INVALID_SSL_CERTIFICATES.format(
                network_location=self.network_location))

        else:
          raise tuf.ssl_commons.exceptions.InvalidConfigurationError(
            INVALID_PARENT_SSL_CERTIFICATES_DIRECTORY.format(
              network_location=self.network_location))

    return ssl_certificates


  def get_repository_mirrors(self, hostname, port, ssl_certificates):
    """
    <Purpose>
      Parse TUF server repository mirrors.
    
    <Arguments>
      hostname:

      port:

      ssl_certificates:
    
    <Exceptions>

    <Side Effects>

    <Returns>

    """

    INVALID_REPOSITORY_MIRROR = "Invalid repository mirror {repository_mirror}!"

    repository_mirrors = self.configuration["repository_mirrors"]
    repository_mirror_network_locations = set()

    for repository_mirror in repository_mirrors:
      mirror_configuration = repository_mirrors[repository_mirror]

      try:
        url_prefix = mirror_configuration["url_prefix"]
        parsed_url = six.moves.urllib.parse.urlparse(url_prefix)
        mirror_hostname = parsed_url.hostname
        mirror_port = parsed_url.port or 80
        mirror_scheme = parsed_url.scheme
        mirror_netloc = "{hostname}:{port}".format(hostname = mirror_hostname,
                                                   port = mirror_port)

        # TODO: warn is ssl_certificates is specified,
        # but there is no mirror_scheme == "https"
        if mirror_scheme == "https":
            assert os.path.isfile(ssl_certificates)

        # No single-edge cycle in interposition.
        # GOOD: A -> { A:XYZ, ... }
        # BAD: A -> { A, ... }
        assert not (mirror_hostname == hostname and mirror_port == port)

        # Unique network location over repository mirrors.
        # GOOD: A -> { A:X, A:Y, ... }
        # BAD: A -> { A:X, A:X, ... }
        assert mirror_netloc not in repository_mirror_network_locations

        # Remember this mirror's network location to check the rest of the mirrors.
        repository_mirror_network_locations.add(mirror_netloc)

      except:
        error_message = \
          INVALID_REPOSITORY_MIRROR.format(repository_mirror=repository_mirror)
        logger.exception(error_message)
        raise tuf.ssl_commons.exceptions.InvalidConfigurationError(error_message)

    return repository_mirrors


  def get_target_paths(self):
    """
    <Purpose>
      Within a network_location, we match URLs with this list of regular
      expressions, which tell us to map from a source URL to a target URL.
      If there are multiple regular expressions which match a source URL,
      the order of appearance will be used to resolve ambiguity.
    
    <Arguments> 
      None.

    <Exceptions>

    <Side Effects>

    <Returns>

    """

    INVALID_TARGET_PATH = "Invalid target path in {network_location}!"

    # An "identity" capture from source URL to target URL.
    WILD_TARGET_PATH = { "(.*)": "{0}" }

    target_paths = self.configuration.get("target_paths", [WILD_TARGET_PATH])

    # target_paths: [ target_path, ... ]
    assert isinstance(target_paths, list)

    for target_path in target_paths:
      try:
        # target_path: { "regex_with_groups", "target_with_group_captures" }
        # e.g. { ".*(/some/directory)/$", "{0}/index.html" }
        assert isinstance(target_path, dict)
        assert len(target_path) == 1

      except:
        error_message = \
          INVALID_TARGET_PATH.format(network_location=self.network_location)
        logger.exception(error_message)
        raise tuf.ssl_commons.exceptions.InvalidConfigurationError(error_message)

    return target_paths


  # TODO: more input sanity checks?
  def parse(self):
    """
    <Purpose>
      Parse, check, and get the required configuration parameters.

    <Arguments>
      None.

    <Exceptions>

    <Side Effects>

    <Returns>

    """

    hostname, port = self.get_network_location()
    ssl_certificates = self.get_ssl_certificates()
    repository_directory = self.get_repository_directory()
    target_paths = self.get_target_paths()

    repository_mirrors = \
      self.get_repository_mirrors(hostname, port, ssl_certificates)

    # If everything passes, we return a Configuration.
    return Configuration(hostname, port, repository_directory,
                         repository_mirrors, target_paths, ssl_certificates)
