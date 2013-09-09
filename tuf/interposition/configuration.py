import os.path
import types
import urlparse


# We import them directly into our namespace so that there is no name conflict.
from utility import Logger, InterpositionException





################################ GLOBAL CLASSES ################################





class InvalidConfiguration(InterpositionException):
  """User configuration is invalid."""
  pass





class Configuration(object):
  """Holds TUF interposition configuration information about a network
  location which is important to an updater for that network location."""


  def __init__(self, hostname, port, repository_directory, repository_mirrors,
               target_paths, ssl_certificates):

    """Constructor assumes that its parameters are valid."""

    self.hostname = hostname
    self.port = port
    self.network_location = \
      "{hostname}:{port}".format( hostname = hostname, port = port )
    self.repository_directory = repository_directory
    self.repository_mirrors = repository_mirrors
    self.target_paths = target_paths
    self.ssl_certificates = ssl_certificates


  def __repr__(self):
    MESSAGE = "Configuration(netloc={network_location})"
    return MESSAGE.format(network_location=self.network_location)


  def get_repository_mirror_hostnames(self):
    """Get a set of hostnames of every repository mirror of this
    configuration."""

    # Parse TUF server repository mirrors.
    repository_mirrors = self.repository_mirrors
    repository_mirror_hostnames = set()

    for repository_mirror in repository_mirrors:
      mirror_configuration = repository_mirrors[repository_mirror]
      url_prefix = mirror_configuration["url_prefix"]
      parsed_url = urlparse.urlparse(url_prefix)
      mirror_hostname = parsed_url.hostname
      repository_mirror_hostnames.add(mirror_hostname)

    return repository_mirror_hostnames





class ConfigurationParser(object):
  """Parses TUF interposition configuration information about a network
  location, stored as a JSON object, and returns it as a Configuration."""


  def __init__(self, network_location, configuration,
               parent_repository_directory=None,
               parent_ssl_certificates_directory=None):

    self.network_location = network_location
    self.configuration = configuration
    self.parent_repository_directory = parent_repository_directory
    self.parent_ssl_certificates_directory = parent_ssl_certificates_directory


  def get_network_location(self):
    """Check network location."""

    INVALID_NETWORK_LOCATION = "Invalid network location {network_location}!"

    network_location_tokens = self.network_location.split(':', 1)
    hostname = network_location_tokens[0]
    port = 80

    if len(network_location_tokens) > 1:
      port = int(network_location_tokens[1], 10)
      if port <= 0 or port >= 2**16:
        raise InvalidConfiguration(INVALID_NETWORK_LOCATION.format(
          network_location=self.network_location))

    return hostname, port


  def get_repository_directory(self):
    """Locate TUF client metadata repository."""

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
        raise InvalidConfiguration(INVALID_PARENT_REPOSITORY_DIRECTORY.format(
          network_location=self.network_location))

    return repository_directory


  def get_ssl_certificates(self):
    """Get any PEM certificate bundle."""

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
            raise InvalidConfiguration(INVALID_SSL_CERTIFICATES.format(
                network_location=self.network_location))

        else:
          raise InvalidConfiguration(
            INVALID_PARENT_SSL_CERTIFICATES_DIRECTORY.format(
              network_location=self.network_location))

    return ssl_certificates


  def get_repository_mirrors(self, hostname, port, ssl_certificates):
    """Parse TUF server repository mirrors."""

    INVALID_REPOSITORY_MIRROR = "Invalid repository mirror {repository_mirror}!"

    repository_mirrors = self.configuration["repository_mirrors"]
    repository_mirror_network_locations = set()

    for repository_mirror in repository_mirrors:
      mirror_configuration = repository_mirrors[repository_mirror]

      try:
        url_prefix = mirror_configuration["url_prefix"]
        parsed_url = urlparse.urlparse(url_prefix)
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
        Logger.exception(error_message)
        raise InvalidConfiguration(error_message)

    return repository_mirrors


  def get_target_paths(self):
    """
    Within a network_location, we match URLs with this list of regular
    expressions, which tell us to map from a source URL to a target URL.
    If there are multiple regular expressions which match a source URL,
    the order of appearance will be used to resolve ambiguity.
    """

    INVALID_TARGET_PATH = "Invalid target path in {network_location}!"

    # An "identity" capture from source URL to target URL.
    WILD_TARGET_PATH = { "(.*)": "{0}" }

    target_paths = self.configuration.get("target_paths", [WILD_TARGET_PATH])

    # target_paths: [ target_path, ... ]
    assert isinstance(target_paths, types.ListType)

    for target_path in target_paths:
      try:
        # target_path: { "regex_with_groups", "target_with_group_captures" }
        # e.g. { ".*(/some/directory)/$", "{0}/index.html" }
        assert isinstance(target_path, types.DictType)
        assert len(target_path) == 1

      except:
        error_message = \
          INVALID_TARGET_PATH.format(network_location=self.network_location)
        Logger.exception(error_message)
        raise InvalidConfiguration(error_message)

    return target_paths


  # TODO: more input sanity checks?
  def parse(self):
    """Parse, check and get the required configuration parameters."""

    hostname, port = self.get_network_location()
    ssl_certificates = self.get_ssl_certificates()
    repository_directory = self.get_repository_directory()
    target_paths = self.get_target_paths()

    repository_mirrors = \
      self.get_repository_mirrors(hostname, port, ssl_certificates)

    # If everything passes, we return a Configuration.
    return Configuration(hostname, port, repository_directory, repository_mirrors,
                         target_paths, ssl_certificates)
