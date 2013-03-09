import functools
import imp
import json
import socket
import urllib
import urllib2


# We import them directly into our namespace so that there is no name conflict.
from configuration import ConfigurationParser, InvalidConfiguration
from utility import Logger
from updater import UpdaterController


# Export nothing when: from tuf.interposition import *
__all__ = []


# TODO:
# - Document design decisions.
# - Interposition: Honour urllib/urllib2 contract.
# - Review security issues resulting from regular expressions (e.g. complexity attacks).
# - Warn user when TUF is used without any configuration.
# - Override other default (e.g. HTTPS) urllib2 handlers.
# - Failsafe: If TUF fails, offer option to unsafely resort back to urllib/urllib2?





############################## GLOBAL VARIABLES ################################





# Our own public copies of the urllib and urllib2 modules.
# We use None as sentinel values.
urllib_tuf = None
urllib2_tuf = None


# A private, global Controller of Updaters.
__updater_controller = UpdaterController()





########################## GLOBAL PRIVATE FUNCTIONS ############################





def __monkey_patch():
  """Build and monkey patch public copies of the urllib and urllib2 modules.

  We prefer simplicity, which leads to easier proof of security, even if it may
  come at the cost of not honouring some provisions of the urllib and urllib2
  module contracts unrelated to security.

  References:
    http://stackoverflow.com/a/11285504
    http://docs.python.org/2/library/imp.html"""

  global urllib_tuf
  global urllib2_tuf

  if urllib_tuf is None:
    try:
      module_file, pathname, description = imp.find_module("urllib")
      urllib_tuf = \
        imp.load_module( "urllib_tuf", module_file, pathname, description)
      module_file.close()
    except:
      raise
    else:
      urllib_tuf.urlopen = __urllib_urlopen
      urllib_tuf.urlretrieve = __urllib_urlretrieve

  if urllib2_tuf is None:
    try:
      module_file, pathname, description = imp.find_module("urllib2")
      urllib2_tuf = \
        imp.load_module( "urllib2_tuf", module_file, pathname, description)
      module_file.close()
    except:
      raise
    else:
      urllib2_tuf.urlopen = __urllib2_urlopen





def __urllib_urlopen(url, data=None, proxies=None):
  """Create a file-like object for the specified URL to read from."""

  updater = __updater_controller.get(url)

  if updater is None:
    return urllib.urlopen(url, data=data, proxies=proxies)
  else:
    return updater.open(url, data=data)





def __urllib_urlretrieve(url, filename=None, reporthook=None, data=None):
  """Copy a network object denoted by a URL to a local file, if necessary."""

  updater = __updater_controller.get(url)

  if updater is None:
    return urllib.urlretrieve(url, filename=filename, reporthook=reporthook, data=data)
  else:
    return updater.retrieve(url, filename=filename, reporthook=reporthook, data=data)





def __urllib2_urlopen(url, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
  """Create a file-like object for the specified URL to read from."""

  updater = __updater_controller.get(url)

  if updater is None:
    return urllib2.urlopen(url, data=data, timeout=timeout)
  else:
    response = updater.open(url, data=data)
    # See urllib2.AbstractHTTPHandler.do_open
    # TODO: let Updater handle this
    response.msg = ""
    return response





########################### GLOBAL PUBLIC FUNCTIONS ############################





# TODO: Is parent_repository_directory a security risk? For example, would it
# allow the user to overwrite another TUF repository metadata on the filesystem?
# On the other hand, it is beyond TUF's scope to handle filesystem permissions.
# TODO: Ditto for the parent_ssl_certificates_directory parameter.

def configure(filename="tuf.interposition.json",
              parent_repository_directory=None,
              parent_ssl_certificates_directory=None):
  """
  The optional parent_repository_directory parameter is used to specify the
  containing parent directory of the "repository_directory" specified in a
  configuration for *all* network locations, because sometimes the absolute
  location of the "repository_directory" is only known at runtime. If you
  need to specify a different parent_repository_directory for other
  network locations, simply call this method again with different parameters.

  Ditto for the optional parent_ssl_certificates_directory parameter.

  Example of a TUF interposition configuration JSON object:

  {
      "configurations": {
          "seattle.cs.washington.edu": {
              "repository_directory": "client/",
              "repository_mirrors" : {
                  "mirror1": {
                      "url_prefix": "http://seattle-tuf.cs.washington.edu",
                      "metadata_path": "metadata",
                      "targets_path": "targets",
                      "confined_target_dirs": [ "" ]
                  }
              },
              ("target_paths": [
                  { ".*/(simple/\\w+)/$": "{0}/index.html" },
                  { ".*/(packages/.+)$": "{0}" }
              ],
              "ssl_certificates": "cacert.pem")
          }
      }
  }

  "target_paths" is optional: If you do not tell TUF to selectively match
  paths with regular expressions, TUF will work over any path under the given
  network location. However, if you do specify it, you are then telling TUF
  how to transform a specified path into another one, and TUF will *not*
  recognize any unspecified path for the given network location.

  Unless any "url_prefix" begins with "https://", "ssl_certificates" is
  optional; it must specify certificates bundled as PEM (RFC 1422).
  """

  INVALID_TUF_CONFIGURATION = "Invalid configuration for {network_location}!"
  INVALID_TUF_INTERPOSITION_JSON = "Invalid configuration in {filename}!"
  NO_CONFIGURATIONS = "No configurations found in configuration in {filename}!"

  try:
    with open(filename) as tuf_interposition_json:
      tuf_interpositions = json.load(tuf_interposition_json)
      configurations = tuf_interpositions.get("configurations", {})

      if len(configurations) == 0:
        raise InvalidConfiguration(NO_CONFIGURATIONS.format(filename=filename))

      else:
        for network_location, configuration in configurations.iteritems():
          try:
            configuration_parser = ConfigurationParser(network_location,
              configuration, parent_repository_directory=parent_repository_directory,
              parent_ssl_certificates_directory=parent_ssl_certificates_directory)

            configuration = configuration_parser.parse()
            __updater_controller.add(configuration)

          except:
            Logger.error(INVALID_TUF_CONFIGURATION.format(network_location=network_location))
            raise

  except:
    Logger.error(INVALID_TUF_INTERPOSITION_JSON.format(filename=filename))
    raise





def open_url(instancemethod):
  """Decorate an instance method of the form
  instancemethod(self, url, ...) with me in order to pass it to TUF."""

  @functools.wraps(instancemethod)
  def wrapper(self, *args, **kwargs):
    # TODO: Ensure that the first argument to instancemethod is a URL.
    url = args[0]
    data = kwargs.get("data")
    updater = __updater_controller.get(url)

    # If TUF has not been configured for this URL...
    if updater is None:
      # ...then revert to default behaviour.
      return instancemethod(self, *args, **kwargs)
    else:
      # ...otherwise, use TUF to get this document.
      return updater.open(url, data=data)

  return wrapper





############################## GLOBAL SIDE EFFECTS #############################





# Build and monkey patch public copies of the urllib and urllib2 modules.
__monkey_patch()
