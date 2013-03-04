import functools
import httplib
import json
import urllib
import urllib2

from configuration import Configuration
from utility import Logger
from updater import Updater

__all__ = []

# TODO:
# - Document design decisions.
# - Interposition: Honour urllib/urllib2 contract.
# - Review security issues resulting from regular expressions (e.g. complexity attacks).
# - Warn user when TUF is used without any configuration.
# - Override other default (e.g. HTTPS) urllib2 handlers.
# - Failsafe: If TUF fails, offer option to unsafely resort back to urllib/urllib2?


################################ GLOBAL CLASSES ################################


class FancyURLOpener( urllib.FancyURLopener ):
    # TODO: replicate complete behaviour of urllib.URLopener.open
    def open( self, fullurl, data = None ):
        updater = Updater.get_updater( fullurl )

        if updater is None:
            return urllib.FancyURLopener.open( self, fullurl, data = data )
        else:
            return updater.open( fullurl, data = data )

    # TODO: replicate complete behaviour of urllib.URLopener.retrieve
    def retrieve( self, url, filename = None, reporthook = None, data = None ):
        updater = Updater.get_updater( url )

        if updater is None:
            return urllib.FancyURLopener.retrieve(
                self,
                url,
                filename = filename,
                reporthook = reporthook,
                data = data
            )
        else:
            return updater.retrieve(
                url,
                filename = filename,
                reporthook = reporthook,
                data = data
            )


class HTTPHandler( urllib2.HTTPHandler ):
    # TODO: replicate complete behaviour of urllib.HTTPHandler.http_open
    def http_open( self, req ):
        fullurl = req.get_full_url()
        updater = Updater.get_updater( fullurl )

        if updater is None:
            return self.do_open( httplib.HTTPConnection, req )
        else:
            response = updater.open( fullurl, data = req.get_data() )
            # See urllib2.AbstractHTTPHandler.do_open
            # TODO: let DownloadMixin handle this
            response.msg = ""
            return response


############################## GLOBAL FUNCTIONS ################################


# TODO: Is parent_repository_directory a security risk? For example, would it
# allow the user to overwrite another TUF repository metadata on the filesystem?
# On the other hand, it is beyond TUF's scope to handle filesystem permissions.
def configure(
    filename = "tuf.interposition.json",
    parent_repository_directory = None
):
    """
    The optional parent_repository_directory parameter is used to specify the
    containing parent directory of the "repository_directory" specified in a
    configuration for *all* network locations, because sometimes the absolute
    location of the "repository_directory" is only known at runtime. If you
    need to specify a different parent_repository_directory for other
    network locations, simply call this method again with different parameters.

    Example of a TUF interposition configuration JSON object:

    {
        "network_locations": {
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
                ])
            }
        }
    }

    "target_paths" is optional: If you do not tell TUF to selectively match
    paths with regular expressions, TUF will work over any path under the given
    network location. However, if you do specify it, you are then telling TUF
    how to transform a specified path into another one, and TUF will *not*
    recognize any unspecified path for the given network location.
    """

    INVALID_TUF_CONFIGURATION = "Invalid configuration for {network_location}!"
    INVALID_TUF_INTERPOSITION_JSON = "Invalid configuration in {filename}!"
    NO_NETWORK_LOCATIONS = "No network locations found in configuration in {filename}!"

    try:
        with open( filename ) as tuf_interposition_json:
            tuf_interpositions = json.load( tuf_interposition_json )
            network_locations = tuf_interpositions.get( "network_locations", {} )

            # TODO: more input sanity checks
            if len( network_locations ) == 0:
                raise InvalidConfiguration(
                    NO_NETWORK_LOCATIONS.format( filename = filename )
                )
            else:
                for network_location, configuration in network_locations.iteritems():
                    try:
                        Updater.build_updater(
                            Configuration.load_from_json(
                                network_location,
                                configuration,
                                parent_repository_directory = parent_repository_directory
                            )
                        )
                    except:
                        Logger.error(
                            INVALID_TUF_CONFIGURATION.format(
                                network_location = network_location
                            )
                        )
                        raise
    except:
        Logger.error(
            INVALID_TUF_INTERPOSITION_JSON.format( filename = filename )
        )
        raise


def go_away():
    """Call me to restore previous urllib and urllib2 behaviour."""

    global _previous_urllib_urlopener
    global _previous_urllib2_opener

    if _previous_urllib_urlopener is not False:
        urllib._urlopener = _previous_urllib_urlopener
        _previous_urllib_urlopener = None

    if _previous_urllib2_opener is not False:
        # NOTE: slightly rude and, furthermore, fragile
        urllib2._opener = _previous_urllib2_opener
        _previous_urllib2_opener = None


def interpose():
    """Call me to have TUF interpose as urllib and urllib2."""

    global _previous_urllib_urlopener
    global _previous_urllib2_opener

    if _previous_urllib_urlopener is False:
        _previous_urllib_urlopener = urllib._urlopener
        # http://docs.python.org/2/library/urllib.html#urllib._urlopener
        urllib._urlopener = FancyURLOpener()

    if _previous_urllib2_opener is False:
        # NOTE: slightly rude and, furthermore, fragile
        _previous_urllib2_opener = urllib2._opener
        # http://docs.python.org/2/library/urllib2.html#urllib2.build_opener
        # http://docs.python.org/2/library/urllib2.html#urllib2.install_opener
        urllib2.install_opener( urllib2.build_opener( HTTPHandler ) )


def open_url( instancemethod ):
    """Decorate a caller instance method of the form
    instancemethod( self, url,... ) with me in order to give it to TUF."""

    @functools.wraps( instancemethod )
    def wrapper( self, *args, **kwargs ):
        # TODO: Ensure that the first argument to instancemethod is a URL.
        url = args[ 0 ]
        data = kwargs.get( "data" )
        updater = Updater.get_updater( url )

        # If TUF has not been configured for this URL...
        if updater is None:
            # ...then revert to default behaviour.
            return instancemethod( self, *args, **kwargs )
        else:
            # ...otherwise, use TUF to get this document.
            return updater.open( url, data = data )

    return wrapper


############################## GLOBAL VARIABLES ################################


# We use False as a sentinel value.
_previous_urllib_urlopener = False
_previous_urllib2_opener = False
