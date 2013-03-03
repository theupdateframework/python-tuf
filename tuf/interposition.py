import functools
import httplib
import json
import logging
import mimetypes
import os.path
import re
import shutil
import tempfile
import types
import urllib
import urllib2
import urlparse

import tuf.client.updater
import tuf.conf


# TODO:
# - Document design decisions.
# - Interposition: Honour urllib/urllib2 contract.
# - Review security issues resulting from regular expressions (e.g. complexity attacks).
# - Warn user when TUF is used without any configuration.
# - Override other default (e.g. HTTPS) urllib2 handlers.
# - Failsafe: If TUF fails, offer option to unsafely resort back to urllib/urllib2?


################################ GLOBAL CLASSES ################################

class InterpositionException( Exception ):
    """Base exception class."""

    pass

class URLMatchesNoPattern( InterpositionException ):
    """URL matches no user-specified regular expression pattern."""

    pass

class InvalidConfiguration( InterpositionException ):
    """User configuration is invalid."""

    pass


class Logger( object ):
    __logger = logging.getLogger( "tuf.interposition" )

    @staticmethod
    def error( message ):
        Logger.__logger.error( message )
        Logger.exception( message )

    @staticmethod
    def exception( message ):
        Logger.__logger.exception( message )

    @staticmethod
    def warn( message ):
        Logger.__logger.warn( message )
        Logger.exception( message )


class Configuration( object ):
    def __init__(
        self,
        hostname,
        port,
        repository_directory,
        repository_mirrors,
        target_paths
    ):
        """This constructor assumes that its parameters are valid."""

        self.hostname = hostname
        self.port = port
        self.network_location = \
            "{hostname}:{port}".format( hostname = hostname, port = port )
        self.repository_directory = repository_directory
        self.repository_mirrors = repository_mirrors
        self.target_paths = target_paths
        self.tempdir = tempfile.mkdtemp()

    @staticmethod
    def load_from_json(
        network_location,
        configuration,
        parent_repository_directory = None
    ):

        INVALID_REPOSITORY_MIRROR = \
            "Invalid repository mirror {repository_mirror}!"
        INVALID_NETWORK_LOCATION = \
            "Invalid network location {network_location}!"
        INVALID_PARENT_REPOSITORY_DIRECTORY = "Invalid " + \
            "parent_repository_directory for {network_location}!"
        # An "identity" capture from source URL to target URL
        WILD_TARGET_PATH = { "(.*)": "{0}" }

        # Check network location
        network_location_tokens = network_location.split( ':', 1 )
        hostname = network_location_tokens[ 0 ]
        port = 80

        if len( network_location_tokens ) > 1:
            try:
                port = int( network_location_tokens[ 1 ], 10 )
                assert port > 0 and port < 2**16
            except:
                error_message = INVALID_NETWORK_LOCATION.format(
                    network_location = network_location
                )
                Logger.error( error_message )
                raise InvalidConfiguration( error_message )

        # Locate TUF client metadata repository
        repository_directory = configuration[ "repository_directory" ]
        if parent_repository_directory is not None:
            parent_repository_directory = \
                os.path.abspath( parent_repository_directory )
            if os.path.isdir( parent_repository_directory ):
                repository_directory = os.path.join(
                    parent_repository_directory,
                    repository_directory
                )
            else:
                raise InvalidConfiguration(
                    INVALID_PARENT_REPOSITORY_DIRECTORY.format(
                        network_location = network_location
                    )
                )

        # Parse TUF server repository mirrors
        repository_mirrors = configuration[ "repository_mirrors" ]
        for repository_mirror in repository_mirrors:
            mirror_configuration = repository_mirrors[ repository_mirror ]
            try:
                url_prefix = mirror_configuration[ "url_prefix" ]
                parsed_url = urlparse.urlparse( url_prefix )
                mirror_hostname = parsed_url.hostname
                mirror_port = parsed_url.port or 80
                # No infinite loop in interposition!
                assert hostname != mirror_hostname or port != mirror_port
            except:
                error_message = INVALID_REPOSITORY_MIRROR.format(
                    repository_mirror = repository_mirror
                )
                Logger.error( error_message )
                raise InvalidConfiguration( error_message )

        # Within a network_location, we match URLs with this list of regular
        # expressions, which tell us to map from a source URL to a target URL.
        # If there are multiple regular expressions which match a source URL,
        # the order of appearance will be used to resolve ambiguity.
        target_paths = \
            configuration.get( "target_paths", [ WILD_TARGET_PATH  ] )

        # target_paths: [ target_path, ... ]
        assert isinstance( target_paths, types.ListType )
        for target_path in target_paths:
            # target_path: { "regex_with_groups", "target_with_group_captures" }
            # e.g. { ".*(/some/directory)/$", "{0}/index.html" }
            assert isinstance( target_path, types.DictType )
            assert len( target_path ) == 1

        # If everything passes, we return a Configuration.
        return Configuration(
            hostname,
            port,
            repository_directory,
            repository_mirrors,
            target_paths
        )


class Updater( object ):
    """
    You can think of Updater as being a factory of Updaters;
    given a Configuration, it will build and store an Updater
    which you can get and use later.
    """

    # A private collection of Updaters;
    # network_location: str -> updater: Updater
    __updaters = {}

    def __init__( self, configuration ):
        self.configuration = configuration

        # must switch context before instantiating updater
        # because updater depends on some module (tuf.conf) variables
        self.switch_context()
        self.updater = tuf.client.updater.Updater(
            self.configuration.hostname,
            self.configuration.repository_mirrors
        )

    @staticmethod
    def build_updater( configuration ):
        assert isinstance( configuration, Configuration )
        assert configuration.network_location not in Updater.__updaters

        Updater.__updaters[ configuration.network_location ] = \
            Updater( configuration )

    def download_target( self, target_filepath ):
        """Downloads target with TUF as a side effect."""

        # download file into a temporary directory shared over runtime
        destination_directory = self.configuration.tempdir
        filename = os.path.join( destination_directory, target_filepath )

        # switch TUF context
        self.switch_context()
        # update TUF client repository metadata
        self.updater.refresh()

        # then, update target at filepath
        targets = [ self.updater.target( target_filepath ) ]

        # TODO: targets are always updated if destination directory is new, right?
        updated_targets = self.updater.updated_targets(
            targets, destination_directory
        )

        for updated_target in updated_targets:
            self.updater.download_target(
                updated_target, destination_directory
            )

        return destination_directory, filename

    # TODO: decide prudent course of action in case of failure
    def get_target_filepath( self, source_url ):
        """Given source->target map,
        figure out what TUF *should* download given a URL."""

        WARNING_MESSAGE = "Possibly invalid target_paths for " + \
            "{network_location}! No TUF interposition for {url}"

        parsed_source_url = urlparse.urlparse( source_url )
        target_filepath = None

        try:
            # Does this source URL match any regular expression which tells us
            # how to map the source URL to a target URL understood by TUF?
            for target_path in self.configuration.target_paths:
                # target_path: { "regex_with_groups", "target_with_group_captures" }
                # e.g. { ".*(/some/directory)/$", "{0}/index.html" }
                source_path_pattern, target_path_pattern = \
                    target_path.items()[ 0 ]
                source_path_match = \
                    re.match( source_path_pattern, parsed_source_url.path )

                if source_path_match is not None:
                    target_filepath = target_path_pattern.format(
                        *source_path_match.groups()
                    )
                    # If there is more than one regular expression which
                    # matches source_url, we resolve ambiguity by order of
                    # appearance.
                    break

            # If source_url does not match any regular expression...
            if target_filepath is None:
                # ...then we raise a predictable exception.
                raise URLMatchesNoPattern( source_url )
        except:
            Logger.warn(
                WARNING_MESSAGE.format(
                    network_location = self.configuration.network_location,
                    url = source_url
                )
            )
            raise
        else:
            # TUF assumes that target_filepath does not begin with a '/'.
            target_filepath = target_filepath.lstrip( '/' )
            return target_filepath

    @staticmethod
    def get_updater( url ):
        WARNING_MESSAGE = "No updater and, hence, TUF interposition for {url}!"

        updater = None

        try:
            parsed_url = urlparse.urlparse( url )
            hostname = parsed_url.hostname
            port = parsed_url.port or 80
            network_location = \
                "{hostname}:{port}".format( hostname = hostname, port = port )

            updater = Updater.__updaters.get( network_location )
            # This will raise an exception in case we do not recognize
            # how to transform this URL for TUF. In that case, there will be
            # no updater for this URL.
            if updater is not None:
                target_filepath = updater.get_target_filepath( url )
        except:
            Logger.warn( WARNING_MESSAGE.format( url = url ) )
            updater = None
        finally:
            return updater

    # TODO: distinguish between urllib and urllib2 contracts
    def open( self, url, data = None ):
        filename, headers = self.retrieve( url, data = data )

        # TODO: like tempfile, ensure file is deleted when closed?
        tempfile = open( filename )
        # extend tempfile with info(), getcode(), geturl()
        # http://docs.python.org/2/library/urllib.html#urllib.urlopen
        response = urllib.addinfourl(
            tempfile,
            headers,
            url,
            code = 200
        )

        return response

    # TODO: distinguish between urllib and urllib2 contracts
    def retrieve(
        self,
        url,
        filename = None,
        reporthook = None,
        data = None
    ):
        # TODO: set valid headers
        content_type, content_encoding = mimetypes.guess_type( url )
        headers = { "content-type": content_type }

        target_filepath = self.get_target_filepath( url )

        temporary_directory, temporary_filename = \
            self.download_target( target_filepath )

        if filename is None:
            # If no filename is given, use the temporary file.
            filename = temporary_filename
        else:
            # Otherwise, copy TUF-downloaded file in its own directory
            # to the location user specified.
            shutil.copy2( temporary_filename, filename )

        return filename, headers

    # TODO: thread-safety, perhaps with a context manager
    def switch_context( self ):
        # Set the local repository directory containing the metadata files.
        tuf.conf.repository_directory = \
            self.configuration.repository_directory


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


def open_url( method ):
    """Decorate a caller instance method of the form method( self, url, ... )
    with this decorator in order to provide it with TUF security."""

    @functools.wraps( method )
    def wrapper( self, *args, **kwargs ):
        # TODO: Ensure that the first argument to method is a URL.
        url = args[ 0 ]
        data = kwargs.get( "data" )
        updater = Updater.get_updater( url )

        # If TUF has not been configured for this URL...
        if updater is None:
            # ...then revert to default behaviour.
            return method( self, *args, **kwargs )
        else:
            # ...otherwise, use TUF to get this document.
            return updater.open( url, data = data )

    return wrapper


############################## GLOBAL VARIABLES ################################


# We use False as a sentinel value.
_previous_urllib_urlopener = False
_previous_urllib2_opener = False
