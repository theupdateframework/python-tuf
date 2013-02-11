import httplib
import json
import logging
import os.path
import tempfile
import tuf.client.updater
import tuf.conf
import urllib
import urllib2
import urlparse


# TODO:
# - failsafe: if TUF fails, offer option to unsafely resort back to urllib/urllib2
# - match URLs not with hostnames, but with regular expressions


class Logger( object ):
    __logger = logging.getLogger( "tuf.interposition" )

    @staticmethod
    def exception( message ):
        Logger.__logger.exception( message )

    @staticmethod
    def warn( message ):
        Logger.__logger.warn( message )
        Logger.exception( message )


class Configuration( object ):
    def __init__( self, hostname, repository_directory, repository_mirrors ):
        self.hostname = hostname
        self.repository_directory = repository_directory
        self.repository_mirrors = repository_mirrors
        self.tempdir = tempfile.mkdtemp()

    @staticmethod
    def load_from_json( hostname, configuration ):
        repository_directory = configuration[ "repository_directory" ]
        repository_mirrors = configuration[ "repository_mirrors" ]

        return Configuration(
            hostname,
            repository_directory,
            repository_mirrors
        )


class Updater( object ):
    # hostname: str -> configuration: Configuration
    __configurations = {}

    def __init__( self, url, parsed_url, configuration ):
        self.url = url
        self.parsed_url = parsed_url
        self.configuration = configuration

        # must switch context before instantiating updater
        # because updater depends on some module (tuf.conf) variables
        self.switch_context()
        self.updater = tuf.client.updater.Updater(
            self.parsed_url.hostname,
            self.configuration.repository_mirrors
        )

    @staticmethod
    def add_configuration( configuration ):
        assert isinstance( configuration, Configuration )
        assert configuration.hostname not in Updater.__configurations

        Updater.__configurations[ configuration.hostname ] = configuration

    @staticmethod
    def make_updater( url ):
        parsed_url = urlparse.urlparse( url )
        # TODO: enable specificity beyond hostname (e.g. include scheme, port)
        configuration = \
            Updater.__configurations.get( parsed_url.hostname )

        if configuration is None:
            return None
        else:
            # TODO: handle raised exceptions!
            return Updater( url, parsed_url, configuration )

    def make_tempfile( self, target_filepath ):
        destination_directory = self.configuration.tempdir
        filename = os.path.join( destination_directory, target_filepath )
        return destination_directory, filename

    # TODO: not thread-safe
    def switch_context( self ):
        # Set the local repository directory containing the metadata files.
        tuf.conf.repository_directory = \
            self.configuration.repository_directory


# TODO: distinguish between urllib and urllib2 contracts
class DownloadMixin( object ):
    def tuf_open( self, updater, data = None ):
        filename, headers = self.tuf_retrieve( updater, data = data )

        # TODO: like tempfile, ensure file is deleted when closed?
        tempfile = open( filename )
        # extend tempfile with info(), getcode(), geturl()
        # http://docs.python.org/2/library/urllib.html#urllib.urlopen
        response = urllib.addinfourl(
            tempfile,
            headers,
            updater.url,
            code = 200
        )

        return response

    def tuf_retrieve(
        self,
        updater,
        filename = None,
        reporthook = None,
        data = None
    ):
        # TODO: set valid headers
        headers = None
        # TUF assumes that target_filepath does not begin with a '/'
        target_filepath = updater.parsed_url.path.lstrip( '/' )

        # if filename does not exist, then we use a temporary directory
        if filename is None:
            destination_directory, filename = updater.make_tempfile(
                target_filepath
            )
        else:
            # TODO: think later about best course of action for filename
            if filename.endswith( target_filepath ):
                last_index = filename.rfind( target_filepath )
                destination_directory = filename[ : last_index ]
                if not os.path.isdir( destination_directory ):
                    destination_directory, filename = \
                        updater.make_tempfile( target_filepath )
            else:
                destination_directory, filename = \
                    updater.make_tempfile( target_filepath )

        # TODO: higher-level download abstractions via Updater
        updater.switch_context()
        updater.updater.refresh()

        targets = [ updater.updater.target( target_filepath ) ]
        updated_targets = updater.updater.updated_targets(
            targets,
            destination_directory
        )

        for target in updated_targets:
            updater.updater.download_target(
                target,
                destination_directory
            )

        return filename, headers


class FancyURLOpener( urllib.FancyURLopener, DownloadMixin ):
    # TODO: replicate complete behaviour of urllib.URLopener.open
    def open( self, fullurl, data = None ):
        updater = Updater.make_updater( fullurl )

        if updater is None:
            return urllib.FancyURLopener.open( self, fullurl, data = data )
        else:
            return self.tuf_open( updater, data = data )

    # TODO: replicate complete behaviour of urllib.URLopener.retrieve
    def retrieve( self, url, filename = None, reporthook = None, data = None ):
        updater = Updater.make_updater( url )

        if updater is None:
            return urllib.FancyURLopener.retrieve(
                self,
                url,
                filename = filename,
                reporthook = reporthook,
                data = data
            )
        else:
            return self.tuf_retrieve(
                updater,
                filename = filename,
                reporthook = reporthook,
                data = data
            )


class HTTPHandler( urllib2.HTTPHandler, DownloadMixin ):
    # TODO: replicate complete behaviour of urllib.HTTPHandler.http_open
    def http_open( self, req ):
        updater = Updater.make_updater( req.get_full_url() )

        if updater is None:
            return self.do_open( httplib.HTTPConnection, req )
        else:
            response = self.tuf_open( updater, data = req.get_data() )
            # See urllib2.AbstractHTTPHandler.do_open
            # TODO: let DownloadMixin handle this
            response.msg = ""
            return response


def interpose( filename = "tuf.interposition.json" ):
    INVALID_TUF_CONFIGURATION = "Invalid TUF configuration for " + \
        "{hostname}! TUF interposition will NOT be present for {hostname}."
    INVALID_TUF_INTERPOSITION_JSON = "Invalid TUF configuration JSON file " + \
        "{filename}! TUF interposition will NOT be present for any host."
    NO_HOSTNAMES = "No hostnames found in TUF configuration JSON file " + \
        "{filename}! TUF interposition will NOT be present for any host."

    """
    {
        "hostnames": {
            "seattle.cs.washington.edu": {
                "repository_directory": ".client/",
                "repository_mirrors" : {
                    "mirror1": {
                        "url_prefix": "http://seattle-tuf.cs.washington.edu",
                        "metadata_path": "metadata",
                        "targets_path": "targets",
                        "confined_target_paths": [ "" ]
                    }
                }
            }
        }
    }
    """
    try:
        with open( filename ) as tuf_interposition_json:
            tuf_interpositions = json.load( tuf_interposition_json )
            hostnames = tuf_interpositions.get( 'hostnames', {} )

            # TODO: more input sanity checks
            if len( hostnames ) == 0:
                Logger.warn( NO_HOSTNAMES.format( filename = filename ) )
            else:
                for hostname, configuration in hostnames.iteritems():
                    try:
                        Updater.add_configuration(
                            Configuration.load_from_json(
                                hostname,
                                configuration
                            )
                        )
                    except:
                        Logger.warn(
                            INVALID_TUF_CONFIGURATION.format(
                                hostname = hostname
                            )
                        )
    except:
        Logger.warn(
            INVALID_TUF_INTERPOSITION_JSON.format( filename = filename )
        )
    else:
        # http://docs.python.org/2/library/urllib.html#urllib._urlopener
        urllib._urlopener = FancyURLOpener()

        # http://docs.python.org/2/library/urllib2.html#urllib2.build_opener
        # http://docs.python.org/2/library/urllib2.html#urllib2.install_opener
        # TODO: override other default urllib2 handlers
        urllib2.install_opener( urllib2.build_opener( HTTPHandler ) )


def go_away():
    """Remove TUF interposition and restore previous urllib openers."""
    raise NotImplementedError
