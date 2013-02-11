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
_logger = logging.getLogger( "tuf.interposition" )


class TUFConfiguration( object ):
    def __init__( self, hostname, repository_directory, repository_mirrors ):
        self.hostname = hostname
        self.repository_directory = repository_directory
        self.repository_mirrors = repository_mirrors
        self.tempdir = tempfile.mkdtemp()

    @staticmethod
    def load_from_json( hostname, configuration ):
        repository_directory = configuration[ "repository_directory" ]
        repository_mirrors = configuration[ "repository_mirrors" ]

        return TUFConfiguration(
            hostname,
            repository_directory,
            repository_mirrors
        )


class TUFUpdater( object ):
    # hostname: str -> tuf_configuration: TUFConfiguration
    __tuf_configurations = {}

    def __init__( self, url, parsed_url, tuf_configuration ):
        self.url = url
        self.parsed_url = parsed_url
        self.tuf_configuration = tuf_configuration

        # must switch context before instantiating updater
        # because updater depends on some module (tuf.conf) variables
        self.switch_context()
        self.updater = tuf.client.updater.Updater(
            self.parsed_url.hostname,
            self.tuf_configuration.repository_mirrors
        )

    @staticmethod
    def add_tuf_configuration( tuf_configuration ):
        assert isinstance( tuf_configuration, TUFConfiguration )
        assert tuf_configuration.hostname not in TUFUpdater.__tuf_configurations

        TUFUpdater.__tuf_configurations[
            tuf_configuration.hostname
        ] = tuf_configuration

    @staticmethod
    def make_tuf_updater( url ):
        parsed_url = urlparse.urlparse( url )
        # TODO: enable specificity beyond hostname (e.g. include scheme, port)
        tuf_configuration = \
            TUFUpdater.__tuf_configurations.get( parsed_url.hostname )

        if tuf_configuration is None:
            return None
        else:
            return TUFUpdater( url, parsed_url, tuf_configuration )

    def make_tempfile( self, target_filepath ):
        destination_directory = self.tuf_configuration.tempdir
        filename = os.path.join( destination_directory, target_filepath )
        return destination_directory, filename

    # TODO: not thread-safe
    def switch_context( self ):
        # Set the local repository directory containing the metadata files.
        tuf.conf.repository_directory = \
            self.tuf_configuration.repository_directory


# TODO: distinguish between urllib and urllib2 contracts
class TUFDownloadMixin( object ):
    def tuf_open( self, tuf_updater, data = None ):
        filename, headers = self.tuf_retrieve( tuf_updater, data = data )

        # TODO: like tempfile, ensure file is deleted when closed?
        tempfile = open( filename )
        # extend tempfile with info(), getcode(), geturl()
        # http://docs.python.org/2/library/urllib.html#urllib.urlopen
        response = urllib.addinfourl(
            tempfile,
            headers,
            tuf_updater.url,
            code = 200
        )

        return response

    def tuf_retrieve(
        self,
        tuf_updater,
        filename = None,
        reporthook = None,
        data = None
    ):
        # TODO: set valid headers
        headers = None
        # TUF assumes that target_filepath does not begin with a '/'
        target_filepath = tuf_updater.parsed_url.path.lstrip( '/' )

        # if filename does not exist, then we use a temporary directory
        if filename is None:
            destination_directory, filename = tuf_updater.make_tempfile(
                target_filepath
            )
        else:
            # TODO: think later about best course of action for filename
            if filename.endswith( target_filepath ):
                last_index = filename.rfind( target_filepath )
                destination_directory = filename[ : last_index ]
                if not os.path.isdir( destination_directory ):
                    destination_directory, filename = \
                        tuf_updater.make_tempfile( target_filepath )
            else:
                destination_directory, filename = \
                    tuf_updater.make_tempfile( target_filepath )

        # TODO: higher-level download abstractions via TUFUpdater
        tuf_updater.switch_context()
        tuf_updater.updater.refresh()

        targets = [ tuf_updater.updater.target( target_filepath ) ]
        updated_targets = tuf_updater.updater.updated_targets(
            targets,
            destination_directory
        )

        for target in updated_targets:
            tuf_updater.updater.download_target(
                target,
                destination_directory
            )

        return filename, headers


class TUFancyURLOpener( urllib.FancyURLopener, TUFDownloadMixin ):
    # TODO: replicate complete behaviour of urllib.URLopener.open
    def open( self, fullurl, data = None ):
        tuf_updater = TUFUpdater.make_tuf_updater( fullurl )

        if tuf_updater is None:
            return urllib.FancyURLopener.open( self, fullurl, data = data )
        else:
            return self.tuf_open( tuf_updater, data = data )

    # TODO: replicate complete behaviour of urllib.URLopener.retrieve
    def retrieve( self, url, filename = None, reporthook = None, data = None ):
        tuf_updater = TUFUpdater.make_tuf_updater( url )

        if tuf_updater is None:
            return urllib.FancyURLopener.retrieve(
                self,
                url,
                filename = filename,
                reporthook = reporthook,
                data = data
            )
        else:
            return self.tuf_retrieve(
                tuf_updater,
                filename = filename,
                reporthook = reporthook,
                data = data
            )


class TUFHTTPHandler( urllib2.HTTPHandler, TUFDownloadMixin ):
    # TODO: replicate complete behaviour of urllib.HTTPHandler.http_open
    def http_open( self, req ):
        tuf_updater = TUFUpdater.make_tuf_updater( req.get_full_url() )

        if tuf_updater is None:
            return self.do_open( httplib.HTTPConnection, req )
        else:
            response = self.tuf_open( tuf_updater, data = req.get_data() )
            # See urllib2.AbstractHTTPHandler.do_open
            # TODO: let TUFDownloadMixin handle this
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
        'hostnames' : {
            'seattle.cs.washington.edu': {
                'repository_directory': '.client/',
                'repository_mirrors' : {
                    'mirror1': {
                        'url_prefix': 'http://seattle-tuf.cs.washington.edu',
                        'metadata_path': 'metadata',
                        'targets_path': 'targets',
                        'confined_target_paths': [ '' ]
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
                log_warning( NO_HOSTNAMES.format( filename = filename ) )
            else:
                for hostname, configuration in hostnames.iteritems():
                    try:
                        TUFUpdater.add_tuf_configuration(
                            TUFConfiguration.load_from_json(
                                hostname,
                                configuration
                            )
                        )
                    except:
                        log_warning(
                            INVALID_TUF_CONFIGURATION.format(
                                hostname = hostname
                            )
                        )
    except:
        log_warning(
            INVALID_TUF_INTERPOSITION_JSON.format( filename = filename )
        )
    else:
        # http://docs.python.org/2/library/urllib.html#urllib._urlopener
        urllib._urlopener = TUFancyURLOpener()

        # http://docs.python.org/2/library/urllib2.html#urllib2.build_opener
        # http://docs.python.org/2/library/urllib2.html#urllib2.install_opener
        # TODO: override other default urllib2 handlers
        urllib2.install_opener( urllib2.build_opener( TUFHTTPHandler ) )


def go_away():
    """Remove TUF interposition and restore previous urllib openers."""
    raise NotImplementedError


def log_exception( message ):
    _logger.exception( message )


def log_warning( message ):
    _logger.warn( message )
    log_exception( message )
