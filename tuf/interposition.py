import httplib
import json
import logging
import mimetypes
import os.path
import shutil
import tempfile
import urllib
import urllib2
import urlparse

import tuf.client.updater
import tuf.conf


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
    """
    You can think of Updater as being a factory of Updaters;
    given a Configuration, it will build and store an Updater
    which you can get and use later.
    """

    # A private collection of Updaters;
    # hostname: str -> updater: Updater
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
        assert configuration.hostname not in Updater.__updaters

        Updater.__updaters[ configuration.hostname ] = Updater( configuration )

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
        targets = [ self.updater.target( filepath ) ]

        # TODO: targets are always updated if destination directory is new, right?
        updated_targets = self.updater.updated_targets(
            targets, destination_directory
        )

        for updated_target in updated_targets:
            self.updater.download_target(
                updated_target, destination_directory
            )

        return destination_directory, filename

    @staticmethod
    def get_updater( url ):
        parsed_url = urlparse.urlparse( url )
        # TODO: enable specificity beyond hostname (e.g. include scheme, port)
        return Updater.__updaters.get( parsed_url.hostname )

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

        parsed_url = urlparse.urlparse( url )
        # TUF assumes that target_filepath does not begin with a '/'
        target_filepath = parsed_url.path.lstrip( '/' )

        temporary_directory, temporary_filename = \
            self.download_target( target_filepath )

        # copy TUF-downloaded file in its own directory
        # to the location user specified
        if filename is not None:
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


def configure( filename = "tuf.interposition.json" ):
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
                        "confined_target_dirs": [ "" ]
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
                        Updater.build_updater(
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


def go_away():
    """Remove TUF interposition and restore previous urllib openers."""
    raise NotImplementedError


def interpose():
    # http://docs.python.org/2/library/urllib.html#urllib._urlopener
    urllib._urlopener = FancyURLOpener()

    # http://docs.python.org/2/library/urllib2.html#urllib2.build_opener
    # http://docs.python.org/2/library/urllib2.html#urllib2.install_opener
    # TODO: override other default urllib2 handlers
    urllib2.install_opener( urllib2.build_opener( HTTPHandler ) )
