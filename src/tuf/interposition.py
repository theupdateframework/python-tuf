import os.path
import tempfile
import tuf.client.updater
import tuf.conf
import urllib
import urlparse


class TUFConfiguration( object ):
    def __init__( self, hostname, repository_directory, repository_mirrors ):
        self.hostname = hostname
        self.repository_directory = repository_directory
        self.repository_mirrors = repository_mirrors
        self.tempdir = tempfile.mkdtemp()


class TUFancyURLOpener( urllib.FancyURLopener ):
    # TODO: replicate complete behaviour of urllib.URLopener.open
    def __tuf_open( self, tuf_updater, data = None ):
        filename, headers = self.__tuf_retrieve( tuf_updater, data = data )

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

    # TODO: replicate complete behaviour of urllib.URLopener.retrieve
    def __tuf_retrieve(
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

    def open( self, fullurl, data = None ):
        tuf_updater = TUFUpdater.make_tuf_updater( fullurl )

        if tuf_updater is None:
            return urllib.FancyURLopener.open( self, fullurl, data = data )
        else:
            return self.__tuf_open( tuf_updater, data = data )

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
            return self.__tuf_retrieve(
                tuf_updater,
                filename = filename,
                reporthook = reporthook,
                data = data
            )


class TUFile( file ):
    pass


class TUFUpdater( object ):
    # hostname: str -> tuf_configuration: TUFConfiguration
    _tuf_configurations = {}

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
    def make_tuf_updater( url ):
        parsed_url = urlparse.urlparse( url )
        # TODO: enable specificity beyond hostname (e.g. include scheme, port)
        tuf_configuration = \
            TUFUpdater._tuf_configurations.get( parsed_url.hostname )

        if tuf_configuration is None:
            return None
        else:
            return TUFUpdater( url, parsed_url, tuf_configuration )

    def make_tempfile( self, target_filepath ):
        destination_directory = self.tuf_configuration.tempdir
        filename = os.path.join( destination_directory, target_filepath )
        return destination_directory, filename

    def switch_context( self ):
        # Set the local repository directory containing the metadata files.
        tuf.conf.repository_directory = \
            self.tuf_configuration.repository_directory


# TODO: setup based on JSON file
def interpose( tuf_configuration ):
    if isinstance( tuf_configuration, TUFConfiguration ):
        TUFUpdater._tuf_configurations[
            tuf_configuration.hostname
        ] = tuf_configuration


def go_away():
    """Remove TUF interposition and restore previous urllib openers."""
    raise NotImplementedError


# http://docs.python.org/2/library/urllib.html#urllib._urlopener
urllib._urlopener = TUFancyURLOpener()
