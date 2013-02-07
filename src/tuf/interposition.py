import os.path
import tempfile
import tuf.client.updater
import tuf.conf
import types
import urllib
import urlparse


# hostname: str -> tuf_configuration: TUFConfiguration
_tuf_configurations = {}


class TUFConfiguration( object ):
    def __init__( self, hostname, repository_directory, repository_mirrors ):
        self.hostname = hostname
        self.repository_directory = repository_directory
        self.repository_mirrors = repository_mirrors
        self.tempdir = tempfile.mkdtemp()

        # must switch context before instantiating updater
        # because updater depends on some module (tuf.conf) variables
        self.switch_context()
        self.updater = tuf.client.updater.Updater(
            hostname,
            repository_mirrors
        )

    def make_tempfile( self, target_filepath ):
        return self.tempdir, os.path.join( self.tempdir, target_filepath )

    def switch_context( self ):
        # Set the local repository directory containing the metadata files.
        tuf.conf.repository_directory = self.repository_directory


class TUFancyURLOpener( urllib.FancyURLopener ):
    # TODO: replicate complete behaviour of urllib.URLopener.open
    def __tuf_open( self, parsed_url, tuf_configuration, data = None ):
        def getcode( self ):
            return 200

        def geturl( self ):
            return fullurl

        def info( self ):
            raise NotImplementedError

        # get a file-like object for free
        filename, headers = self.__tuf_retrieve(
            parsed_url,
            tuf_configuration,
            data = data
        )

        tempfile = TUFile( filename )
        # extend tempfile with info(), getcode(), geturl()
        # http://docs.python.org/2/library/urllib.html#urllib.urlopen
        # http://stackoverflow.com/a/2982
        tempfile.getcode = types.MethodType( getcode, tempfile )
        tempfile.geturl = types.MethodType( geturl, tempfile )
        tempfile.info = types.MethodType( info, tempfile )

        return tempfile

    # TODO: replicate complete behaviour of urllib.URLopener.retrieve
    def __tuf_retrieve(
        self,
        parsed_url,
        tuf_configuration,
        filename = None,
        reporthook = None,
        data = None
    ):
        # TODO: set valid headers
        headers = {}
        # TUF assumes that target_filepath does not begin with a '/'
        target_filepath = parsed_url.path.lstrip( '/' )

        # if filename does not exist, then we use a temporary directory
        if filename is None:
            destination_directory, filename = tuf_configuration.make_tempfile(
                target_filepath
            )
        else:
            # TODO: think later about best course of action for filename
            if filename.endswith( target_filepath ):
                last_index = filename.rfind( target_filepath )
                destination_directory = filename[ : last_index ]
                if not os.path.isdir( destination_directory ):
                    destination_directory, filename = \
                        tuf_configuration.make_tempfile( target_filepath )
            else:
                destination_directory, filename = \
                    tuf_configuration.make_tempfile( target_filepath )

        tuf_configuration.switch_context()
        tuf_configuration.updater.refresh()

        targets = [ tuf_configuration.updater.target( target_filepath ) ]
        updated_targets = tuf_configuration.updater.updated_targets(
            targets,
            destination_directory
        )

        for target in updated_targets:
            tuf_configuration.updater.download_target(
                target,
                destination_directory
            )

        return filename, headers

    def open( self, fullurl, data = None ):
        parsed_url = urlparse.urlparse( fullurl )
        tuf_configuration = _tuf_configurations.get( parsed_url.hostname )

        if tuf_configuration is None:
            return urllib.URLopener.open( self, fullurl, data = data )
        else:
            return self.__tuf_open( parsed_url, tuf_configuration, data = data )

    def retrieve( self, url, filename = None, reporthook = None, data = None ):
        parsed_url = urlparse.urlparse( url )
        tuf_configuration = _tuf_configurations.get( parsed_url.hostname )

        if tuf_configuration is None:
            return urllib.URLopener.retrieve(
                self,
                url,
                filename = filename,
                reporthook = reporthook,
                data = data
            )
        else:
            return self.__tuf_retrieve(
                parsed_url,
                tuf_configuration,
                filename = filename,
                reporthook = reporthook,
                data = data
            )


class TUFile( file ):
    pass


def map( tuf_configuration ):
    global _tuf_configurations

    assert isinstance( tuf_configuration, TUFConfiguration )
    # TODO: clean up after old configurations
    _tuf_configurations[ tuf_configuration.hostname ] = tuf_configuration


# http://docs.python.org/2/library/urllib.html#urllib._urlopener
urllib._urlopener = TUFancyURLOpener()
