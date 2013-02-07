import os.path
import tempfile
import tuf.client.updater
import tuf.conf
import urllib
import urlparse


class TUFancyURLOpener( urllib.FancyURLopener ):
    def __init__( self, *args, **kwargs ):
        # cannot use super() with old-style class
        # http://stackoverflow.com/a/9719731
        urllib.FancyURLopener.__init__( self, *args, **kwargs )

        self.__repository_mirrors = kwargs.get( "repository_mirrors", {} )

        # Create repository object using given repository mirrors.
        self.__tuf_updater = tuf.client.updater.Updater(
            "tuf_updater",
            self.__repository_mirrors
        )

    # TODO: replicate complete behaviour of urllib.URLopener.retrieve
    def retrieve( self, url, filename = None, reporthook = None, data = None ):
        def mkdtemp( target_filepath ):
            destination_directory = tempfile.mkdtemp()
            filename = os.path.join( destination_directory, target_filepath )
            return destination_directory, filename

        # TODO: set valid headers
        headers = {}
        # get target_filepath by parsing url
        parsed_url = urlparse.urlparse( url )
        # TUF assumes that target_filepath does not begin with a '/'
        target_filepath = parsed_url.path.lstrip( '/' )

        # if filename does not exist, then we use a temporary directory
        if filename is None:
            destination_directory, filename = mkdtemp( target_filepath )
        else:
            if filename.endswith( target_filepath ):
                last_index = filename.rfind( target_filepath )
                destination_directory = filename[ : last_index ]
                if not os.path.isdir( destination_directory ):
                    destination_directory, filename = mkdtemp( target_filepath )
            else:
                destination_directory, filename = mkdtemp( target_filepath )

        self.__tuf_updater.refresh()

        targets = [ self.__tuf_updater.target( target_filepath ) ]
        updated_targets = self.__tuf_updater.updated_targets(
            targets,
            destination_directory
        )

        for target in updated_targets:
            self.__tuf_updater.download_target( target, destination_directory )

        return filename, headers


def initialize( repository_directory, repository_mirrors ):
    # Set the local repository directory containing the metadata files.
    tuf.conf.repository_directory = repository_directory

    # http://docs.python.org/2/library/urllib.html#urllib._urlopener
    urllib._urlopener = TUFancyURLOpener(
        repository_mirrors = repository_mirrors
    )
