import os.path
import tempfile
import types
import urlparse

from utility import Logger, InterpositionException


class InvalidConfiguration( InterpositionException ):
    """User configuration is invalid."""

    pass


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
        INVALID_TARGET_PATH = \
            "Invalid target path in {network_location}!"

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

        # Parse TUF server repository mirrors.
        repository_mirrors = configuration[ "repository_mirrors" ]
        repository_mirror_network_locations = set()

        for repository_mirror in repository_mirrors:
            mirror_configuration = repository_mirrors[ repository_mirror ]
            try:
                url_prefix = mirror_configuration[ "url_prefix" ]
                parsed_url = urlparse.urlparse( url_prefix )
                mirror_hostname = parsed_url.hostname
                mirror_port = parsed_url.port or 80
                mirror_netloc = "{hostname}:{port}".format(
                    hostname = mirror_hostname,
                    port = mirror_port
                )

                # No single-edge cycle in interposition.
                # GOOD: A -> { A:XYZ, ... }
                # BAD: A -> { A, ... }
                assert not ( mirror_hostname == hostname and mirror_port == port )

                # Unique network location over repository mirrors.
                # GOOD: A -> { A:X, A:Y, ... }
                # BAD: A -> { A:X, A:X, ... }
                assert mirror_netloc not in repository_mirror_network_locations

                # Remember this mirror's network location to check the rest of the mirrors.
                repository_mirror_network_locations.add( mirror_netloc )
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
            try:
                # target_path: { "regex_with_groups", "target_with_group_captures" }
                # e.g. { ".*(/some/directory)/$", "{0}/index.html" }
                assert isinstance( target_path, types.DictType )
                assert len( target_path ) == 1
            except:
                error_message = INVALID_TARGET_PATH.format(
                    network_location = network_location
                )
                Logger.error( error_message )
                raise InvalidConfiguration( error_message )

        # If everything passes, we return a Configuration.
        return Configuration(
            hostname,
            port,
            repository_directory,
            repository_mirrors,
            target_paths
        )
