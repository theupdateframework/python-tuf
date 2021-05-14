import json
import logging
import os
import shutil
import sys
import tempfile
import unittest

from tuf import exceptions
from tuf.api.metadata import Metadata
from tuf.client_rework.metadata_bundle import MetadataBundle

from tests import utils

logger = logging.getLogger(__name__)

class TestMetadataBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(dir=os.getcwd())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        # copy metadata to "local repo"
        shutil.copytree(
            os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata'),
            self.temp_dir,
            dirs_exist_ok=True
        )

    def test_local_load(self):

        # test loading all local metadata succesfully
        bundle = MetadataBundle(self.temp_dir)
        bundle.root_update_finished()
        bundle.load_local_timestamp()
        bundle.load_local_snapshot()
        bundle.load_local_targets()
        bundle.load_local_delegated_targets('role1','targets')
        bundle.load_local_delegated_targets('role2','role1')

        # Make sure loading metadata without its "dependencies" fails
        bundle = MetadataBundle(self.temp_dir)

        with self.assertRaises(RuntimeError):
            bundle.load_local_timestamp()
        bundle.root_update_finished()
        with self.assertRaises(RuntimeError):
            bundle.load_local_snapshot()
        bundle.load_local_timestamp()
        with self.assertRaises(RuntimeError):
            bundle.load_local_targets()
        bundle.load_local_snapshot()
        with self.assertRaises(RuntimeError):
            bundle.load_local_delegated_targets('role1','targets')
        bundle.load_local_targets()
        with self.assertRaises(RuntimeError):
            bundle.load_local_delegated_targets('role2','role1')
        bundle.load_local_delegated_targets('role1','targets')
        bundle.load_local_delegated_targets('role2','role1')

    def test_update(self):
        remote_dir = os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata')

        # remove all but root.json from local repo
        os.remove(os.path.join(self.temp_dir, "timestamp.json"))
        os.remove(os.path.join(self.temp_dir, "snapshot.json"))
        os.remove(os.path.join(self.temp_dir, "targets.json"))
        os.remove(os.path.join(self.temp_dir, "role1.json"))
        os.remove(os.path.join(self.temp_dir, "role2.json"))

        bundle = MetadataBundle(self.temp_dir)
        bundle.root_update_finished()

        # test local load failure, then updating metadata succesfully
        with self.assertRaises(exceptions.RepositoryError):
            bundle.load_local_timestamp()
        with open(os.path.join(remote_dir, "timestamp.json"), "rb") as f:
            bundle.update_timestamp(f.read())
        with open(os.path.join(remote_dir, "snapshot.json"), "rb") as f:
            bundle.update_snapshot(f.read())
        with open(os.path.join(remote_dir, "targets.json"), "rb") as f:
            bundle.update_targets(f.read())
        with open(os.path.join(remote_dir, "role1.json"), "rb") as f:
            bundle.update_delegated_targets(f.read(), "role1", "targets")
        with open(os.path.join(remote_dir, "role2.json"), "rb") as f:
            bundle.update_delegated_targets(f.read(), "role2", "role1")

        # test loading the metadata (that should now be locally available)
        bundle = MetadataBundle(self.temp_dir)
        bundle.root_update_finished()
        bundle.load_local_timestamp()
        bundle.load_local_snapshot()
        bundle.load_local_targets()
        bundle.load_local_delegated_targets('role1','targets')
        bundle.load_local_delegated_targets('role2','role1')

        # TODO test loading one version, then updating to new versions of each metadata

    def test_local_load_with_invalid_data(self):
        # Test root and one of the top-level metadata files

        with tempfile.TemporaryDirectory() as tempdir:
            # Missing root.json
            with self.assertRaises(exceptions.RepositoryError):
                MetadataBundle(tempdir)

            # root.json not a json file at all
            with open(os.path.join(tempdir, "root.json"), "w") as f:
                f.write("")
            with self.assertRaises(exceptions.RepositoryError):
                MetadataBundle(tempdir)

            # root.json does not validate
            md = Metadata.from_file(os.path.join(self.temp_dir, "root.json"))
            md.signed.version += 1
            md.to_file(os.path.join(tempdir, "root.json"))
            with self.assertRaises(exceptions.RepositoryError):
                MetadataBundle(tempdir)

            md.signed.version -= 1
            md.to_file(os.path.join(tempdir, "root.json"))
            bundle = MetadataBundle(tempdir)
            bundle.root_update_finished()

            # Missing timestamp.json
            with self.assertRaises(exceptions.RepositoryError):
                bundle.load_local_timestamp()

            # timestamp not a json file at all
            with open(os.path.join(tempdir, "timestamp.json"), "w") as f:
                f.write("")
            with self.assertRaises(exceptions.RepositoryError):
                bundle.load_local_timestamp()

            # timestamp does not validate
            md = Metadata.from_file(os.path.join(self.temp_dir, "timestamp.json"))
            md.signed.version += 1
            md.to_file(os.path.join(tempdir, "timestamp.json"))
            with self.assertRaises(exceptions.RepositoryError):
                bundle.load_local_timestamp()

            md.signed.version -= 1
            md.to_file(os.path.join(tempdir, "timestamp.json"))
            bundle.load_local_timestamp()

    def test_update_with_invalid_data(self):
        # Test on of the top level metadata files

        timestamp_md = Metadata.from_file(os.path.join(self.temp_dir, "timestamp.json"))

        # remove all but root.json from local repo
        os.remove(os.path.join(self.temp_dir, "timestamp.json"))
        os.remove(os.path.join(self.temp_dir, "snapshot.json"))
        os.remove(os.path.join(self.temp_dir, "targets.json"))
        os.remove(os.path.join(self.temp_dir, "role1.json"))
        os.remove(os.path.join(self.temp_dir, "role2.json"))

        bundle = MetadataBundle(self.temp_dir)
        bundle.root_update_finished()

        # timestamp not a json file at all
        with self.assertRaises(exceptions.RepositoryError):
            bundle.update_timestamp(b"")

        # timestamp does not validate
        timestamp_md.signed.version += 1
        data = timestamp_md.to_dict()
        with self.assertRaises(exceptions.RepositoryError):
            bundle.update_timestamp(json.dumps(data).encode())

        timestamp_md.signed.version -= 1
        data = timestamp_md.to_dict()
        bundle.update_timestamp(json.dumps(data).encode())


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
