import sys

from tuf.ngclient import Updater

print(f"Fetching metadata {sys.argv[1]} times:")
print(f"  metadata dir: {sys.argv[2]}")
print(f"  metadata url: {sys.argv[3]}")


for i in range(int(sys.argv[1])):
    try:
        u = Updater(metadata_dir=sys.argv[2], metadata_base_url=sys.argv[3])
        # file3.txt is delegated so we end up exercising all metadata load paths
        u.get_targetinfo("file3.txt")
    except OSError as e:
        sys.exit(f"Failed on iteration {i}: {e}")
