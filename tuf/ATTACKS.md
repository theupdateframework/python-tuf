# Demonstrate protection against malicious updates

## Table of Contents ##
- [Blocking Malicious Updates](#blocking-malicious-updates)
  - [Arbitrary Package Attack](#arbitrary-package-attack)
  - [Rollback Attack](#rollback-attack)
  - [Indefinite Freeze Attack](#indefinite-freeze-attack)
  - [Endless Data Attack](#endless-data-attack)
  - [Compromised Key Attack](#compromised-key-attack)
  - [Slow Retrieval Attack](#slow-retrieval-attack)
- [Conclusion](#conclusion)

## Blocking Malicious Updates ##
TUF protects against a number of attacks, some of which include rollback,
arbitrary package, and mix and match attacks.  We begin this document on
blocking malicious updates by demonstrating how the client rejects a target
file downloaded from the software repository that doesn't match what is listed
in TUF metadata.

The following demonstration requires and operates on the repository created in
the [repository management
tutorial](https://github.com/theupdateframework/tuf/blob/develop/tuf/README.md).

### Arbitrary Package Attack ###
In an arbitrary package attack, an  attacker installs anything they want on the
client system. That is, an attacker can provide arbitrary files in response to
download requests and the files will not be detected as illegitimate.  We
simulate an arbitrary package attack by creating a "malicious" target file
that our client attempts to fetch.

```Bash
$ mv 'repository/targets/file2.txt' 'repository/targets/file2.txt.backup'
$ echo 'bad_target' > 'repository/targets/file2.txt'
```

We next reset our local timestamp (so that a new update is prompted), and
the target files previously downloaded by the client.
```Bash
$ rm -rf "client/targets/" "client/metadata/current/timestamp.json"
```

The client now performs an update and should detect the invalid target file...
Note: The following command should be executed in the "client/" directory.
```Bash
$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  localhost:8001: BadHashError()
```

The log file (tuf.log) saved to the current working directory contains more
information on the update procedure and the cause of the BadHashError.

```Bash
...

BadHashError: Observed
hash ('f569179171c86aa9ed5e8b1d6c94dfd516123189568d239ed57d818946aaabe7') !=
expected hash (u'67ee5478eaadb034ba59944eb977797b49ca6aa8d3574587f36ebcbeeb65f70e')
[2016-10-20 19:45:16,079 UTC] [tuf.client.updater] [ERROR] [_get_file:1415@updater.py]
Failed to update /file2.txt from all mirrors: {u'http://localhost:8001/targets/file2.txt': BadHashError()}
```

Note: The "malicious" target file should be removed and the original file2.txt
restored, otherwise the following examples will fail with BadHashError
exceptions:

```Bash
$ mv 'repository/targets/file2.txt.backup' 'repository/targets/file2.txt'
```

### Indefinite Freeze Attack ###
In an indefinite freeze attack, an attacker continues to present a software
update system with the same files the client has already seen. The result is
that the client does not know that new files are available.   Although the
client would be unable to prevent an attacker or compromised repository from
feeding it stale metadata, it can at least detect when an attacker is doing so
indefinitely.  The signed metadata used by TUF contains an "expires" field that
indicates when metadata should no longer be trusted.

In the following simulation, the client first tries to perform an update.

```Bash
$ python basic_client.py --repo http://localhost:8001
```

According to the logger (`tuf.log` file in the current working directory),
everything appears to be up-to-date.  The remote server should also show that
the client retrieved only the timestamp.json file.  Let's suppose now that an
attacker continues to feed our client the same stale metadata.  If we were to
move the time to a future date that would cause metadata to expire, the TUF
framework should raise an exception or error to indicate that the metadata
should no longer be trusted.

```Bash
$ sudo date -s '2080-12-25 12:34:56'
Wed Dec 25 12:34:56 EST 2080

$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  u'localhost:8001': ExpiredMetadataError(u"Metadata u'root' expired on Tue Jan  1 00:00:00 2030 (UTC).",)
```

Note: Reset the date to continue with the rest of the attacks.


### Rollback Attack ###
In a rollback attack, an attacker presents a software update system with older
files than those the client has already seen, causing the client to use files
older than those the client knows about.  We begin this example by saving the
current version of the Timestamp file available on the repository.  This saved
file will later be served to the client to see if it is rejected.  The client
should not accept versions of metadata that is older than previously trusted.

Navigate to the directory containing the server's files and save the current
timestamp.json to a temporary location:
```Bash
$ cp repository/metadata/timestamp.json /tmp
```

We should next generate a new Timestamp file on the repository side.
```Bash
$ python
>>> from tuf.repository_tool import *
>>> repository = load_repository('repository')
>>> repository.timestamp.version
1
>>> repository.timestamp.version = 2
>>> repository.dirty_roles()
Dirty roles: [u'timestamp']
>>> private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key")
Enter a password for the encrypted RSA file (/path/to/keystore/timestamp_key):
>>> repository.timestamp.load_signing_key(private_timestamp_key)
>>> repository.write('timestamp')

$ cp repository/metadata.staged/* repository/metadata
```

Now start the HTTP server from the directory containing the 'repository'
subdirectory.
```Bash
$ python -m SimpleHTTPServer 8001
```

And perform an update so that the client retrieves the updated timestamp.json.
```Bash
$ python basic_client.py --repo http://localhost:8001
```

Finally, move the previous timestamp.json file to the current live repository
and have the client try to download the outdated version.  The client should
reject it!
```Bash
$ cp /tmp/timestamp.json repository/metadata/
$ cd repository; python -m SimpleHTTPServer 8001
```

On the client side, perform an update...
```Bash
$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  u'localhost:8001': ReplayedMetadataError()
```

The tuf.log file contains more information about the ReplayedMetadataError
exception and update process.  Please reset timestamp.json to the latest
version, which can be found in the 'repository/metadata.staged' subdirectory.

```Bash
$ cp repository/metadata.staged/timestamp.json repository/metadata
```


### Endless Data Attack ###
In an endless data attack, an attacker responds to a file download request with
an endless stream of data, causing harm to clients (e.g., a disk partition
filling up or memory exhaustion).  In this simulated attack, we append extra
data to one of the target files available on the software repository.  The
client should only download the exact number of bytes it expects for a
requested target file (according to what is listed in trusted TUF metadata).

```Bash
$ cp repository/targets/file1.txt /tmp
$ python -c "print 'a' * 1000" >> repository/targets/file1.txt
```

Now delete the local metadata and target files on the client side so
that remote metadata and target files are downloaded again.
```Bash
$ rm -rf client/targets/
$ rm client/metadata/current/snapshot.json* client/metadata/current/timestamp.json*
```

Lastly, perform an update to verify that the file1.txt is downloaded up to the
expected size, and no more.  The target file available on the software
repository does contain more data than expected, though.

```Bash
$ python basic_client.py --repo http://localhost:8001
```

At this point, part of the "file1.txt" file should have been fetched.  That is,
up to 31 bytes of it should have been downloaded, and the rest of the maliciously
appended data ignored.  If we inspect the logger, we'd discover the following:

```Bash
[2016-10-06 21:37:39,092 UTC] [tuf.download] [INFO] [_download_file:235@download.py]
Downloading: u'http://localhost:8001/targets/file1.txt'

[2016-10-06 21:37:39,145 UTC] [tuf.download] [INFO] [_check_downloaded_length:610@download.py]
Downloaded 31 bytes out of the expected 31 bytes.

[2016-10-06 21:37:39,145 UTC] [tuf.client.updater] [INFO] [_get_file:1372@updater.py]
Not decompressing http://localhost:8001/targets/file1.txt

[2016-10-06 21:37:39,145 UTC] [tuf.client.updater] [INFO] [_check_hashes:778@updater.py]
The file's sha256 hash is correct: 65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da
```

Indeed, the sha256 sum of the first 31 bytes of the "file1.txt" available
on the repository should match to what is trusted.  The client did not
downloaded the appended data.

Note: Restore file1.txt

```Bash
$ cp /tmp/file1.txt repository/targets/
```


### Compromised Key Attack ###
An attacker who compromise less than a given threshold of keys is limited in
scope. This includes relying on a single online key (such as only being
protected by SSL) or a single offline key (such as most software update systems
use to sign files).  In this example, we attempt to sign a role file with
less-than-a-threshold number of keys.  A single key (suppose this is a
compromised key) is used to demonstrate that roles must be signed with the
total number of keys required for the role.  In order to compromise a role, an
attacker would have to compromise a threshold of keys.  This approach of
requiring a threshold number of signatures provides compromise resilience.

Let's attempt to sign a new snapshot file with a less-than-threshold number of
keys.  The client should reject the partially signed snapshot file served by
the repository (or imagine that it is a compromised software repository).

```Bash
$ python
>>> from tuf.repository_tool import *
>>> repository = load_repository('repository')
>>> version = repository.root.version
>>> repository.root.version = version + 1
>>> private_root_key = import_rsa_privatekey_from_file("keystore/root_key", password="password")
>>> repository.root.load_signing_key(private_root_key)
>>> private_root_key2 = import_rsa_privatekey_from_file("keystore/root_key2", password="password")
>>> repository.root.load_signing_key(private_root_key2)

>>> repository.snapshot.version = 8
>>> repository.snapshot.threshold = 2
>>> private_snapshot_key = import_rsa_privatekey_from_file("keystore/snapshot_key", password="password")
>>> repository.snapshot.load_signing_key(private_snapshot_key)

>>> repository.timestamp.version = 8
>>> private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key", password="password")
>>> repository.timestamp.load_signing_key(private_timestamp_key)

>>> repository.write('root')
>>> repository.write('snapshot')
>>> repository.write('timestamp')

$ cp repository/metadata.staged/* repository/metadata
```

The client now attempts to refresh the top-level metadata and the
partially written snapshot.json, which should be rejected.

```Bash
$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  u'localhost:8001': BadSignatureError()
```


### Slow Retrieval Attack ###
In a slow retrieval attack, an attacker responds to clients with a very slow
stream of data that essentially results in the client never continuing the
update process.  In this example, we simulate a slow retrieval attack by
spawning a server that serves data at a slow rate to our update client data.
TUF should not be vulnerable to this attack, and the framework should raise an
exception or error when it detects that a malicious server is serving it data
at a slow enough rate.

We first spawn the server that slowly streams data to the client.  The
'slow_retrieval_server.py' module (can be found in the tests/ directory of the
source code) should be copied over to the server's 'repository/' directory from
which to launch it.

```Bash
# Before launching the slow retrieval server, copy 'slow_retrieval_server.py'
# to the 'repository/' directory and run it from that directory as follows:
$ python slow_retrieval_server.py 8002 mode_2
```

The client may now make a request to the slow retrieval server on port 8002.
However, before doing so, we'll reduce (for the purposes of this demo) the
minimum average download rate allowed and download chunk size.  Open the
'settings.py' module and set MIN_AVERAGE_DOWNLOAD_SPEED = 5 and CHUNK_SIZE = 1.
This should make it so that the client detects the slow retrieval server's
delayed streaming.

```Bash
$ python basic_client.py --verbose 1 --repo http://localhost:8002
Error: No working mirror was found:
  u'localhost:8002': SlowRetrievalError()
```

The framework should detect the slow retrieval attack and raise a
SlowRetrievalError exception to the client application.


## Conclusion ##
These are just some of the attacks that TUF provides protection against.  For
more attacks and updater weaknesses, please see the
[Security](https://github.com/theupdateframework/tuf/blob/develop/docs/SECURITY.md)
page.
