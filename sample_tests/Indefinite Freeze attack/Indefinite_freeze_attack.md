# Indefinite Freeze Attack

An attacker keeps on presenting the software update system to the client with the version he has already seen despite the newer versions available of the repository. 
It tries to trick the client in believing that there are no newer versions available and hence tries to freeze the client at that version. 
An attacker can be successful in preventing the client to see the latest repository but he won't be able to do so indefinitely
because the signed metadata has an "expiry" date associated with it, so the client will not trust the metadata post that expiry date.

## Walkthrough 
To simulate this attack the client initially downloads the latest version of the repository and then requests an update of the top
level metadata after the expiry date of the repository's metadata(we refrain from updating the server's repository after it's 
expiry date).

The metadata at server's repository has expired and is set to - Tue Apr 16 12:08:00 2019 (UTC).

At client side, we remove the target files and top level metadata, 
```Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json" "tufrepo/metadata/current/snapshot.json"
```
Then we request an update and get an error saying  `ExpiredMetadataError` and so the client rejects the download.
```Bash
$ client.py --repo http://localhost:8001 --verbose 5 file1.txt
Error: No working mirror was found:
'localhost:8001': ExpiredMetadataError("Metadata 'timestamp' expired on Tue Apr 16 12:08:00 2019 (UTC).",)
```

