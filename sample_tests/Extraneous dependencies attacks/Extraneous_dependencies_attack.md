# Extraneous Dependency Attack

An attacker tries to show some false dependencies of a file to the client, 
it indicates that a trusted file is dependent on some other file, and the client needs to download that dependency in order to install that trusted file. 
That dependency can be another trusted file which is vulnerable and can be exploited by the attacker. So an attacker, simply adds this false dependecy to some trusted
TUF metadata file but the client rejects this because of improper signature of the metadata file.

## Walkthrough 
Here, we add a trusted file on the repository as an extraneous dependency of another trusted file
by listing it in the project's metadata file. We add the file in the targets.json file which the client should reject when verifiying it's signature.


On the server side, we have the following files-

```Bash
$ cd repository/targets/
$ ls
# output - file1.txt file2.txt file3.txt file5.txt myproject
```
We add file5.txt(another trusted file on the repository) to the targets.json metadata file, 
```Bash
$ python
>>> import os
>>> from tuf.repository_tool import *
>>> dir=os.getcwd()
>>> role1_filepath = os.path.join(dir, 'metadata', 'targets.json')
>>> file5_filepath = os.path.join(dir, 'targets', 'file5.txt')
>>> length, hashes = securesystemslib.util.get_file_details(file5_filepath)
>>> role1_metadata = securesystemslib.util.load_json_file(role1_filepath)
>>> role1_metadata['signed']['targets']['file1.txt']['hashes'] = hashes
>>> role1_metadata['signed']['targets']['file1.txt']['length'] = length
>>> with open(role1_filepath, 'wt') as file_object:
...       json.dump(role1_metadata, file_object, indent=1, sort_keys=True)

```
On the client side, we remove the target and top level metadata files for fresh update,
```Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json" "tufrepo/metadata/current/snapshot.json"
```
Now when the client tries to download the file1.txt, it rejects the download because of improper signature 
```Bash
$ client.py --repo http://localhost:8001 --verbose 3 file1.txt
```
We get the follwoing error,
```Bash
>>> Update failed from http://localhost:8001/metadata/targets.json.
Failed to update 'targets.json' from all mirrors: {'http://localhost:8001/metadata/targets.json':   BadSignatureError('targets',)}
Metadata for 'targets' cannot be updated.
Error: No working mirror was found:
'localhost:8001': BadSignatureError('targets',)
```

