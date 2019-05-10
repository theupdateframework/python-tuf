# Wrong Software Installation
Here an attacker tries to respond with a trusted file that the client hasn't asked for. The client won't accept the download because
of trusted TUF metadata files which tries to verify the hash of the file being sent and when it doesn't match, it raises `BadHashError` error.

## Walkthrough
To simulate this attack, when the client requests for some file, say file2.txt, the attacker serves file3.txt framed as file2.txt thus 
tricking the client to install file3.txt. 

So at the server side, make the backup of file2.txt, 

```Bash
mv file2.txt file2.txt.bckup 
```
And rename file3.txt to file2.txt,

```Bash
mv file3.txt file2.txt
```
Now request for fresh update at client side and ask for file2.txt, 

```Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json" "tufrepo/metadata/current/snapshot.json"
```
```Bash
mv file3.txt file2.txt
```
We get the following error, 
```Bash
$ client.py --repo http://localhost:8001 --verbose 5 file2.txt
Error: No working mirror was found: 'localhost:8001': BadHashError('67ee5478eaadb034ba59944eb977797b49ca6aa8d3574587f36ebcbeeb65f70e', '94f6e58bd04a4513b8301e75f40527cf7610c66d1960b26f6ac2e743e108bdac')
```
It verifies the hash of the file being served against the hash given by the trusted TUF metadata file, which obviously doesn't match and hence raises an error.
