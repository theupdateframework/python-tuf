# Endless Data Attack

Here an attacker tries to send an endless stream of data when a client requests for a certain file trying to cause harm to the client by disk partition filling up or memory exhaustion. 
In such a case, the client must accept exactly the same number of bytes of that file as mentioned by a trusted TUF metadata file, after that limit it just cancels the download and doesn't accept the extra data.

## Walkthrough 

On the server side, we first take backup of exisitng trusted target file-

```Bash
$ cp repository/targets/file3.txt /tmp
```
Now we append some extra data to the trusted file, 
```Bash
$ python -c "print('a' * 1000") >> repository/targets/file3.txt
```
At client side, we remove the target and top level metadata files for fresh update,
```Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json" "tufrepo/metadata/current/snapshot.json"
```
Now the client tries to download the file, 
```Bash
$ client.py --repo http://localhost:8001 --verbose 3 file3.txt
```
The file gets downloaded but only till the size as given in the 'length' attribute in the targets.json for this file, 
the extra data appended to the file is not available in the file downloaded by the client

Also, the hash of the file downloaded by the client should match the hash given for that file by the targets.json file else it won't download anything.

Now in order to download the valid file at client side, get the original target file back at the server side,
```Bash
$ cp /tmp/file3.txt repository/targets/
```



