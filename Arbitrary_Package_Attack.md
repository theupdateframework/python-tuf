# Arbitrary Package Attack

Here, an attacker tries to install anything they want on the client system. 
That is, an attacker can provide arbitrary files in response to download requests and the files will not be detected as illegitimate.

## Walkthrough 
In order to simulate this attack, on the server side run the following commands -

```Bash
$ mv 'repository/targets/file1.txt' 'repository/targets/file1.txt.bckup'
$ echo 'bad_target' > 'repository/targets/file1.txt'
```

On the client side to perform fresh update, we remove the timestamp file by, 

``` Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json"
```
then try to request for the file `file1.txt` by- 

``` Bash
$ client.py --repo http://localhost:8001 --verbose 3 file1.txt
```
We get the following response when trying to perform the update, 

``` Bash
Update failed from http://localhost:8001/targets/file1.txt.

securesystemslib.exceptions.BadHashError: Observed hash ('f569179171c86aa9ed5e8b1d6c94dfd516123189568d239ed57d818946aaabe7') != expected hash ('ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8')
Failed to update 'file1.txt' from all mirrors: {'http://localhost:8001/targets/file1.txt': BadHashError('ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8', 'f569179171c86aa9ed5e8b1d6c94dfd516123189568d239ed57d818946aaabe7')}
Error: No working mirror was found:
  'localhost:8001': BadHashError('ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8', 'f569179171c86aa9ed5e8b1d6c94dfd516123189568d239ed57d818946aaabe7')
```
As the contents of the file1.txt were changed by attacker, the generated hash doesn't match with the hash given in the metadata file `targets.json`, so client gets `BadHashError` when requesting this file 

Now restore the original file at server side, by
```Bash
$ mv 'repository/targets/file1.txt.backup' 'repository/targets/file1.txt'
```
