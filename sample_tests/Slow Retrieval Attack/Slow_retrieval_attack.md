# Slow Retrieval Attack
Here an attacker tries to serve the client with very slow stream of data so that the client would never be able to update its repository.
TUF provides resistance to such kind of attack, as it sets two attributes (`MIN_AVERAGE_DOWNLOAD_SPEED` and `CHUNK_SIZE`) 
in the file  `tuf/settings.py`, which detects when slow stream data is being served and raises this exception `SlowRetrievalError`.

## Walkthrough
To simulate this attack, we fist set the attributes in the file `tuf/settings.py` at the client side to the following values, 

```Bash
MIN_AVERAGE_DOWNLOAD_SPEED = 5 and CHUNK_SIZE = 5
```

Now, on the server side, run the following script to spawn the server to respond with very slow stream, 

```Bash
$ python slow_retrieval_server.py 8002 mode_2
```

Now at client side, try to request for an update by, 

```Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json" "tufrepo/metadata/current/snapshot.json"
```

```Bash
$ client.py --repo http://localhost:8002 file2.txt
```
We get the following error, 
```Bash
Could not download URL: 'http://localhost:8002/metadata/root.json'
tuf.exceptions.SlowRetrievalError: Download was too slow. Average speed: 1.991938457761411 bytes per second.
Failed to update 'root.json' from all mirrors: {'http://localhost:8002/metadata/root.json': SlowRetrievalError()}
Error: No working mirror was found: 'localhost:8002': SlowRetrievalError()
```


