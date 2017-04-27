# Implementation of TAP 7 (conformance testing)


`test_updater.py` is a program that performs a software update and
follows the requirements outlined in [TAP
7](https://github.com/theupdateframework/taps/blob/tap7/tap7.md).
It serves as an example of what software updaters must do to
be considered tuf-compliant.

Note: The example updater provided here is a work in progress and does
not yet fully comply with TAP 7.

`test_updater.py` presently exits with the following return values:

```
return value      outcome
------------      -------
0                 success
5                 slow retrieval error
```


## Verifying that an updater conforms with the specification

### Test for detection of a slow retrieval attack
Start the slow retrieval server from the
scripts/conformance_tester/tests/repository directory, and indicate the port
number and mode of operation as command-line options.

mode_1: Before sending any data, the server does nothing for a long time.

mode_2: Throttle the file by sending a character every few seconds.

```Bash
$ python slow_retrieval_server 8001 mode_1
```

Attempt an update from the slow retrieval server.  The tuf-compliant updater
should indicate that an error occurred and exit with a return value of 5.

```Bash
$ python test_updater.py --file file1.txt --repo http://localhost:8001 --metadata /tmp/metadata --targets /tmp/targets
Error: Download was too slow. Average speed: 0.0 bytes per second.

$ echo $?
5
```

### Test for a normal update. `
TODO



## Running the conformance testing tool

```Bash
TODO
```
