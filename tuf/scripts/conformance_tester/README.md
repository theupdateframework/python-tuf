# Implementation of TAP 7 (conformance testing)


`compliant_updater.py` is a program that performs a software update and
follows the requirements outlined in [TAP
7](https://github.com/theupdateframework/taps/blob/tap7/tap7.md).
It serves as an example of what software updaters must do to
be considered tuf-compliant.

Note: The example updater provided here is a work in progress and does
not yet fully comply with TAP 7.

`compliant_updater.py` presently exits with the following return values:

```
return value      outcome
------------      -------
0                 success
5                 slow retrieval error
```


## Verifying that an updater conforms with the specification
Note that most of the following attacks will be be managed by the conformance
tester.  For instance, although the slow retrieval server is manually started
below, users will not be required to do so once the conformance tool is
implemented.  The documentation here will be updated to remove
or add text as progress is made.

### Test for a normal update. `

Start the simple server, on port 30001, that faithfully serves metadata.

```Bash
$ python simple_server.py 30001
```

Attempt a normal update.

```Bash
$ python compliant_updater.py
  --repo http://localhost:30001
  --metadata /tmp/test_repository
  --targets /tmp/targets
  --file file1.txt

$ echo $?
0
```

### Test for detection of a slow retrieval attack
Start the slow retrieval server from the
`scripts/conformance_tester/tests/repository` directory, and indicate the port
number and mode of operation on the command-line options.

mode_1: Before sending any data, the server does nothing for a long time.

mode_2: Throttle the file by sending a character every few seconds.

```Bash
$ python slow_retrieval_server 8001 mode_1
```

Attempt an update from the slow retrieval server.  The tuf-compliant updater
should indicate that an error occurred and exit with a return value of 5.

```Bash
$ python compliant_updater.py --file file1.txt --repo http://localhost:8001 --metadata /tmp/metadata --targets /tmp/targets
Error: Download was too slow. Average speed: 0.0 bytes per second.

$ echo $?
5
```


## Running the conformance testing tool

```Bash
TODO
```
