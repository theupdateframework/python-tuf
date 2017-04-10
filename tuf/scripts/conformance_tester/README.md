# TAP 7 implementation

## Verifying that an updater conforms with the specification

### Updater that is tuf-compliant
`test_updater.py` is a program that performs a software update and follows the
requirements outlined in [TAP
7](https://github.com/theupdateframework/taps/blob/tap7/tap7.md).
Note: This is a WIP.

It presently exits with the following return values:

slow retrieval error: 5

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




### Running the conformance testing tool

```Bash
TODO
```
