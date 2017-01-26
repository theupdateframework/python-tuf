# conformance testing with specification

## tuf-compliant program
`test_updater.py` is a program that performs a software update and follows the
requirements outlined in TAP 7.  Note: It presently returns status code 5 (for
slow retrieval error).  This is a WIP.

```Bash
$ python test_updater.py --file file1.txt --repo http://localhost:8001 --metadata /tmp/metadata --targets /tmp/targets
Error: Download was too slow. Average speed: 0.0 bytes per second.

$ echo $?
5
```

## conformance testing the program

```Bash
TODO
```
