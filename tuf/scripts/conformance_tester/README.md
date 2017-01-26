# Conformance testing with specification

## Program that performs update and follows TAP 7 requirements (test_updater.py)
Note: Presently returns status code 5 (for slow retrieval error).  This is a WIP.

```Bash
$ python test_updater.py --file file1.txt --repo http://localhost:8001 --metadata /tmp/metadata --targets /tmp/targets
Error: Download was too slow. Average speed: 0.0 bytes per second.

$ echo $?
5
```

## conformance_tester.py

```Bash
TODO
```
