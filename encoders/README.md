```Bash
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ ./encode-timestamp-metadata.py
```

All metadata are encoded using BER for simplicity in decoding.
