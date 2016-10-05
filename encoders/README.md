```Bash
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ ./encode-timestamp-metadata.py
```

Choosing CER based on this [guideline from X.690](https://en.wikipedia.org/wiki/X.690#BER.2C_CER_and_DER_compared):

> The canonical encoding rules is more suitable than the distinguished encoding
> rules if there is a need to encode values that are so large that they cannot
> readily fit into the available memory or it is necessary to encode and
> transmit a part of a value before the entire value is available.
