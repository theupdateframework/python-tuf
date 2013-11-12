## Create TUF Repository

### Keys

#### Create RSA Keys
```python
from libtuf import *


# Generate and write the first of two root keys for the repository.
# The following function creates an RSA key pair, where the private key is saved to
# “path/to/root_key” and the public key to “path/to/root_key.pub”.
generate_and_write_rsa_keypair("path/to/root_key",bits=2048,password="password")

#if thhe key length is unspecified, it defaults to 3072 bits. A length of then 
#than 2048 bits prints an error mesage. A password may be supplied as an 
#argument, otherwise a user prompt is presented
generate_and_write_rsa_keypair("path/to/root_key2")
>>> Enter a password for the RSA key:
>>> Confirm:
```
The following four files should now exist:

1. root_key
2. root_key.pub
3. root_key2
4. root_key2.pub
