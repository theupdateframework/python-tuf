"""
<Program Name>
  exceptions.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Dec 8, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Define Exceptions used in the gpg package. Following the practice from
  securesystemslib the names chosen for exception classes should end in
  'Error' (except where there is a good reason not to).

"""

import datetime


class PacketParsingError(Exception):
    pass


class KeyNotFoundError(Exception):
    pass


class PacketVersionNotSupportedError(Exception):
    pass


class SignatureAlgorithmNotSupportedError(Exception):
    pass


class KeyExpirationError(Exception):
    def __init__(self, key):
        super().__init__()
        self.key = key

    def __str__(self):
        creation_time = datetime.datetime.utcfromtimestamp(self.key["creation_time"])
        expiration_time = datetime.datetime.utcfromtimestamp(
            self.key["creation_time"] + self.key["validity_period"]
        )
        validity_period = expiration_time - creation_time

        return (
            "GPG key '{}' created on '{:%Y-%m-%d %H:%M} UTC' with validity "
            "period '{}' expired on '{:%Y-%m-%d %H:%M} UTC'.".format(
                self.key["keyid"],
                creation_time,
                validity_period,
                expiration_time,
            )
        )
