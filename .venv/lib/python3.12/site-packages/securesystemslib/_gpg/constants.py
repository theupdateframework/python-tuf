"""
<Module Name>
  constants.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  aggregates all the constant definitions and lookup structures for signature
  handling
"""

from __future__ import annotations

import functools
import logging
import os
import shlex
import subprocess

log = logging.getLogger(__name__)

GPG_TIMEOUT = 10


@functools.lru_cache(maxsize=3)
def is_available_gnupg(gnupg: str, timeout: int | None = None) -> bool:
    """Returns whether gnupg points to a gpg binary."""
    if timeout is None:
        timeout = GPG_TIMEOUT

    gpg_version_cmd = shlex.split(f"{gnupg} --version")
    try:
        subprocess.run(  # noqa: S603
            gpg_version_cmd,
            capture_output=True,
            timeout=timeout,
            check=True,
        )
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


GPG_ENV_COMMAND = os.environ.get("GNUPG")
GPG2_COMMAND = "gpg2"
GPG1_COMMAND = "gpg"


def gpg_command() -> str:
    """Returns command to run GPG, or ``""``` if not found)."""
    # By default, we allow providing GPG client through the environment
    # assuming gpg2 as default value and test if exists. Otherwise, we assume gpg
    # exists.
    if GPG_ENV_COMMAND:
        if is_available_gnupg(GPG_ENV_COMMAND):
            return GPG_ENV_COMMAND
    elif is_available_gnupg(GPG2_COMMAND):
        return GPG2_COMMAND
    elif is_available_gnupg(GPG1_COMMAND):
        return GPG1_COMMAND
    return ""


def have_gpg() -> bool:
    """Returns True if a gpg_command is available."""
    return bool(gpg_command())


def gpg_version_command() -> list[str]:
    """Returns the command to get the current GPG version."""
    return shlex.split(f"{gpg_command()} --version")


FULLY_SUPPORTED_MIN_VERSION = "2.1.0"
NO_GPG_MSG = (
    f"GPG support requires a GPG client. 'gpg2' or 'gpg' with version "
    f"{FULLY_SUPPORTED_MIN_VERSION} or newer is fully supported."
)


def gpg_sign_command(keyarg: str, homearg: str) -> list[str]:
    """Returns the command to use GPG to sign STDIN."""
    return shlex.split(
        f"{gpg_command()} --detach-sign --digest-algo SHA256 {keyarg} {homearg}"
    )


def gpg_export_pubkey_command(homearg: str, keyid: str) -> list[str]:
    """Returns the GPG command to export a public key."""
    return shlex.split(f"{gpg_command()} {homearg} --export {keyid}")


# See RFC4880 section 4.3. Packet Tags for a list of all packet types The
# relevant packets defined below are described in sections 5.2 (signature),
# 5.5.1.1 (primary pubkey) and 5.5.1.2 (pub subkey), 5.12 (user id) and 5.13
# (user attribute)
PACKET_TYPE_SIGNATURE = 0x02
PACKET_TYPE_PRIMARY_KEY = 0x06
PACKET_TYPE_USER_ID = 0x0D
PACKET_TYPE_USER_ATTR = 0x11
PACKET_TYPE_SUB_KEY = 0x0E


# See sections 5.2.3 (signature) and 5.5.2 (public key) of RFC4880
SUPPORTED_SIGNATURE_PACKET_VERSIONS = {0x04}
SUPPORTED_PUBKEY_PACKET_VERSIONS = {0x04}

# The constants for hash algorithms are taken from section 9.4 of RFC4880.
SHA1 = 0x02
SHA256 = 0x08
SHA512 = 0x0A

# See section 5.2.1 of RFC4880
SIGNATURE_TYPE_BINARY = 0x00
SIGNATURE_TYPE_SUB_KEY_BINDING = 0x18
SIGNATURE_TYPE_CERTIFICATES = {0x10, 0x11, 0x12, 0x13}

# See section 5.2.3.4 (Signature Creation Time) of RFC4880
SIG_CREATION_SUBPACKET = 0x02
# See section 5.2.3.5. (Issuer) of RFC4880
PARTIAL_KEYID_SUBPACKET = 0x10
# See section 5.2.3.6 (Key Expiration Time) of RFC4880
KEY_EXPIRATION_SUBPACKET = 0x09
# See section 5.2.3.19 (Primary User ID) of RFC4880
PRIMARY_USERID_SUBPACKET = 0x19
# See section 5.2.3.28. (Issuer Fingerprint) of rfc4880bis-06
FULL_KEYID_SUBPACKET = 0x21

GPG_HASH_ALGORITHM_STRING = "pgp+SHA2"
