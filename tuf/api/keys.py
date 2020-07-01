# Borrowed from https://github.com/cnabio/signy/blob/afba301697df456b363790dc16483408b626a8af/scripts/in-toto/keys.py
# TODO:
# * Make a storage/provider-agnostic (e.g., filesystem, HSM) key management API, like securesystemslib.storage.

# Imports.

# 1st-party.
import os
import shutil

# 2nd-party.
from typing import Any, Dict, List, Optional

# 3rd-party.
from securesystemslib.interface import (
    generate_and_write_ed25519_keypair,
    get_password,
    import_ed25519_privatekey_from_file,
    import_ed25519_publickey_from_file,
)

# Utility classes.

class Threshold:

    def __init__(self, m: int = 1, n: int = 1):
        assert m > 0, f'{m} <= 0'
        assert n > 0, f'{n} <= 0'
        assert m <= n, f'{m} > {n}'
        self.m = m
        self.n = n

class Keypath:

    def __init__(self, private: str, public: str):
        assert os.path.isfile(private), private
        assert os.path.isfile(public), public
        self.private = private
        self.public = public

class Key:

    def __init__(self, path: str, obj: Any):
        self.path = path
        self.obj = obj

class Keypair:

    def __init__(self, private: Key, public: Key):
        self.private = private
        self.public = public

Keypairs = List[Keypair]

class Keyring:

    def __init__(self, threshold: Threshold, keypairs: Keypairs):
        if len(keypairs) >= threshold.m:
            logging.warning(f'{len(keypairs)} >= {threshold.m}')
        if len(keypairs) <= threshold.n:
            logging.warning(f'{len(keypairs)} <= {threshold.n}')
        self.threshold = threshold
        self.keypairs = keypairs

# Useful for securesytemslib.
KeyDict = Dict[str, Any]

# Utility functions.

def get_new_private_keypath(keystore_dir: str, rolename: str, i : int = 1) -> str:
    return os.path.join(keystore_dir, f'{rolename}_ed25519_key_{i}')

def get_public_keypath(private_keypath: str) -> str:
    # this is the tuf filename convention at the time of writing.
    return f'{private_keypath}.pub'

def get_private_keys_from_keyring(keyring: Keyring) -> KeyDict:
    privkeys = {}

    for keypair in keyring.keypairs:
        privkey = keypair.private.obj
        keyid = privkey['keyid']
        assert keyid not in privkeys
        privkeys[keyid] = privkey

    return privkeys

def get_public_keys_from_keyring(keyring: Keyring) -> KeyDict:
    pubkeys = {}

    for keypair in keyring.keypairs:
        pubkey = keypair.public.obj
        keyid = pubkey['keyid']
        assert keyid not in pubkeys
        pubkeys[keyid] = pubkey

    return pubkeys

def write_keypair(keystore_dir: str, rolename: str, i: int = 1, n: int = 1, passphrase: Optional[str] = None) -> Keypath:
    private_keypath = get_new_private_keypath(keystore_dir, rolename, i)
    assert not os.path.isfile(private_keypath)
    public_keypath = get_public_keypath(private_keypath)
    assert not os.path.isfile(public_keypath)

    # Make the keystore directory, WR-only by self, if not already there.
    os.makedirs(keystore_dir, mode=0o700, exist_ok=True)

    # FIXME: do not assume Ed25519
    generate_and_write_ed25519_keypair(private_keypath, password=passphrase)

    return Keypath(private_keypath, public_keypath)

def read_keypair(keypath: Keypath, passphrase: Optional[str] = None) -> Keypair:
    private_keypath = keypath.private
    private_key_obj = import_ed25519_privatekey_from_file(keypath.private, password=passphrase)
    private_key = Key(private_keypath, private_key_obj)

    # and its corresponding public key.
    public_keypath = keypath.public
    public_key_obj = import_ed25519_publickey_from_file(keypath.public)
    public_key = Key(public_keypath, public_key_obj)

    return Keypair(private_key, public_key)

def rename_keys_to_match_keyid(keystore_dir: str, keypair: Keypair) -> None:
    '''
    <Purpose>
        Rename public / private keys to match their keyid, so that it is easy
        to later find public keys on the repository, or private keys on disk.
        Also see https://github.com/theupdateframework/tuf/issues/573
    '''

    keyid = keypair.public.obj['keyid']

    # Rename the private key filename to match the keyid.
    assert os.path.exists(keystore_dir), keystore_dir
    new_private_keypath = os.path.join(keystore_dir, keyid)
    # Move the key to the new filename.
    assert not os.path.isfile(new_private_keypath), new_private_keypath
    shutil.move(keypair.private.path, new_private_keypath)
    # Update the path to the key.
    keypair.private.path = new_private_keypath

    # Rename the public key filename to match the keyid.
    new_public_keypath = get_public_keypath(new_private_keypath)
    # Move the key to the new filename.
    assert not os.path.isfile(new_public_keypath), new_public_keypath
    shutil.move(keypair.public.path, new_public_keypath)
    # Update the path to the key.
    keypair.public.path = new_public_keypath

def write_and_read_new_keys(keystore_dir: str, rolename: str, threshold: Threshold) -> Keyring:
    keypairs = []

    for i in range(1, threshold.n + 1):
        print(f'Writing key {i}/{threshold.n} for the "{rolename}" rolename...')
        passphrase = get_password(
            prompt='Please enter a NON-EMPTY passphrase to ENCRYPT this key: ',
            confirm=True
        )
        keypath = write_keypair(keystore_dir, rolename, i, threshold.n, passphrase)
        keypair = read_keypair(keypath, passphrase)
        # Rename the private and public keys to match the keyid instead.
        # Why? So that we know how to find keys later on repository / disk.
        rename_keys_to_match_keyid(keystore_dir, keypair)
        keypairs.append(keypair)
        print()

    return Keyring(threshold, tuple(keypairs))
