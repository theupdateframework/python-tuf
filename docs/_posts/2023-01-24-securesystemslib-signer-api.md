---
title: New signing API
author: Jussi Kukkonen
---

> Things should be made as simple as possible – but no simpler.
>
> _- sometimes attributed to Einstein_

I believe the rule of thumb above stands on its own merit when it comes to software systems so the credibility of the attribution is not important (it's also possible that we should not take software design advice from a physicist).

This post is about the PKI signing API provided by [Securesystemslib](https://github.com/secure-systems-lab/securesystemslib/) and used by applications built with python-tuf. It's an example of how keeping a thing too simple can actually make it more complex.

## The problem with private keys

 The original `securesystemslib.keys` module is based on the assumption that there are three distinct steps in the lifetime of a private-public keypair in a system like a TUF repository:
1. Generate private and public key
1. Sign with private key
1. Verify signature with public key

This all seems logical on paper but in practice implementing signing for different underlying technologies (like online key vaults and Yubikeys) forces the API surface to grow linearly, and still requires the applications to also be aware of all the different signing technologies and their configuration. It was clear that something was wrong.

## New signer module

In reality there are four distinct events during the lifetime of a signing key. All of these steps can happen on different systems, with different operators and different access to the underlying signing system:
1. Generate private and public keys – _This may happen in securesystemslib but also in an online key vault configuration UI or the Yubikey command line tool_
1. Store the public key _and the information needed to access the private key_
1. Sign using the information stored in step 2
1. Verify signature with public key

Securesystemslib 0.26 introduces an improved signer API that recognizes this process complexity – and in turn makes managing and signing with keys simpler in practical application development. There are three main changes, all in the `securesystemslib.signer` module that defines Signer and Key classes:
* The concept of **Private key URIs** is introduced – this is a relatively simple string that identifies a signing technology and encodes how to access and sign with a specific private key. Examples:
  - `gcpkms:projects/python-tuf-kms/locations/global/keyRings/git-repo-demo/cryptoKeys/online/cryptoKeyVersions/1` (A Google Cloud KMS key)
  - `file:/home/jku/keys/mykey?encrypted=true` (A key in an encrypted file)
  - `hsm:` (A hardware security module like Yubikey)
* **Importing** public keys and constructing private key URIs is handled by Signers (there's no generic API though: this detail is specific to signing technology)
* **Dynamic dispatch** is added for both Signers and Keys (former based on the private key URI, latter on the key content): As a result application code does not need to care about the specific technology used to sign/verify but securesystemslib can still support a wide array of signing methods -- and this support can even be extended with out-of-tree implementations.

## Code examples

These examples are slightly simplified copies from my latest repository implementation and should represent any new application code using the python-tuf Metadata API in the future[^1]. Some things to note in these examples:
* Application code that signs does not care what signing technology is used
* Public key import (and related private key URI construction) is specific to the underlying signing technology
* Private key URIs can be stored wherever makes sense for the specific application

### Example 1: Online key in a KMS

Here’s an example where the private key URI is stored in a custom field in the metadata (this makes sense for online keys). First, the setup code that imports a key from Google Cloud KMS – this code runs in a repository maintainer tool:

```python
def import_google_cloud_key() -> Key
    gcp_key_id = input("Please enter the Google Cloud KMS key id")
    uri, key = GCPSigner.import_(gcp_key_id)
    # embed the uri in the public key metadata
    key.unrecognized_fields["x-online-uri"] = uri
    return key
```

Then signing with the same key – this code runs in the online repository component and only needs the public key as an argument since we embedded the private key URI in the public key metadata. It does require the `cloudkms.signer` role permissions on Google Cloud though:

```python
def sign_online(self, md: Metadata, key: Key) -> None:
     uri = key.unrecognized_fields["x-online-uri"]
     signer = Signer.from_priv_key_uri(uri, key)
     md.sign(signer)
```

### Example 2: Maintainer key on a Yubikey

This time we're importing the maintainers Yubikey:

```python
def import_yubikey(config: ConfigParser) -> Key
    input("Insert your HW key and press enter")
    uri, key = HSMSigner.import_()
    # store the uri in application configuration
    config["keyring"][key.keyid] = uri
    return key
```

Later we sign with the Yubikey:

```python
def sign_local(md: Metadata, key: Key, config: ConfigParser) -> None:
     uri = config["keyring"][key.keyid]
     signer = Signer.from_priv_key_uri(uri, key)
     md.sign(signer)
```

[^1]: The new signer API is not used in python-tuf quite yet: follow Pull Request [#2165](https://github.com/theupdateframework/python-tuf/pull/2165) to see when the support is merged.