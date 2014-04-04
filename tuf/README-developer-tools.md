# Developing for a TUF repository #

## Table of Contents ##
- [Overview](#overview)
- [Creating a simple project](#creating_a_simple_project)
  - [Generating a key](#generating_a_key)
  - [The Project class](#the_project_class)
  - [Signing and writing metadata](#signing_and_writing_metadata)
- [Loading an Existing project](#Loading_an_existing_project)
- [Managing keys](#managing_keys)
- [Managing targets](#managing_targets)
- [Delegations](#delegations)
  - [Restricted paths](#restricted_paths)
  - [Keys and thresholds](#keys_and_thresholds)

<a name="overview">
## Overview 
The TUF developer tool is a Python library that enables developers to create 
and maintain the required metadata for files hosted in a TUF Repository. This 
document has two parts. The first part walks through the creation of a
prototypal TUF project. The second part demonstrates the full capabilities of 
the TUF developer tool, which can be users to expand the project from the first
part to meet the developer''s needs.

<a name="creating_a_simple_project">
## Creating a Simple project ##
### Generating a Key ###
First, you will need to generate a key to sign the metadata. Keys are generated
in pairs: one public and the other private. The private key is password-protected
and is used to sign metadata. The public key can be shared freely, and is used
to verify signatures made by the private key.   

The generate_and_write_rsa_keypair function will create two key files in the 
path (path/to/) and named "key.pub", which is the public key and "key"
which is the private key.

```
>>> from tuf.developer_tool import *

>>> generate_and_write_rsa_keypair("path/to/key")
Enter a password for the RSA key:
Confirm:
>>> 
```

<a name="the_project_class">
### The project class ###
TUF-dev is built around the Project class, which is used to organize groups of 
targets associated with a single set of metadata. Each Project instance keeps 
track of which target files are associated with a single set of metadata. Each 
Project instance keeps track of which target files are signed and which need
signing, which keys are used to sign metadata. It also keeps track of delegated
roles, which are covered later.

Before creating a project, you must know where it will be located in the TUF 
Repository. In the following example, we will create a project to be hosted as
"repo/example_project" within the repository, and store a local copy of the 
metadata at "path/to/metadata". The project will comprise a single target file, 
"local/path/to/example_project/target_1" locally, and we will secure it with
the key generated above. 

```
>>> public_key = import_rsa_publickey_from_file("path/to/keys.pub")

>>> project = create_new_project(metadata_directory="local/path/to/metadata/",
... targets_directory="local/path/to/example_project",
... location_in_repository="repo/example_project", key=public_key)
>>> project.add_target("target_1")
```

At this point, the metadata is not valid. We have assigned a key to the project,
but we have not *signed* it with that key.

<a name="signing_and_writing_the_metadata">
### Signing and writing the metadata ###
In order to sign the metadata, we need to import the private key corresponding 
to the public key we added to the project. One the key is loaded to the project,
it will automatically be used to sign the metadata whenever it is written.

```
>>> private_key = import_rsa_privatekey_from_file("path/to/key")
Enter password for the RSA key:
>>> project.load_signing_key(private_key)
>>> project.write()
```

When all changes to a project have been written, the Project instance can safely
be deleted.

<a name="loading_an_existing_project">
To make changes to existing metadata, we will need the Project again. We can 
restore it with the load_project() function.

```
>>> from tuf.developer_tool import *
>>> project = load_project("local/path/to/metadata")
>>>
```
Each time the project is loaded anew, the necessary private keys must also be 
loaded in order to sign metadata.

```
>>> private_key = import_rsa_privatekey_from_file("path/to/key")
Enter a password for the RSA key:

>>> project.load_signing_key(private_key)

>>> project.write()
```

<a name="managing_keys">
## Managing keys 
When generating keys, it is possible to specify the length of the key in bits 
and its password as parameters:

```
>>> generate_and_write_rsa_keypair("path/to/key",bits=2048, password="pw")
```
The bits parameter defaults to 3072, and values below 2048 will raise an error.
The password parameter is only intended to be used in scripts.


## Managing Targets

```

>>> list_of_targets = \
...   project.get_filepaths_in_directory(“path/within/targets/folder”,
...   recursive_walk=False, follow_links=False)
...   project.add_targets(list_of_targets)
```

```
>>> project.remove_target(“target_1”)
```

## Delegations

The project we created above is secured entirely by one key. If you want to
allow someone else to update part of your project independently, you will need
to delegate a new role for them. For example, we can

```
>>> other_key = import_rsa_publickey_from_file(“sombodys_public_key.pub”)

>>> project.delegate(“newrole”, [other_key], targets)
```

The new role is now an attribute of the Project instance, and contains the same
methods as Project. For example, we can add targets in the same way as before:

```

>>> project(“newrole”).add_target(“delegated_1”)

```



Recall that we input the other person’s key as part of a list. That list can
contain any number of public keys. You can also add keys to the role after
creating it using the add_signing_key() method.

