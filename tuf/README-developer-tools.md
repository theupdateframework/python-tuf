# The Update Framework Developer Tool: How to Update your Project Securely on a TUF Repository

## Table of Contents
- [Overview](#overview)
- [Creating a Simple Project](#creating_a_simple_project)
  - [Generating a Key](#generating_a_key)
  - [The Project Class](#the_project_class)
  - [Signing and Writing the Metadata](#signing_and_writing_the_metadata)
- [Loading an Existing Project](#loading_an_existing_project)
- [Delegations](#delegations)
- [Managing Keys](#managing_keys)
- [Managing Targets](#managing_targets)

<a name="overview">
## Overview 
The Update Framework (TUF) is a Python-based security system for software
updates. In order to prevent your users from downloading vulnerable or malicious
code disguised as updates to your software, TUF requires that each update you
release include certain metadata verifying your authorship of the files.

The TUF developer tools are a Python Library that enables you to create and
maintain the required metadata for files hosted on a TUF Repository. (We call
these files “targets,” to distinguish them from the metadata associated with
them. Both of these together comprise a complete “project”.) You will use these
tools to generate the keys and metadata you need to claim and secure your files
on the repository, and to update the metadata and sign it with those keys
whenever you upload a new version of those files.

This document will teach you how to use these tools in two parts. The first
part walks through the creation of a minimal-complexity TUF project, which is
all you need to get started, and can be expanded later. The second part details
the full functionality of the tools, which offer a finer degree of control in
securing your project.

<a name="creating_a_simple_project">
## Creating a Simple Project
This section walks through the creation of a small example project with just
one target. Once created, this project will be fully functional, and can be
modified as needed.

<a name="generating_a_key">
### Generating a Key
First, we will need to generate a key to sign the metadata. Keys are generated
in pairs: one public and the other private. The private key is
password-protected and is used to sign metadata. The public key can be shared
freely, and is used to verify signatures made by the private key. You will need
to share your public key with the repository hosting your project so they can
verify your metadata is signed by the right person.

The generate\_and\_write\_rsa\_keypair function will create two key files named
"path/to/key.pub", which is the public key and "path/to/key", which
is the private key.

```
>>> from tuf.developer_tool import *
>>> generate_and_write_rsa_keypair("path/to/key")
Enter a password for the RSA key:
Confirm:
>>> 
```

We can also use the bits parameter to set a different key length (the default
is 3072). We can also provide the password parameter in order to suppress the
password prompt.

In this example we will be using rsa keys, but ed25519 keys are also supported.

Now we have a key for our project, we can proceed to create our project.

<a name="the_project_class">
### The Project Class
The TUF developer tool is built around the Project class, which is used to
organize groups of targets associated with a single set of metadata. A single
Project instance is used to keep track of all the target files and metadata
files in one project. The Project also keeps track of the keys and signatures,
so that it can update all the metadata with the correct changes and signatures
on a single command.

Before creating a project, you must know where it will be located in the TUF
Repository. In the following example, we will create a project to be hosted as
"repo/unclaimed/example_project" within the repository, and store a local copy
of the metadata at "path/to/metadata". The project will comprise a single
target file, "local/path/to/example\_project/target\_1" locally, and we will
secure it with the key generated above.

First, we must import the generated keys. We can do that by issuing the
following command:

```
>>> public_key = import_rsa_publickey_from_file("path/to/keys.pub")
```

After importing the key, we can generate a new project with the following
command:

```
>>> project = create_new_project(project_name="example_project",
...  metadata_directory="local/path/to/metadata/",
...  targets_directory="local/path/to/example_project",
...  location_in_repository="repo/unclaimed", key=public_key)
```

Let's list the arguments and make sense out of this rather long function call:

- create a project named example_project: the name of the metadata file will match this name
- the metadata will be located in "local/path/to/metadata", this means all of the generated files
for this project will be located here
- the targets are located in local/path/to/example project. If your targets are located in some other
place, you can point the targets directory there. Files must reside under the path local/path/to/example_project or else it won't be possible to add them.
- location\_in\_repository points to repo/unclaimed, this will be prepended to the paths in the generated metadata so the signatures all match.

Now the project is in memory and we can do different operations on it such as
adding and removing targets, delegating files, changing signatures and keys,
etc. For the moment we are interested in adding our one and only target inside
the project.

To add a target, we issue the following method:

```
>>> project.add_target("local/path/to/example_project/target_1")
```

Note that the file "target\_1" should be located in
"local/path/to/example\_project", or this method will throw an
error.

At this point, the metadata is not valid. We have assigned a key to the
project, but we have not *signed* it with that key. Signing is the process of
generating a signature with our private key so it can be verified with the
public key by the server (upon uploading) and by the clients (when updating).

<a name="signing_and_writing_the_metadata">
### Signing and Writing the Metadata ###
In order to sign the metadata, we need to import the private key corresponding 
to the public key we added to the project. One the key is loaded to the project,
it will automatically be used to sign the metadata whenever it is written.

```
>>> private_key = import_rsa_privatekey_from_file("path/to/key")
Enter password for the RSA key:
>>> project.load_signing_key(private_key)
>>> project.write()
```

When all changes to the project have been written, the metadata is ready to be
uploaded to the repository, and it is safe to exit the Python interpreter, or
to delete the Project instance.

The project can be loaded later to update changes to the project. The metadata
contains checksums that have to match the actual files or else it won't be
accepted by the upstream repository.

At this point, if you have followed all the steps in this document so far
(substituting appropriate names and filepaths) you will have created a basic
TUF project, which can be expanded as needed. The simplest way to get your
project secured is to add all your files using add\_target() (or see [Managing
Keys](#managing_keys) on how to add whole directories). If your project has
several contributors, you may want to consider adding
[delegations](#delegations) to your project.

<a name="loading_an_existing_project">
## Loading an Existing Project
To make changes to existing metadata, we will need the Project again. We can 
restore it with the load_project() function.  

```
>>> from tuf.developer_tool import *
>>> project = load_project("local/path/to/metadata")
```
Each time the project is loaded anew, the necessary private keys must also be 
loaded in order to sign metadata.

```
>>> private_key = import_rsa_privatekey_from_file("path/to/key")
Enter a password for the RSA key:
>>> project.load_signing_key(private_key)
>>> project.write()
```

If your project does not use any delegations, the five commands above are all
you need to update your project's metadata.

<a name="delegations">
## Delegations

The project we created above is secured entirely by one key. If you want to
allow someone else to update part of your project independently, you will need
to delegate a new role for them. For example, we can do the following:

```
>>> other_key = import_rsa_publickey_from_file(“another_public_key.pub”)
>>> targets = ['local/path/to/newtarget']
>>> project.delegate(“newrole”, [other_key], targets)
```

The new role is now an attribute of the Project instance, and contains the same
methods as Project. For example, we can add targets in the same way as before:

```
>>> project(“newrole”).add_target(“delegated_1”)
```

Recall that we input the other person’s key as part of a list. That list can
contain any number of public keys. We can also add keys to the role after
creating it using the [add\_verification\_key()](#adding_a_key_to_a_delegation)
method.

### Restricted Paths

By default, a delegated role is permitted to add and modify targets anywhere in
the Project's targets directory. We can assign restricted paths to a delegated
role to limit this permission.

```
>>> project.add_restricted_paths(["restricted/filepath"], "newrole")
```

This will prevent the delegated role from signing targets whose local filepaths
do not begin with "restricted/filepath". We can assign several restricted
filepaths to a role by adding them to the list in the first parameter, or by
invoking the method again. A role with multiple restricted paths can add
targets to any of them.

Note that this method is invoked from the parent role (in this case, the Project)
and takes the delegated role name as an argument.

### Nested Delegations

It is possible for a delegated role to have delegations of its own. We can do
this by calling delegate() on a delegated role:

```
>>> project("newrole").delegate(“nestedrole”, [key], targets)
```

Nested delegations function no differently than first-order delegations. to
demonstrate, adding a target to nested delegation looks like this:

```
>>> project("newrole")("nestedrole").add_target("foo")
```

### Revoking Delegations
Delegations can be revoked, removing the delegated role from the project.

```
>>> project.revoke("newrole")
```

<a name="managing_keys">
## Managing Keys 
This section describes the key-related functions and parameters not covered in
the [Creating a Simple Project](#creating_a_simple_project) section.

### Additional Parameters for Key Generation
When generating keys, it is possible to specify the length of the key in bits 
and its password as parameters:

```
>>> generate_and_write_rsa_keypair("path/to/key",bits=2048, password="pw")
```
The bits parameter defaults to 3072, and values below 2048 will raise an error.
The password parameter is only intended to be used in scripts.

<a name="adding_a_key_to_a_delegation">
### Adding a Key to a Delegation
New verifications keys can be added to an existing delegation using
add\_verification\_key():

```
>>> project("rolename").add_verification_key(pubkey)
```

A delegation can have several verification keys at once. By default, a
delegated role with multiple keys can be written using any one of their
corresponding signing keys. To modify this behavior, you can change the
delegated role's [threshold](#delegation_thrsholds).

### Removing a Key from a Delegation
Verification keys can also be removed, like this:

```
>>> project("rolename").remove_verification_key(pubkey)
```

Remember that a project can only have one key, so this method will return an
error if there is already a key assigned to it. In order to replace a key we
must first delete the existing one and then add the new one. It is possible to
omit the key parameter in the create\_new\_project() function, and add the key
later.

### Changing the Project Key
Each Project instance can only have one verification key. This key can be
replaced by removing it and adding a new key, in that order.

```
>>> project.remove_verification_key(oldkey)
>>> project.add_verification_key(new)
```

<a name="delegation_thresholds">
### Delegation Thresholds

Every delegated role has a threshold, which determines how many of its signing
keys need to be loaded to write the role. The threshold defaults to 1, and
should not exceed the number of verification keys assigned to the role. The
threshold can be accessed as a property of a delegated role.

```
>>> project("rolename").threshold = 2
```

The above line will set the "rolename" role's threshold to 2.

<a name="managing_targets">
## Managing Targets
There are supporting functions of the targets library to make the project
maintenance easier. These functions are described in this section.

### Adding Targets by Directory
This function is especially useful when creating a new project to add all the
files contained in the targets directory. The following code block illustrates
the usage of this function:

```
>>> list_of_targets = \
...   project.get_filepaths_in_directory(“path/within/targets/folder”,
...   recursive_walk=False, follow_links=False)
>>> project.add_targets(list_of_targets)
```

### Deleting Targets from a Project
It is possible that we want to delete existing targets inside our project. To
stop the developer tool from tracking this file we can issue the following
command:

```
>>> project.remove_target(“target_1”)
```

Now the target file won't be part of the metadata.
