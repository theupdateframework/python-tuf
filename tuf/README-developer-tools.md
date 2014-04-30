# Developing for a TUF repository #

## Table of Contents ##
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
The TUF developer tool is a Python library that enables developers to create 
and maintain the required metadata for files hosted in a TUF Repository. The main
concern when generating metadata for a TUF repository is generating information
that matches the future location of the files in the repository. We use
the developer tools to generate valid information so that the project and it's
metadata can be applied to the TUF project transparently. 

This  document has two parts. The first part walks through the creation of a
prototypal TUF project. The second part demonstrates the full capabilities of 
the TUF developer tool, which can be used to expand the project from the first
part to meet the developer's needs.

<a name="creating_a_simple_project">
## Creating a Simple project
The following section describes a very basic example usage of the developer tools with
a one-file project. 

<a name="generating_a_key">
### Generating a Key
First, you will need to generate a key to sign the metadata. Keys are generated
in pairs: one public and the other private. The private key is password-protected
and is used to sign metadata. The public key can be shared freely, and is used
to verify signatures made by the private key.   

The generate\_and\_write\_rsa\_keypair function will create two key files
named "path/to/key.pub", which is the public key and "path/to/key", which
is the private key.

```
>>> from tuf.developer_tool import *
>>> generate_and_write_rsa_keypair("path/to/key")
Enter a password for the RSA key:
Confirm:
>>> 
```

We can also use the bits parameter to set a different key length (the default is 
3072). We can also provide the password parameter in order to suppress the password
prompt.

During this example we will be using rsa keys, but ed25519 keys are also supported. 

Now we have a key for our project, we can proceed to create our project. 

<a name="the_project_class">
### The Project Class
The TUF developer tool is built around the Project class, which is used to organize groups of 
targets associated with a single set of metadata. Each Project instance keeps 
track of which target files are associated with a single set of metadata. Each 
Project instance keeps track of which target files are signed and which need
signing, which keys are used to sign metadata. It also keeps track of delegated
roles, which are covered later.

Before creating a project, you must know where it will be located in the TUF 
Repository. In the following example, we will create a project to be hosted as
"repo/unclaimed/example_project" within the repository, and store a local copy of the 
metadata at "path/to/metadata". The project will comprise a single target file, 
"local/path/to/example\_project/target\_1" locally, and we will secure it with
the key generated above. 

First, we must import the generated keys. We can do that by issuing the following:

```
>>> public_key = import_rsa_publickey_from_file("path/to/keys.pub")
```

After importing the key, we can generate a new project with the following command 
```
>>> project = create_new_project(name="example_project",
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

Now the project is in memory and we can do different operations on it such as adding and
removing targets, delegating files, changing signatures and keys, etc. For the moment we are 
interested in adding our one and only target inside the project.

To add a target, we issue the following method:
```
>>> project.add_target("target_1")
```

Have in mind the file "target\_1" should be located in "local/path/to/example\_project"
or else the adding procedure will throw an error.

At this point, the metadata is not valid. We have assigned a key to the project,
but we have not *signed* it with that key. Signing is the process of generating
a signature with our private key so it can be verified with the public key by the 
server (upon uploading) and by the clients (when updating). 

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

When all changes to a project have been written, the Project instance can safely
be deleted. 

The project can be loaded later to update changes to the project. The metadata
contains checksums that have to match the actual files or else it won't be accepted 
by the upstream repository.

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

Now we have a project properly setup. The rest of this guide contains a more
in-depth description of the functions of the developer\_tool.

<a name="delegations">
## Delegations

The project we created above is secured entirely by one key. If you want to
allow someone else to update part of your project independently, you will need
to delegate a new role for them. For example, we can do the following:

```
>>> other_key = import_rsa_publickey_from_file(“another_public_key.pub”)
>>> project.delegate(“newrole”, [other_key], targets)
```

The new role is now an attribute of the Project instance, and contains the same
methods as Project. For example, we can add targets in the same way as before:

```
>>> project(“newrole”).add_target(“delegated_1”)
```

Recall that we input the other person’s key as part of a list. That list can
contain any number of public keys. You can also add keys to the role after
creating it using the [add\_verification\_key()](#adding_a_key_to_a_delegation) method.

### Restricted Paths

By default, a delegated role is permitted to add and modify targets anywhere in the
Project's targets directory. We can assign restricted paths to a delegated role to
limit this permission.

```
>>> project.add_restricted_paths(["restricted/filepath"], "newrole")
```

This will prevent the delegated role from signing targets whose local filepaths do not
begin with "restricted/filepath". We can assign several restricted filepaths to a role
by adding them to the list in the first parameter, or by invoking the method again. A
role with multiple restricted paths can add targets to any of them.

Note that this method is invoked the parent role (in this case, the project) and takes
the delegated role name as an argument.

### Nested Delegations



### Revoking Delegations

<a name="managing_keys">
## Managing Keys 
This section describes the key-related functions and parameters that weren't 
mentioned inside the example:

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
Likewise, it is possible to add a key to a project by issuing the following command:
```
>>> project.add_verification_key(pubkey)
```

### Removing a Key from a Delegation
Removing a verification key is really simple, we should only issue the following
command:

```
>>> project.remove_verification_key(key)
```

Remember that a project can only have one key, so this method will return an error
if there is already a key assigned to it. In order to replace a key we must first
delete the existing one and then add the new one. It is possible to
ommit the key parameter in the create\_new\_project function, and add the key 
later.

### Changing the Project Key

### Delegation Thresholds

<a name="managing_targets">
## Managing Targets
There are supporting functions of the targets library to make the project
maintenance easier. These functions are described in this section.

### Adding Targets by Directory
This function is specially useful when creating a new project to add all the files
contained in the targets directory. The following code block illustrates the usage
of this function:
```

>>> list_of_targets = \
...   project.get_filepaths_in_directory(“path/within/targets/folder”,
...   recursive_walk=False, follow_links=False)
>>> project.add_targets(list_of_targets)
```

### Deleting Targets from a Project
It is possible that we want to delete existing targets inside our project. In order
to stop the developer tool to track this file we must issue the following command:
```
>>> project.remove_target(“target_1”)
```
Now the target file won't be part of the metadata.

