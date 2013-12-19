## A Framework for Securing Software Update Systems

TUF (The Update Framework) helps developers secure their new or existing
software update systems. Software update systems are vulnerable to many known
attacks, including those that can result in clients being compromised or
crashed.  TUF helps solve this problem by providing a flexible security
framework that can be added to software updaters.

## What Is a Software Update System?

Generally, a software update system is an application (or part of an
application) running on a client system that obtains and installs software.
This can include updates to software that is already installed or even
completely new software.

Three major classes of software update systems are:

* **Application updaters** which are used by applications use to update
themselves. For example, Firefox updates itself through its own application
updater.

* **Library package managers** such as those offered by many programming
languages for installing additional libraries. These are systems such as
Python's pip/easy_install + PyPI, Perl's CPAN, Ruby's Gems, and PHP's PEAR.

* **System package managers** used by operating systems to update and install all
of the software on a client system. Debian's APT, Red Hat's YUM, and openSUSE's
YaST are examples of these.

## Our Approach

There are literally thousands of different software update systems in common
use today. (In fact the average Windows user has about [two dozen](http://secunia.com/gfx/pdf/Secunia_RSA_Software_Portfolio_Security_Exposure.pdf) different
software updaters on their machine!)

We are building a library that can be universally (and in most cases
transparently) used to secure software update systems.

## Overview

At the highest level, TUF simply provides applications with a secure method of obtaining files and knowing when new versions of files are available. We call these files, the ones that are supposed to be downloaded, "target files". The most common need for these abilities is in software update systems and obviously that's what we had in mind when creating TUF.

On the surface, this all sounds simple. Securely obtaining updates just means:

* Knowing when an update exists.
* Downloading the updated file. 

The problem is that this is only simple when there are no malicious parties involved. If an attacker is trying to interfere with these seemingly simple steps, there is plenty they can do.

## Background

Let's assume you take the approach that most systems do (at least, the ones that even try to be secure). You download both the file you want and a cryptographic signature of the file. You already know which key you trust to make the signature. You check that the signature is correct and was made by this trusted key. All seems well, right? Wrong. You are still at risk in many ways, including:

* An attacker keeps giving you the same file, so you never realize there is an update.
* An attacker gives you an older, insecure version of a file that you already have, so you download that one and blindly use it thinking it's newer.
* An attacker gives you a newer version of a file you have but it's not the newest one. It's newer to you, but it may be insecure and exploitable by the attacker.
* An attacker compromises the key used to sign these files and now you download a malicious file that is properly signed. 

There are other attacks, as well. This is just to quickly show some problems and make clear that using signed files doesn't by itself solve all security problems.

### [Security](SECURITY.md)

### [Metadata](METADATA.md)

##What TUF Does

In order to securely download and verify target files, TUF requires a few extra files to exist on a repository. These are called metadata files. Metadata files contain additional information, including information about which keys are trusted, the cryptographic hashes of files, signatures on the metadata, and timestamps that indicate how old the metadata is and the date after which the metadata should be considered expired.

When a software update system using TUF wants to check for updates, it asks TUF to do the work. That is, your software update system never has to deal with this additional metadata or understand what's going on underneath. If TUF reports back that there are updates available, your software update system can then ask TUF to download these files. TUF downloads them and checks them against the security metadata that it also downloads from the repository. If the downloaded target files are trustworthy, TUF hands them over to your software update system.

##Using TUF

TUF has four major classes of users: clients, for whom TUF is largely transparent; mirrors, who will (in most cases) have nothing at all to do with TUF; upstream servers, who will largely be responsible for care and feeding of repositories; and integrators, who do the work of putting TUF into existing projects.

###[Creating a repository](tuf/README.md)

###[Low-level integration](tuf/client/README.md)

###[High-level integration](tuf/interposition/README.md)
