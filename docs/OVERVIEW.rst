What Is a Software Update System?
---------------------------------

Generally, a software update system is an application (or part of an
application) running on a client system that obtains and installs
software. These systems typically update the applications installed
on client systems to introduce new features, enhancements, and security
fixes.

Three major classes of software update systems are:

-  **Application updaters** which are used by applications to update
   themselves. For example, Firefox updates itself through its own
   application updater.

-  **Library package managers** such as those offered by many
   programming languages for installing additional libraries. These are
   systems such as Python's pip/easy_install + PyPI, Perl's CPAN,
   Ruby's RubyGems, and PHP's Composer.

-  **System package managers** used by operating systems to update and
   install all of the software on a client system. Debian's APT, Red
   Hat's YUM, and openSUSE's YaST are examples of these.

Our Approach
------------

There are literally thousands of different software update systems in
common use today. (In fact the average Windows user has about `two
dozen <https://secuniaresearch.flexerasoftware.com/gfx/pdf/Secunia_RSA_Software_Portfolio_Security_Exposure.pdf>`_
different software updaters on their machine!)

We are building a library that can be universally (and in most cases
transparently) used to secure software update systems.

Overview
--------

On the surface, the update procedure followed by a software update system can be regarded
as straightforward.  Obtaining and installing an update just means:

-  Knowing when an update exists.
-  Downloading the update.
-  Applying the changes introduced by the update.

The problem with this view is that it is only straightforward when there
are no malicious parties involved throughout the update procedure. If an attacker
is trying to interfere with these seemingly simple steps, there is plenty
that they can do.

TUF is designed to perform the first two steps of the above update procedure,
while guarding against the majority of attacks that malicious actors have at
their disposal; especially those attacks that are overlooked by security-conscious
developers.


Background
----------

Let's assume you take the approach that most systems do (at least, the
ones that even try to be secure). You download both the file you want
and a cryptographic signature of the file. You already know which key
you trust to make the signature. You check that the signature is correct
and was made by this trusted key. All seems well, right? Wrong. You are
still at risk in many ways, including:

-  An attacker keeps giving you the same file, so you never realize
   there is an update.
-  An attacker gives you an older, insecure version of a file that you
   already have, so you download that one and blindly use it thinking
   it's newer.
-  An attacker gives you a newer version of a file you have but it's not
   the newest one. It's newer to you, but it may be insecure and
   exploitable by the attacker.
-  An attacker compromises the key used to sign these files and now you
   download a malicious file that is properly signed.

These are just some of the attacks software update systems are
vulnerable to when only using signed files. See
`Security <SECURITY.md>`_ for a full list of attacks and updater
weaknesses TUF is designed to prevent.

The following papers provide detailed information on securing software
updater systems, TUF's design and implementation details, attacks on
package managers, and package management security:

-  `Mercury: Bandwidth-Effective Prevention of Rollback Attacks Against Community Repositories
   <papers/prevention-rollback-attacks-atc2017.pdf?raw=true>`_

-  `Diplomat: Using Delegations to Protect Community Repositories
   <papers/protect-community-repositories-nsdi2016.pdf?raw=true>`_

-  `Survivable Key Compromise in Software Update
   Systems <papers/survivable-key-compromise-ccs2010.pdf?raw=true>`_

-  `A Look In the Mirror: Attacks on Package
   Managers <papers/package-management-security-tr08-02.pdf?raw=true>`_

-  `Package Management
   Security <papers/attacks-on-package-managers-ccs2008.pdf?raw=true>`_

What TUF Does
-------------

In order to securely download and verify target files, TUF requires a
few extra files to exist on a repository. These are called metadata
files. TUF metadata files contain additional information, including
information about which keys are trusted, the cryptographic hashes of
files, signatures on the metadata, metadata version numbers, and the
date after which the metadata should be considered expired.

When a software update system using TUF wants to check for updates, it
asks TUF to do the work. That is, your software update system never has
to deal with this additional metadata or understand what's going on
underneath. If TUF reports back that there are updates available, your
software update system can then ask TUF to download these files. TUF
downloads them and checks them against the TUF metadata that it also
downloads from the repository. If the downloaded target files are
trustworthy, TUF hands them over to your software update system. See
`Metadata <METADATA.md>`_ for more information and examples.
