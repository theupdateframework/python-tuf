# A Framework for Securing Software Update Systems

TUF (The Update Framework) helps developers secure their new or existing
software update systems. Software update systems are vulnerable to many known
attacks, including those that can result in clients being compromised or
crashed.  TUF helps solve this problem by providing a flexible security
framework that can be added to software updaters.

# What Is a Software Update System?

Generally, a software update system is an application (or part of an
application) running on a client system that obtains and installs software.
This can include updates to software that is already installed or even
completely new software.

Three major classes of software update systems are:

* Application Updaters - which are used by applications use to update
themselves. For example, Firefox updates itself through its own application
updater.

* Library Package Managers - such as those offered by many programming
languages for installing additional libraries. These are systems such as
Python's pip/easy_install + PyPI, Perl's CPAN, Ruby's Gems, and PHP's PEAR.

* System Package Managers - used by operating systems to update and install all
of the software on a client system. Debian's APT, Red Hat's YUM, and openSUSE's
YaST are examples of these.

# Our Approach

There are literally thousands of different software update systems in common
use today. (In fact the average Windows user has about  two dozen different
software updaters on their machine!)

We are building a library that can be universally (and in most cases
transparently) used to secure software update systems.
