"""
<Module Name>
  gpg

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  This module was written due to the lack of other python (such as pygpg)
  modules that can provide an abstraction to the RFC4480 encoded messages from
  GPG. The closest candidate we could find was the python bindings for gpgme,
  we oped to use a Popen-based python-only construction given that gpgme is
  often shipped separately and other popular tools using gpg (e.g., git) don't
  use these bindings either. This is because users willing to use gpg signing
  are almost guaranteed to have gpg installed, yet the same assumption can't be
  made for the gpgme python bindings.
"""
