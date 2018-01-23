Using TUF
---------

TUF has four major classes of users: clients, for whom TUF is largely
transparent; mirrors, who will (in most cases) have nothing at all to do
with TUF; upstream servers, who will largely be responsible for care and
feeding of repositories; and integrators, who do the work of putting TUF
into existing projects.

An integration requires importing a single module into the new or existing
software updater and calling particular methods to perform updates.  Generating
metadata files stored on upstream servers can be handled by repository tools that
we provide for this purpose.


- `Integrating with a Software Updater <https://github.com/theupdateframework/tuf/tree/develop/tuf/client/README.md>`_

- `Creating a TUF Repository  <https://github.com/theupdateframework/tuf/tree/develop/tuf/README.md>`_
