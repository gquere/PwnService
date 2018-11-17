PwnService
==========

Rationale
---------
During a recent penetration test I came accross a misconfigured Windows service running as SYSTEM.
The rights of the binary spawned by the service were funky and allowed regular users to write to the file.

This example drops a shell with SYSTEM privileges to the currently logged in user. It does so by impersonating the SYSTEM token and starting a process within the user's session with said token.
It's trickier than for instance adding a new user, changing an admin password or granting the current user admin rights, but I needed something stealthy that doesn't leave as much traces ;)

Licence
-------
This repository is GPLv3. Refer to the LICENSE file for more information.
