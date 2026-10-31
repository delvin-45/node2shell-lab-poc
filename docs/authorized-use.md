# Authorized use

This repository is a restricted local cyber range for security research,
remediation validation, and education.

Run the reproducer only against the included Docker labs on loopback. The tool
accepts only `127.0.0.1`, `::1`, and `localhost`, requires the exact port from
the selected profile, uses fixed request paths, and never accepts a
caller-supplied command. The RCE proof executes only `/usr/bin/id`; it requires
fresh `uid=` and `gid=` output.

The outbound test path binds an attacker origin on the host. On Docker Desktop
the container reaches it through `host.docker.internal`. Keep that listener
local, do not forward the port, and stop the container when the test ends.

Do not use this material to access, disrupt, or exfiltrate data from a
third-party system; to establish persistence; to evade controls; or to perform
any activity without prior written authorization. A profile entry is a
reproduction recipe, not authorization for another host.

If you are validating a production system, use the vendor advisory and the
fixed release. Do not send the malformed stream outside the included lab.
