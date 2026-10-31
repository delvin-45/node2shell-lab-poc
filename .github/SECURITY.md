# Security policy

## Scope

This repository is a deliberately vulnerable research lab. The applications
in `labs/` are not safe to expose to a network. They are built to run on
loopback with pinned, affected runtimes.

The maintainer welcomes reports about the lab harness itself, including:

- a path that lets `poc.py` contact a non-loopback host;
- a way to inject an arbitrary command into the proof;
- a build that does not match the documented digest or package lock;
- an evidence file that does not match its recorded hash.

## Reporting

Email: **delvinalvazri45@gmail.com**

Include the affected file, reproduction steps, the expected and observed
behaviour, and whether the report involves a real third-party system. Do not
attach data obtained from a system you do not own.

Please do not open a public issue for a harness escape or a secret leak.

## Safe harbour

Testing is authorized only against the included loopback labs on a machine you
control. Nothing in this repository grants permission to test another system.
See [docs/authorized-use.md](../docs/authorized-use.md).

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Earlier | No |
