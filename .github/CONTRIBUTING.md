# Contributing

This repository is primarily a research record. Changes that alter a profile,
the trigger, or an evidence claim need the corresponding verification run.

## Before opening a pull request

1. Run `python poc.py --self-test`.
2. Run the lab affected by your change on a loopback port.
3. If the change can affect a claim, add a raw log under `docs/evidence/` and
   update `docs/evidence/SHA256SUMS` and `docs/evidence/MATRIX.md`.
4. Keep the trigger digest and size unchanged unless the CVE itself changes.
5. Do not add a real target, a public callback address, or an arbitrary command
   option to `poc.py`.
6. Use Conventional Commits, for example `fix(poc): reject empty profile ID`.
7. Run `make verify` from a clean state if Docker is available.

## Style

- English for repository content.
- Short sentences and tables where they help.
- No emoji in body text.
- No claim without a linked evidence file.
- Node.js source uses `'use strict'` and standard library APIs where possible.
- Python stays standard-library only and Python 3.11 compatible.

## Security

Do not include credentials, public IP addresses, packet captures from
third-party systems, or personal data in a pull request. See
[SECURITY.md](SECURITY.md) for reporting a harness issue.
