# Changelog

All notable changes to this project are documented here.
The format follows Keep a Changelog, and the project uses Semantic Versioning.

## [1.1.0] - 2026-10-31

### Changed

- Reorganized the repository into `assets/`, `deploy/`, `docs/`, `labs/`, and
  `tools/`.
- Replaced the text banner with a generated research banner and rebuilt the
  README around the verified lab matrix, demo capture, and evidence.
- Moved governance files to `.github/` and authorized-use guidance to
  `docs/`.
- Removed the duplicate Indonesian README and the internal rebuild plan.

## [1.0.0] - 2026-10-31

### Added

- Three loopback labs: `wp-cms`, `unfurl-api`, and `reference-express`.
- Exact affected and patched image variants pinned by digest.
- Stdlib-only `poc.py` with RCE and DoS modes, JSON output, quiet mode,
  dry-run, profile listing, and self-test.
- `profiles.json` with exact fingerprints, probe metadata, limitations, and
  evidence pointers.
- Passive three-asset scanner and Compose file.
- Raw evidence logs, SHA-256 checksums, and a claim matrix.
- VHS terminal recordings and real headless-Chrome screenshots.
- Startup verification workflow and Makefile targets.

### Verified

- Reference Express RCE: 2/2 fresh containers.
- WordPress-style CMS RCE: 2/2 fresh containers.
- Reference Express, WordPress-style CMS, and unfurl API DoS: 2/2 each.
- All three patched controls: failed closed with
  `ERR__ERROR_FORMAT_BLOCK_SWITCH` and stayed healthy.

### Security

- The PoC rejects non-loopback hosts, mismatched ports, and arbitrary commands.
- Outbound fetch labs accept only loopback and host-gateway destinations.
