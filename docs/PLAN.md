# Rebuild plan

Status: complete, with the limitations recorded in the evidence matrix.

## Starting point

The workspace contained an unlicensed multi-lab repository with duplicated
Node.js versions (v20, v22, v24.9, v24.22, v26), ten application integrations,
large VHS recordings, and historical evidence tied to the previous owner. The
pinned trigger digest and the exact-binary Express RCE profile were the only
technical anchors carried forward.

## Target tree

```text
lab/reference-express/   minimal Express 5.3.0 negative/positive fixture
lab/wp-cms/              WordPress-style CMS with JSON and media routes
lab/unfurl-api/          link unfurler on Node.js 24.22.0 + undici 8.12.3
poc.py                   stdlib-only loopback reproducer
profiles.json            exact profiles and evidence pointers
scan.py                  passive three-asset triage
compose.scan.yaml        three loopback-bound scan targets
docs/                    architecture, walkthrough, lab notes, evidence, demos
```

## Execution record

1. Legacy labs, assets, captures, and the previous licence were removed.
2. The three lab directories were rebuilt from scratch with pinned Node.js
   24.22.0 and patched 24.22.1 variants.
3. The reference Express profile passed RCE in 2/2 fresh containers and DoS in
   2/2. The patched control failed closed.
4. The WordPress-style CMS passed RCE in 2/2 (successful attempts 1 and 1) and
   DoS in 2/2. The patched control failed closed.
5. The unfurl API passed DoS in 2/2. No RCE is claimed. The patched control
   failed closed and exposed the decoder error in its cause chain.
6. `poc.py` was refactored without changing the trigger or the two proven
   attack shapes. The self-test still returns the anchor digest.
7. Real VHS recordings and headless-Chrome screenshots were captured from the
   running containers.
8. The claim matrix, checksums, documentation, Makefile, and CI workflow were
   written from the measured results.

## Evidence rules

- A claim maps to a raw transcript under `docs/evidence/`.
- Logs contain the command, timestamp, image identity, full output, exit code,
  operator observation, and container log tail.
- `docs/evidence/SHA256SUMS` covers every text log.
- A failed RCE attempt is a limitation, not a pass.
- No result is marked verified until it has run on this machine.

## Environment notes

- Docker Desktop 4.91.0 on Windows; Linux `amd64` containers.
- Python 3.13.9; the PoC targets 3.11 and later.
- VHS 0.12.1 with `ttyd` 1.7.7 and `ffmpeg` produced the recordings.
- GitHub CLI is not authenticated. The repository is committed locally; the
  push is the owner's remaining action.
- The claim matrix records what was not proven, including universal RCE and
  the untested 22.x and 26.x release lines.
