# Verification matrix

Recorded on 2026-10-31 on the owner's Windows host with Docker Desktop
4.91.0, Linux `amd64` containers, Python 3.13.9, and the pinned images below.
Every row points to a raw command transcript. The transcripts include the
timestamp, image ID, Node.js version and binary hash, PoC command, full output,
PoC exit code, container state, health probe, and container log tail.

## Claims

| Claim | Exact profile | Fresh runs | Result | Successful attempt | Raw evidence |
| --- | --- | ---: | --- | ---: | --- |
| Reference Express RCE | `n2s-ref-express-24.22.0-x86_64` | 2/2 | PASS, fresh `uid=` and `gid=` | 8, 7 | [run 1](ref-express-rce-run1.txt) · [run 2](ref-express-rce-run2.txt) |
| Reference Express DoS | `n2s-ref-express-24.22.0-x86_64`, `--mode dos` | 2/2 | PASS, 4/4 health checks failed | 1, 1 | [run 1](ref-express-dos-run1.txt) · [run 2](ref-express-dos-run2.txt) |
| WordPress-style CMS RCE | `n2s-wp-24.22.0-x86_64` | 2/2 | PASS, fresh `uid=` and `gid=` | 1, 1 | [run 1](wp-cms-rce-run1.txt) · [run 2](wp-cms-rce-run2.txt) |
| WordPress-style CMS DoS | `n2s-wp-24.22.0-x86_64`, `--mode dos` | 2/2 | PASS, 4/4 health checks failed | 1, 1 | [run 1](wp-cms-dos-run1.txt) · [run 2](wp-cms-dos-run2.txt) |
| Unfurl API DoS | `n2s-unfurl-24.22.0-x86_64` | 2/2 | PASS, 4/4 health checks failed | 1, 1 | [run 1](unfurl-api-dos-run1.txt) · [run 2](unfurl-api-dos-run2.txt) |
| Reference Express patched control | `n2s-ref-express-patched-24.22.1-x86_64` | 1/1 | FAIL CLOSED, `ERR__ERROR_FORMAT_BLOCK_SWITCH`, health `PONG` | n/a | [control](ref-express-patched-control.txt) |
| WordPress-style CMS patched control | `n2s-wp-patched-24.22.1-x86_64` | 1/1 | FAIL CLOSED, `ERR__ERROR_FORMAT_BLOCK_SWITCH`, health `PONG` | n/a | [control](wp-cms-patched-control.txt) |
| Unfurl API patched control | `n2s-unfurl-patched-24.22.1-x86_64` | 1/1 | FAIL CLOSED, `ERR__ERROR_FORMAT_BLOCK_SWITCH`, health `PONG` | n/a | [control](unfurl-api-patched-control.txt) |

"Fresh" means a newly created container and a newly created Node.js process.
The RCE proofs contain complete `uid=` and `gid=` output returned on the
exploited request socket. The DoS proofs contain four consecutive failed
`/health` checks after the trigger. The patched controls use the same
application source, package lock, request, and image family; only the Node.js
digest changes from v24.22.0 to v24.22.1.

## Pinned images

| Role | Image digest | Node.js | `/usr/local/bin/node` SHA-256 |
| --- | --- | --- | --- |
| Affected | `node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5` | v24.22.0 | `67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c` |
| Patched control | `node@sha256:6449e19d8184d84062525b6a7524def03146c2cb04a7f08b076680d0e8e4240a` | v24.22.1 | `e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb` |

## Evidence hashes

The full list is in [SHA256SUMS](SHA256SUMS). It is generated from every
`*.txt` file in this directory. Hashes for the primary affected runs:

| File | SHA-256 |
| --- | --- |
| `ref-express-rce-run1.txt` | `c4510fcfc02922110c49baef621440e0c339cb266f0a7bfe59354e092c6f1715` |
| `ref-express-rce-run2.txt` | `7c6cec40cb6f759ded2f11fa621009b82b31de3c1d0a9b2d5eea4dbf3c14ce16` |
| `wp-cms-rce-run1.txt` | `ad182df6dde570ea81da7f18c6dafeb1337ebbf1c951096d8f50895eb48dedd9` |
| `wp-cms-rce-run2.txt` | `15e875250410deee94d79d50d9d6e99577a80f2d322daf760335a8cbb8d61eb9` |
| `unfurl-api-dos-run1.txt` | `b53e060d2e145ed0e179f97663b1b15f02a95deef54eec7fa0975faab596963e` |
| `unfurl-api-dos-run2.txt` | `f7f14c6001a3b45e7a81fadb38615a2dcced9dc617618485ccd49ffdb6b9e227` |
| `ref-express-patched-control.txt` | `f7be8f35235bcb5a793ef5e926f151d2dcaa0b381f363e0c1800cc2e0026499b` |
| `wp-cms-patched-control.txt` | `ff20df02bbae50506633a8c30a4ce67184dbe6f39e3dfc1a4405aaa9efe1361b` |
| `unfurl-api-patched-control.txt` | `d39866f79ca8a8ff4cce58d0fc4b586631317c5c5fb179a2998432da539f2384` |

## What was not proven

- A universal exploit for every Node.js v24.22.0 deployment. RCE is verified
  only for the two exact application profiles and their pinned image, package
  lock, libuv worker count, accepted socket descriptor, and restart supervisor.
- RCE through the unfurl API or through the WordPress-style import sink. Those
  profiles claim denial of service only.
- Any impact on Node.js versions other than the listed v24.22.0 image. The
  v24.22.1 control covers only that digest.
- A fix for the underlying decoder beyond upgrading the runtime. Application
  body limits reduce exposure but do not repair the decoder.
- Non-x86-64 platforms, other libc versions, Windows containers, or native
  Node.js installations.
- Production scanner coverage. `tools/scan.py` is a bounded, passive triage tool and
  does not determine exploitability.
- Authenticity of any third-party advisory beyond the links published in the
  README. The evidence in this directory is limited to the local runs above.
