# FAQ

## What is CVE-2026-111497?

An out-of-bounds write in the Brotli decoder bundled with affected Node.js
releases. A malformed block-type selection corrupts decoder memory. The
practical impact ranges from a process crash to command execution under a
specific layout.

## Is this a zero-day or an unreported bug?

No. The repository targets a public CVE with a vendor advisory and a fixed
release. The lab is a reproduction and evidence package, not a disclosure.

## Why are there two RCE labs?

The reference Express fixture preserves the smallest known-good shape for the
exact RCE profile. The WordPress-style CMS repeats the same parser shape behind
a larger application. Both passed 2/2 in fresh containers. The separate
fixture makes the proof easier to audit without the rest of the CMS.

## Why does the CMS RCE profile succeed while the unfurl profile claims only DoS?

They exercise different application code. The CMS has a JSON body sink with the
same middleware as the reference fixture. The unfurl API consumes a response
through undici, and the verified result for that shape is a crash. Claiming RCE
there would require a separate exact profile and proof.

## Why is the RCE result probabilistic?

The exploit uses a saved-return-address guess that depends on the process
address-space layout. A miss crashes the worker. The supervisor starts a fresh
process, and the PoC tries again. Two fresh containers passed, but the number
of attempts varied, so the claim is not deterministic.

## Why does the RCE need file descriptor 19?

The ROP chain duplicates a specific accepted socket descriptor onto stdout.
That descriptor is part of the exact container and application layout. A
different accept order or supervisor can change it, which is why the profile is
binary-specific.

## Does a failed RCE attempt mean the target is safe?

No. It means this profile did not observe a complete proof within its attempt
budget. The service may still be affected. Use the vendor patch as the safety
decision, not a failed exploit run.

## Can I change the command that runs?

No. The PoC always executes `/usr/bin/id`. It has no command-line option for a
shell command, file path, or callback payload. This keeps the repository useful
as a proof and limits misuse.

## Can I test another host with it?

No. `poc.py` accepts only `127.0.0.1`, `::1`, and `localhost`, and the port must
match the selected profile. The lab's outbound fetchers also restrict targets.
See [AUTHORIZED_USE.md](../AUTHORIZED_USE.md).

## Why does `make verify` not run RCE?

`make verify` is the deterministic gate: self-test, build, DoS for labs A and
B, and all three patched controls. RCE is probabilistic and has its own
two-container evidence set. Keeping the gate deterministic makes CI useful.

## Why is the target version not visible in the scanner?

Node.js does not send its version by default, and the labs do not add a
diagnostic header. The scanner reports `RUNTIME_DETECTED_VERSION_HIDDEN` or
`REACHABLE_VERSION_UNKNOWN` instead of guessing. See
[`scan.py`](../scan.py).

## Is the trigger safe to send anywhere else?

No. It is a memory-corruption input. Send it only to the included loopback
labs. The repository stores the exact digest so the payload cannot drift
silently.

## What is the CISA KEV badge saying?

It links to the CISA catalog so a reader can check the current listing status.
The repository does not independently assert that this CVE is listed. Vendor
advisories and the catalog are the external sources of record.

## How do I cite this work?

Use [`CITATION.cff`](../CITATION.cff) or the repository URL. The software is
MIT licensed; the evidence logs describe measurements on one host and are not
a warranty for another environment.
