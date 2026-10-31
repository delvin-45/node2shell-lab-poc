# reference-express

Minimal Express fixture used to preserve the exact-binary RCE claim.

It keeps the middleware shape that was verified: `express.json()` with default
options, no earlier body middleware, and the stock error handler.

## Routes

| Method | Path | Behaviour |
| --- | --- | --- |
| GET | `/health` | `PONG` |
| POST | `/upload` | JSON parser, then `DONE` |
| any | error | `ERR <code>` with HTTP 400 |

## Run

```bash
docker build -t node2shell-lab:ref-24.22.0 -f labs/reference-express/Dockerfile labs/reference-express
docker run --rm -d --name n2s-ref -p 127.0.0.1:3000:3000 node2shell-lab:ref-24.22.0
python poc.py --profile n2s-ref-express-24.22.0-x86_64
```

For the retry loop used by the probabilistic RCE profile, start the container
with `N2S_SUPERVISE=1` and `UV_THREADPOOL_SIZE=1`. The supervisor restarts the
Node process after each decoder crash, which gives the PoC a fresh ASLR layout.

```bash
docker run --rm -d --name n2s-ref -e N2S_SUPERVISE=1 -e UV_THREADPOOL_SIZE=1 \
  -p 127.0.0.1:3000:3000 node2shell-lab:ref-24.22.0
```

## Patched control

`Dockerfile.patched` pins Node.js v24.22.1. The same request fails closed with
`ERR__ERROR_FORMAT_BLOCK_SWITCH` and the health endpoint stays available.

```bash
docker build -t node2shell-lab:ref-24.22.1 -f labs/reference-express/Dockerfile.patched labs/reference-express
docker run --rm -d --name n2s-ref-patched -p 127.0.0.1:3000:3000 node2shell-lab:ref-24.22.1
python poc.py --profile n2s-ref-express-patched-24.22.1-x86_64
```

## Verified status

| Claim | Runs | Evidence |
| --- | ---: | --- |
| RCE | 2/2 | [run 1](../../docs/evidence/ref-express-rce-run1.txt) · [run 2](../../docs/evidence/ref-express-rce-run2.txt) |
| DoS | 2/2 | [run 1](../../docs/evidence/ref-express-dos-run1.txt) · [run 2](../../docs/evidence/ref-express-dos-run2.txt) |
| Patched control | 1/1 | [control](../../docs/evidence/ref-express-patched-control.txt) |

## Scope

The RCE result is specific to this exact binary, package lock, libuv thread
count, accepted socket descriptor, and restart supervisor. It is not a claim
about arbitrary Express applications.
