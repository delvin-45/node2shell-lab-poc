# Troubleshooting

## Docker access is denied on Windows

Symptom: `permission denied while trying to connect to the Docker API`.

Start Docker Desktop, wait for the engine, and confirm:

```powershell
docker version
docker context ls
```

The active context should be `desktop-linux`. A shell that cannot open the
Docker named pipe is not a problem with this repository.

## Port 3000 is already in use

Only one RCE lab uses host port `3000` at a time. Check and remove leftovers:

```bash
docker ps --filter publish=3000
docker rm -f n2s-wp n2s-unfurl n2s-ref n2s-patched-ref n2s-patched-wp n2s-patched-unfurl
```

`make clean` also removes the three Compose assets on ports `19200`-`19202`.

## The PoC says the target was not healthy

Check the container and the health route:

```bash
docker ps
curl -i http://127.0.0.1:3000/health
docker logs --tail 30 <container>
```

The service must answer `PONG` before `poc.py` sends a stage. For the DoS labs,
this check is intentionally expected to fail after the trigger.

## The RCE attempt reaches 16/16 without a proof

That is a normal failure for a probabilistic ASLR guess. It is not evidence
that the target is safe. Start a fresh container with the supervisor and try
again:

```bash
docker run --rm -d --name n2s-ref \
  -e N2S_SUPERVISE=1 -e UV_THREADPOOL_SIZE=1 \
  -p 127.0.0.1:3000:3000 node2shell-lab:ref-24.22.0
python poc.py --profile n2s-ref-express-24.22.0-x86_64
```

If it repeatedly fails, verify that the image digest, package lock, accepted
socket descriptor, and one-worker setting match the profile. Do not "fix" it by
relaxing the proof.

## The patched control does not report the decoder error

For the Express labs, the expected body is:

```text
ERR ERR__ERROR_FORMAT_BLOCK_SWITCH
```

For the unfurl lab, the server wraps the error but includes the cause chain:

```json
{"error":"ERR__ERROR_FORMAT_BLOCK_SWITCH","codes":["ERR__ERROR_FORMAT_BLOCK_SWITCH"],"message":"terminated"}
```

If the error is absent, confirm that the image was built from
`Dockerfile.patched` and that the runtime is v24.22.1.

## The unfurl target did not fetch from the attacker origin

The container cannot reach the host listener. On Docker Desktop,
`host.docker.internal` is normally available. On a Linux engine, add:

```bash
--add-host host.docker.internal:host-gateway
```

The PoC binds its origin to `127.0.0.1:4000`. Keep that port free and do not
forward it beyond the host.

## `make` is not installed

The Makefile is convenience tooling. Every target has a direct equivalent in
the lab README and in `docs/evidence/MATRIX.md`. On Windows, GNU Make 4.4.1
from `ezwinports.make` is sufficient.

## VHS reports that ttyd is missing

VHS needs both `ffmpeg` and `ttyd` on this Windows setup. Install them, then
render a tape:

```powershell
winget install --id tsl0922.ttyd --exact
winget install --id charmbracelet.vhs --exact
vhs docs/assets/demos/passive-scan.tape
```

The checked-in `.gif`, `.mp4`, and `.ascii` files are the recordings from this
machine, not mockups.

## The scan reports `REACHABLE_VERSION_UNKNOWN`

That is expected when the application does not disclose its Node.js version.
`tools/scan.py` does not guess from a framework header and does not send the PoC. A
hidden version is not a safe version.
