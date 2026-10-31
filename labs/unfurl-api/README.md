# unfurl-api

A link unfurler in the style of a chat integration. It accepts a URL, fetches
the page, consumes the complete response, and extracts Open Graph metadata.

Runtime: Node.js v24.22.0 with the pinned `undici` 8.12.3 client.

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | HTML tester |
| GET | `/health` | `PONG` |
| POST | `/api/unfurl` | `{"url":"..."}`; fetch and consume body |

Only `127.0.0.1`, `localhost`, and `host.docker.internal` are accepted as
targets. This keeps the lab loopback-scoped and prevents it from being used as
an arbitrary outbound fetch proxy.

## Run

```bash
docker build -t node2shell-lab:unfurl-24.22.0 -f labs/unfurl-api/Dockerfile labs/unfurl-api
docker run --rm -d --name n2s-unfurl -p 127.0.0.1:3000:3000 node2shell-lab:unfurl-24.22.0
curl http://127.0.0.1:3000/health
```

The PoC binds its own origin on `127.0.0.1:4000`; the container reaches it as
`host.docker.internal`. Start the container with
`--add-host host.docker.internal:host-gateway` on Docker Engines that do not
provide that name automatically.

## Patched control

```bash
docker build -t node2shell-lab:unfurl-24.22.1 -f labs/unfurl-api/Dockerfile.patched labs/unfurl-api
```

The patched control uses the same source and lockfile with Node.js v24.22.1.

## Status

The measured result is recorded in
[`docs/evidence/MATRIX.md`](../../docs/evidence/MATRIX.md). The intended claim
is denial of service through response-body consumption; no command execution is
claimed for this profile.
