# Link Unfurl API lab

`labs/unfurl-api` models a chat integration that expands a URL into a small
preview. The server fetches the page, reads the whole body, extracts Open Graph
metadata, and returns JSON.

## Stack

| Item | Value |
| --- | --- |
| Runtime | Node.js v24.22.0 |
| HTTP client | undici 8.12.3 |
| Server | Node.js `node:http` |
| User | `node` (uid 1000) |
| Container port | 3000 |

## Routes

| Route | Description |
| --- | --- |
| `GET /` | HTML tester with a URL form |
| `GET /assets/style.css` | Local stylesheet |
| `GET /health` | `PONG` |
| `POST /api/unfurl` | `{"url":"..."}`, fetch and consume the response |

The accepted target hosts are `127.0.0.1`, `localhost`, and
`host.docker.internal`. This keeps the lab from becoming an arbitrary
outbound fetch proxy.

## Sink

The request body is small JSON. The outbound response is the test surface:

```text
POST /api/unfurl
Content-Type: application/json

{"url":"http://host.docker.internal:4000/payload"}
```

The server always reads the complete response with `arrayBuffer()`, even when
the caller only wants a title. That consumption is what reaches the decoder.

## Verified result

| Claim | Runs | Result | Evidence |
| --- | ---: | --- | --- |
| DoS | 2/2 | 4/4 health checks failed after the fetch | [run 1](../../docs/evidence/unfurl-api-dos-run1.txt) · [run 2](../../docs/evidence/unfurl-api-dos-run2.txt) |
| RCE | n/a | Not attempted; not claimed | n/a |
| Patched control | 1/1 | Failed closed with `ERR__ERROR_FORMAT_BLOCK_SWITCH`, health `PONG` | [control](../../docs/evidence/unfurl-api-patched-control.txt) |

## Run

```bash
docker build -t node2shell-lab:unfurl-24.22.0 -f labs/unfurl-api/Dockerfile labs/unfurl-api
docker run --rm -d --name n2s-unfurl -p 127.0.0.1:3000:3000 node2shell-lab:unfurl-24.22.0
python poc.py --profile n2s-unfurl-24.22.0-x86_64
```

The PoC starts its own origin on `127.0.0.1:4000` and sends the target a URL
that points at it. On Linux engines without `host.docker.internal`, add:

```bash
--add-host host.docker.internal:host-gateway
```

## Patched control

```bash
docker build -t node2shell-lab:unfurl-24.22.1 -f labs/unfurl-api/Dockerfile.patched labs/unfurl-api
docker run --rm -d --name n2s-unfurl-patched -p 127.0.0.1:3000:3000 node2shell-lab:unfurl-24.22.1
python poc.py --profile n2s-unfurl-patched-24.22.1-x86_64
```

The patched server reports the cause chain, so the control can see
`ERR__ERROR_FORMAT_BLOCK_SWITCH` even though undici surfaces the outer error as
`TypeError: terminated`.
