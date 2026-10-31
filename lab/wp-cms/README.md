# wp-cms

A WordPress-style publishing application on the affected Node.js v24.22.0
runtime. It is not WordPress and does not use PHP. The layout, admin pages, and
REST shape exist to put the decoder sink behind a realistic content workflow.

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Front page with three posts |
| GET | `/p/:slug/` | Single post |
| GET | `/wp-admin/` | Dashboard |
| GET | `/wp-admin/media` | Add Media form |
| GET | `/wp-admin/import` | Import from URL form |
| GET | `/wp-json/` | REST index |
| GET | `/wp-json/wp/v2/posts` | Post collection |
| GET | `/wp-json/wp/v2/posts/:id` | Single post |
| POST | `/wp-json/wp/v2/media` | JSON body parsed by `express.json()` |
| POST | `/wp-json/node2shell/v1/import` | Fetch a loopback URL and consume the body |
| GET | `/health` | `PONG` |

## Sinks

The RCE-profile sink is `POST /wp-json/wp/v2/media`. It uses route-scoped
`express.json()` with default options. No body parser runs before it. Errors
leave through the shared handler as `ERR <code>`.

The DoS-profile sink is `POST /wp-json/node2shell/v1/import`. It accepts
`{"url":"..."}`, fetches the URL, and reads the complete response. Only loopback
and `host.docker.internal` targets are accepted.

## Run

```bash
docker build -t node2shell-lab:wp-24.22.0 -f lab/wp-cms/Dockerfile lab/wp-cms
docker run --rm -d --name n2s-wp -p 127.0.0.1:3000:3000 node2shell-lab:wp-24.22.0
curl http://127.0.0.1:3000/health
```

For the RCE attempt, use the restart supervisor and one libuv worker:

```bash
docker run --rm -d --name n2s-wp -e N2S_SUPERVISE=1 -e UV_THREADPOOL_SIZE=1 \
  -p 127.0.0.1:3000:3000 node2shell-lab:wp-24.22.0
```

## Patched control

```bash
docker build -t node2shell-lab:wp-24.22.1 -f lab/wp-cms/Dockerfile.patched lab/wp-cms
```

The patched image keeps the application, package lock, and routes unchanged.
Only the Node.js runtime digest differs.

## Status

| Claim | Runs | Evidence |
| --- | ---: | --- |
| RCE | 2/2 | [run 1](../../docs/evidence/wp-cms-rce-run1.txt) · [run 2](../../docs/evidence/wp-cms-rce-run2.txt) |
| DoS | 2/2 | [run 1](../../docs/evidence/wp-cms-dos-run1.txt) · [run 2](../../docs/evidence/wp-cms-dos-run2.txt) |
| Patched control | 1/1 | [control](../../docs/evidence/wp-cms-patched-control.txt) |

Read [`docs/evidence/MATRIX.md`](../../docs/evidence/MATRIX.md) for the full
claim boundary. Do not infer the result from the app shape alone.
