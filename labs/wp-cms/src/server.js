'use strict';

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const app = express();
const port = Number(process.env.N2S_PORT || 3000);
const publicDir = path.join(__dirname, 'public');
const viewsDir = path.join(__dirname, 'views');
const layout = fs.readFileSync(path.join(viewsDir, 'layout.html'), 'utf8');

const posts = [
  {
    id: 1,
    slug: 'welcome-to-the-lab',
    date: '2026-10-21T09:00:00',
    title: 'Welcome to the lab',
    excerpt: 'A small publication desk, built to study one decoder failure.',
    body: [
      'This site is a deliberately vulnerable Node.js application. It looks like a publishing dashboard because real content pipelines often expose exactly these paths: an editor, a media endpoint, and an import tool.',
      'The only behaviour under test is the Brotli decoder bundled with this Node.js runtime. Nothing on this page needs to be attacked to reproduce the issue.',
    ],
  },
  {
    id: 2,
    slug: 'notes-on-media-import',
    date: '2026-10-22T11:30:00',
    title: 'Notes on media import',
    excerpt: 'Why an import box is a useful boundary for this lab.',
    body: [
      'Editors import assets from remote URLs. The server fetches the URL and consumes the response so it can inspect the file. That ordinary feature is the outbound half of the test surface.',
      'The JSON media route is the inbound half: it inflates a request body before routing. Both paths are documented and loopback-only in this repository.',
    ],
  },
  {
    id: 3,
    slug: 'release-day-checklist',
    date: '2026-10-23T08:15:00',
    title: 'Release day checklist',
    excerpt: 'Pin the runtime, verify the patch, keep the blast radius small.',
    body: [
      'Record the exact image digest. Run the malformed stream against the affected build. Repeat on the fixed build and confirm a clean parser error.',
      'A decoder crash is an availability result. Command execution is a narrower claim that only applies to the exact binary profile recorded in the evidence directory.',
    ],
  },
];

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function render(template, values) {
  const page = fs.readFileSync(path.join(viewsDir, template), 'utf8');
  const content = page.replace(/\{\{(\w+)\}\}/g, (_match, key) => {
    return Object.hasOwn(values, key) ? String(values[key]) : '';
  });
  return layout
    .replaceAll('{{siteName}}', 'Node2Shell Press')
    .replaceAll('{{year}}', '2026')
    .replaceAll('{{content}}', content);
}

function postPayload(post) {
  return {
    id: post.id,
    date: post.date,
    date_gmt: post.date,
    guid: { rendered: `/p/${post.slug}/` },
    modified: post.date,
    modified_gmt: post.date,
    slug: post.slug,
    status: 'publish',
    type: 'post',
    link: `/p/${post.slug}/`,
    title: { rendered: escapeHtml(post.title) },
    content: {
      rendered: post.body.map((paragraph) => `<p>${escapeHtml(paragraph)}</p>`).join(''),
      protected: false,
    },
    excerpt: { rendered: `<p>${escapeHtml(post.excerpt)}</p>`, protected: false },
    author: 1,
    featured_media: 0,
    comment_status: 'closed',
    ping_status: 'closed',
    format: 'standard',
  };
}

function postBySlug(slug) {
  return posts.find((entry) => entry.slug === slug);
}

function postById(id) {
  return posts.find((entry) => entry.id === Number(id));
}

function postCards() {
  return posts
    .map(
      (post) => `
        <article class="post-card">
          <p class="eyebrow">${escapeHtml(post.date.slice(0, 10))}</p>
          <h2><a href="/p/${escapeHtml(post.slug)}/">${escapeHtml(post.title)}</a></h2>
          <p>${escapeHtml(post.excerpt)}</p>
          <a class="read-more" href="/p/${escapeHtml(post.slug)}/">Read post</a>
        </article>`,
    )
    .join('\n');
}

function renderHome() {
  return render('home.html', { posts: postCards() });
}

function renderPost(post) {
  const body = post.body.map((paragraph) => `<p>${escapeHtml(paragraph)}</p>`).join('');
  return render('post.html', {
    title: escapeHtml(post.title),
    date: escapeHtml(post.date.slice(0, 10)),
    body,
    excerpt: escapeHtml(post.excerpt),
  });
}

app.get('/health', (_request, response) => response.type('text/plain').send('PONG\n'));

app.get('/assets/style.css', (_request, response) => {
  response.sendFile(path.join(publicDir, 'style.css'));
});

// The helper pages are intentionally separate from the JSON sink. No body
// parser runs before the media route, preserving the profile's middleware shape.
app.get('/', (_request, response) => response.type('html').send(renderHome()));

app.get('/p/:slug/', (request, response) => {
  const post = postBySlug(request.params.slug);
  if (!post) {
    return response.status(404).type('html').send(render('not-found.html', { title: 'Not found' }));
  }
  return response.type('html').send(renderPost(post));
});

app.get('/wp-admin/', (_request, response) => {
  return response.type('html').send(render('admin.html', {
    count: posts.length,
    recent: postCards(),
  }));
});

app.get('/wp-admin/media', (_request, response) => {
  return response.type('html').send(render('media.html', { title: 'Add media' }));
});

app.get('/wp-admin/import', (_request, response) => {
  return response.type('html').send(render('import.html', { title: 'Import from URL' }));
});

app.get('/wp-json/', (_request, response) => {
  response.json({
    name: 'Node2Shell Press',
    description: 'A WordPress-style publishing lab',
    url: '/',
    home: '/',
    gmt_offset: 0,
    timezone_string: 'UTC',
    namespaces: ['wp/v2', 'node2shell/v1'],
    routes: {
      '/wp/v2/posts': { methods: ['GET'] },
      '/wp/v2/posts/(?P<id>[\\d]+)': { methods: ['GET'] },
      '/wp/v2/media': { methods: ['POST'] },
      '/node2shell/v1/import': { methods: ['POST'] },
    },
  });
});

app.get('/wp-json/wp/v2/posts', (_request, response) => {
  response.json(posts.map(postPayload));
});

app.get('/wp-json/wp/v2/posts/:id', (request, response) => {
  const post = postById(request.params.id);
  if (!post) {
    return response.status(404).json({
      code: 'rest_post_invalid_id',
      message: 'Invalid post ID.',
      data: { status: 404 },
    });
  }
  return response.json(postPayload(post));
});

// SINK (RCE profile): default express.json() parses this request body before
// the handler. Content-Encoding: br reaches the bundled Brotli decoder here.
app.post('/wp-json/wp/v2/media', express.json(), (request, response) => {
  response.status(201).json({
    id: 101,
    date: '2026-10-31T00:00:00',
    slug: 'uploaded-media',
    type: 'attachment',
    title: { rendered: 'Uploaded media' },
    source_url: '/uploads/uploaded-media',
    media_type: request.body && request.body.media_type ? request.body.media_type : 'file',
    status: 'inherit',
  });
});

// SINK (DoS profile): fetch an operator-approved loopback URL and consume the
// whole response. The local allowlist keeps this lab from becoming a scanner.
app.post('/wp-json/node2shell/v1/import', express.json(), async (request, response) => {
  let target;
  try {
    target = new URL(request.body && request.body.url);
  } catch {
    return response.status(400).json({ code: 'invalid_url', message: 'A URL is required.' });
  }
  const allowedHosts = new Set(['127.0.0.1', 'localhost', 'host.docker.internal']);
  if (!allowedHosts.has(target.hostname) || !['http:', 'https:'].includes(target.protocol)) {
    return response.status(400).json({
      code: 'url_not_allowed',
      message: 'Only loopback import URLs are allowed in this lab.',
    });
  }
  try {
    const upstream = await fetch(target);
    const body = Buffer.from(await upstream.arrayBuffer());
    return response.json({
      imported: true,
      status: upstream.status,
      bytes: body.length,
      content_type: upstream.headers.get('content-type') || null,
    });
  } catch (error) {
    return response.status(502).json({
      code: error.code || error.name || 'fetch_failed',
      message: error.message,
    });
  }
});

app.use('/uploads', express.static(path.join(publicDir, 'uploads')));

app.use((_request, response) => {
  response.status(404).type('html').send(render('not-found.html', { title: 'Not found' }));
});

app.use((error, _request, response, _next) => {
  response.status(400).end(`ERR ${error.code || error.type || error.message}\n`);
});

app.listen(port, '0.0.0.0');
