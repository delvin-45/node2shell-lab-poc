'use strict';

const express = require('express');

const app = express();
const port = Number(process.env.N2S_PORT || 3000);

app.get('/health', (_request, response) => response.end('PONG\n'));

app.post('/upload', express.json(), (_request, response) => {
  response.end('DONE\n');
});

app.use((error, _request, response, _next) => {
  response.status(400).end(`ERR ${error.code || error.type || error.message}\n`);
});

app.listen(port, '0.0.0.0');
