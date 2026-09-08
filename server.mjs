import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { scan } from './scanner.js';

const PORT = 8080;

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);

  if (u.pathname === '/scan') {
    const target = u.searchParams.get('url');
    res.setHeader('content-type', 'application/json; charset=utf-8');
    try {
      const result = await scan(target);
      res.end(JSON.stringify(result));
    } catch (e) {
      res.statusCode = 200;
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (u.pathname === '/logo.png') {
    try {
      const img = await readFile(new URL('./logo.png', import.meta.url));
      res.setHeader('content-type', 'image/png');
      res.end(img);
    } catch { res.statusCode = 404; res.end('no logo'); }
    return;
  }

  // serve the demo page
  try {
    const html = await readFile(new URL('./demo.html', import.meta.url));
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end(html);
  } catch {
    res.statusCode = 404;
    res.end('not found');
  }
});

server.listen(PORT, () => {
  console.log(`safechk demo running at http://localhost:${PORT}`);
});
