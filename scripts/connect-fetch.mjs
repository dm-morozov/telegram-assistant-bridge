import { request } from 'node:http';

// HTTP routing only; the official SDK still implements every MCP operation.
export function connectFetch(address, port) {
  return async (input, init) => {
    const incoming = new Request(input, init);
    const url = new URL(incoming.url);
    const body = incoming.body ? Buffer.from(await incoming.arrayBuffer()) : undefined;
    return new Promise((resolve, reject) => {
      const req = request({ hostname: address, port, path: url.pathname + url.search, method: incoming.method,
        headers: { ...Object.fromEntries(incoming.headers), host: url.host }, signal: incoming.signal }, res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('error', reject);
        res.on('end', () => {
          const headers = new Headers();
          for (const [name, value] of Object.entries(res.headers)) {
            if (Array.isArray(value)) value.forEach(item => headers.append(name, item));
            else if (value !== undefined) headers.set(name, value);
          }
          resolve(new Response([204, 205, 304].includes(res.statusCode) ? null : Buffer.concat(chunks), { status: res.statusCode, headers }));
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  };
}
