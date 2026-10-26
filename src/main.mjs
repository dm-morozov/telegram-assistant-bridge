import { createBridgeHttpServer } from './server.mjs';
const host = process.argv.includes('--container') ? '0.0.0.0' : '127.0.0.1';
const server = createBridgeHttpServer({ publicStatus: process.argv.includes('--public-status') });
server.listen(3000, host, () => console.log('Local MCP status prototype started on port 3000.'));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close());
