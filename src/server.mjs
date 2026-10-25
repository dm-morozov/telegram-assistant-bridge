import { createServer } from 'node:http';
import { McpServer } from '@modelcontextprotocol/server';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import * as z from 'zod/v4';

function createMcpServer() {
  const server = new McpServer({ name: 'telegram-assistant-bridge', version: '0.1.0' });
  server.registerTool('status', {
    title: 'Bridge status',
    description: 'Return prototype readiness only. Does not connect to Telegram or read host or personal data.',
    inputSchema: z.object({}).strict(),
    outputSchema: z.object({ service: z.literal('telegram-assistant-bridge'), stage: z.literal('prototype'), telegramConnected: z.literal(false) }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true }
  }, async () => {
    const result = { service: 'telegram-assistant-bridge', stage: 'prototype', telegramConnected: false };
    return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
  });
  return server;
}

export function createBridgeHttpServer() {
  const http = createServer(async (req, res) => {
    // Local prototype: reject browser origins and DNS-rebinding hosts. No authentication is implemented.
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(req.headers.host ?? '') || req.headers.origin) {
      res.writeHead(403).end(); return;
    }
    if (req.url !== '/mcp') { res.writeHead(404).end(); return; }
    const server = createMcpServer();
    const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => { void server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) res.writeHead(500).end();
      else res.end();
      await server.close();
    }
  });
  http.requestTimeout = 15000;
  http.headersTimeout = 10000;
  http.maxConnections = 32;
  return http;
}
