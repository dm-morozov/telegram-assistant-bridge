import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { request } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createBridgeHttpServer } from '../src/server.mjs';

test('official MCP client initializes, discovers and calls only status', async () => {
  const http = createBridgeHttpServer();
  http.listen(0, '127.0.0.1');
  await once(http, 'listening');
  const endpoint = new URL(`http://127.0.0.1:${http.address().port}/mcp`);
  const client = new Client({ name: 'bridge-test', version: '0.1.0' });
  try {
    await client.connect(new StreamableHTTPClientTransport(endpoint));
    const listed = await client.listTools();
    assert.deepEqual(listed.tools.map(tool => tool.name), ['status']);
    const result = await client.callTool({ name: 'status', arguments: {} });
    assert.equal(result.isError, undefined);
    assert.deepEqual(result.structuredContent, { service: 'telegram-assistant-bridge', stage: 'prototype', telegramConnected: false });
    const invalid = await client.callTool({ name: 'status', arguments: { unexpected: true } });
    assert.equal(invalid.isError, true);
    await assert.rejects(client.callTool({ name: 'telegram_messages', arguments: {} }), /not found/);
    assert.equal((await fetch(endpoint, { headers: { Origin: 'https://example.invalid' } })).status, 403);
    const deniedHost = await new Promise((resolve, reject) => {
      const req = request(endpoint, { headers: { Host: 'example.invalid' } }, res => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject); req.end();
    });
    assert.equal(deniedHost, 403);
  } finally {
    await client.close();
    await new Promise(resolve => http.close(resolve));
  }
});
