import assert from 'node:assert/strict';
import { connectFetch } from './connect-fetch.mjs';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
const endpoint = new URL(process.argv[2]);
const routedFetch = process.argv[3] ? connectFetch(process.argv[3], Number(process.argv[4])) : undefined;
const client = new Client({ name: 'container-smoke', version: '0.1.0' });
try {
  await client.connect(new StreamableHTTPClientTransport(endpoint, { fetch: routedFetch }));
  assert.deepEqual((await client.listTools()).tools.map(tool => tool.name), ['status']);
  for (let count = 0; count < 60; count++) {
    const result = await client.callTool({ name: 'status', arguments: {} });
    assert.deepEqual(result.structuredContent, { service: 'telegram-assistant-bridge', stage: 'prototype', telegramConnected: false });
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  await assert.rejects(client.callTool({ name: 'telegram_messages', arguments: {} }), /not found/);
  if (routedFetch) {
    assert.equal((await routedFetch(endpoint, { headers: { Origin: 'https://example.invalid' } })).status, 403);
    const wrongHost = await routedFetch(new URL('http://example.invalid/mcp'));
    assert.ok([403, 421].includes(wrongHost.status));
  }
  console.log('MCP initialization, discovery, 60 status calls and negative tool/Host/Origin checks passed.');
} finally { await client.close(); }
