import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
const endpoint = new URL(process.argv[2]);
const client = new Client({ name: 'container-smoke', version: '0.1.0' });
try {
  await client.connect(new StreamableHTTPClientTransport(endpoint));
  assert.deepEqual((await client.listTools()).tools.map(tool => tool.name), ['status']);
  for (let count = 0; count < 60; count++) {
    const result = await client.callTool({ name: 'status', arguments: {} });
    assert.deepEqual(result.structuredContent, { service: 'telegram-assistant-bridge', stage: 'prototype', telegramConnected: false });
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  console.log('Container MCP initialization, discovery and 60 status calls passed.');
} finally { await client.close(); }
