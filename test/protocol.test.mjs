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

test('public trial allows only its fixed host and still exposes static status only', async () => {
  const http = createBridgeHttpServer({ publicStatus: true });
  http.listen(0, '127.0.0.1');
  await once(http, 'listening');
  const endpoint = new URL(`http://127.0.0.1:${http.address().port}/mcp`);
  const post = (host, origin) => new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'status', arguments: {} } });
    const headers = { Host: host, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Content-Length': Buffer.byteLength(body), 'MCP-Protocol-Version': '2025-11-25' };
    if (origin) headers.Origin = origin;
    const req = request(endpoint, { method: 'POST', headers }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, text }));
    });
    req.on('error', reject); req.end(body);
  });
  try {
    const accepted = await post('telegram-bridge.mu56.ru');
    assert.equal(accepted.status, 200, accepted.text);
    assert.deepEqual(JSON.parse(accepted.text).result.structuredContent, { service: 'telegram-assistant-bridge', stage: 'prototype', telegramConnected: false });
    assert.equal((await post('telegram-bridge.mu56.ru.attacker.invalid')).status, 403);
    assert.equal((await post('telegram-bridge.mu56.ru', 'https://example.invalid')).status, 403);
    assert.equal((await post('telegram-bridge.mu56.ru', 'https://telegram-bridge.mu56.ru')).status, 403);
    assert.equal((await post('example.invalid')).status, 403);
  } finally {
    await new Promise(resolve => http.close(resolve));
  }
});
