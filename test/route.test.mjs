import test from 'node:test';
import assert from 'node:assert/strict';
import { renderLoopback } from '../scripts/render-loopback.mjs';
const id = 'a'.repeat(64);
const identity = { containerId: id, project: 'telegram-assistant-bridge', service: 'bridge', imageId: 'sha256:4bcc401e4eab8e8149da83a92829265b549ae1d4ddc084ab54de8d3a84fd8d1c', running: true, networkCount: 1, publishedPortCount: 0, internal: true, driver: 'bridge', gatewayMode: 'nat', ip: '192.168.250.2' };
test('route renders only a verified running project identity without publishing ports', async () => {
  const config = await renderLoopback(identity, id);
  assert.ok(config.includes('listen 127.0.0.1:18085;'));
  assert.ok(config.includes('proxy_pass http://192.168.250.2:3000;'));
  assert.ok(!config.includes('BRIDGE_CONTAINER_IPV4'));
});
test('stale identity, neighbor project, changed image/network and IP injection fail closed', async () => {
  for (const changed of [ { containerId: 'b'.repeat(64) }, { project: 'other-project' }, { running: false }, { imageId: 'sha256:' + 'b'.repeat(64) }, { networkCount: 2 }, { publishedPortCount: 1 }, { internal: false }, { gatewayMode: 'isolated' }, { gatewayMode: 'routed' }, { gatewayMode: undefined }, { ip: '127.0.0.1' }, { ip: '192.168.1.2; malicious' } ]) {
    await assert.rejects(renderLoopback({ ...identity, ...changed }, id));
  }
});
