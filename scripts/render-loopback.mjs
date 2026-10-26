import { readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

const reviewedImage = 'sha256:4bcc401e4eab8e8149da83a92829265b549ae1d4ddc084ab54de8d3a84fd8d1c';
export async function renderLoopback(metadata, expectedContainerId) {
  if (!/^[a-f0-9]{64}$/.test(expectedContainerId ?? '') || metadata.containerId !== expectedContainerId) throw new Error('Container identity mismatch');
  if (metadata.project !== 'telegram-assistant-bridge' || metadata.service !== 'bridge') throw new Error('Wrong Compose project/service');
  if (metadata.imageId !== reviewedImage || metadata.running !== true) throw new Error('Image or running-state mismatch');
  if (metadata.networkCount !== 1 || metadata.publishedPortCount !== 0 || metadata.internal !== true || metadata.driver !== 'bridge' || !['nat', 'default-nat'].includes(metadata.gatewayMode)) throw new Error('Unexpected network configuration');
  if (isIP(metadata.ip) !== 4) throw new Error('Invalid IP');
  const [a, b] = metadata.ip.split('.').map(Number);
  if (!(a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))) throw new Error('Expected private project IP');
  const template = await readFile(new URL('../deploy/status-loopback.conf.template', import.meta.url), 'utf8');
  return template.replaceAll('BRIDGE_CONTAINER_IPV4', metadata.ip);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [metadataPath, expectedContainerId, outputPath] = process.argv.slice(2);
  if (!metadataPath || !outputPath) throw new Error('Usage: node scripts/render-loopback.mjs metadata.json expected-container-id output.conf');
  const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
  await writeFile(outputPath, await renderLoopback(metadata, expectedContainerId), { flag: 'wx' });
}
