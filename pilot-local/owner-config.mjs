import { readFile, lstat } from 'node:fs/promises';
import { isAbsolute, basename } from 'node:path';
import { readJwksSnapshot } from './jwks-snapshot.mjs';
import { createResourceVerifier } from './verifier.mjs';
import { createLocalProtectedPilot, createSnapshotIngressPilot } from './http-pilot.mjs';

// Explicit private-file loading only. No environment, fixture, discovery or anonymous fallback.
export async function loadApprovedOwnerConfiguration(configPath) {
  try {
    if (typeof configPath !== 'string' || !isAbsolute(configPath) || basename(configPath) !== 'owner.local.json') throw new Error();
    const info = await lstat(configPath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 8192) throw new Error();
    const config = JSON.parse(await readFile(configPath,'utf8'));
    const keys = ['schemaVersion','oauth','ownerEmailVerified','verificationObservedAtUtc','connectionName'];
    if (!config || Object.keys(config).some(key=>!keys.includes(key)) || config.schemaVersion!==1 || config.ownerEmailVerified!==true || config.connectionName!=='Username-Password-Authentication' || !Number.isFinite(Date.parse(config.verificationObservedAtUtc)) || Date.parse(config.verificationObservedAtUtc)>Date.now()+60000) throw new Error();
    if (!config.oauth || Object.keys(config.oauth).sort().join(',')!=='audience,issuer,jwksUri,ownerSubject') throw new Error();
    createResourceVerifier(config.oauth); // Validates explicit issuer/resource/owner/JWKS; performs no fetch.
    return Object.freeze({oauth:Object.freeze({...config.oauth})});
  } catch { throw new Error('Approved verified-owner configuration required'); }
}
export async function createConfiguredLocalPilot({ownerConfigPath,chats=[],clock=Date.now,sweepMs=1000}={}) {
  const {oauth}=await loadApprovedOwnerConfiguration(ownerConfigPath);
  return createLocalProtectedPilot({oauth,chats,clock,sweepMs});
}

export async function createConfiguredIngressPilot({ownerConfigPath,jwksSnapshotPath,chats=[],listenHost='127.0.0.1',sweepMs=1000}={}) {
  const {oauth}=await loadApprovedOwnerConfiguration(ownerConfigPath);
  await readJwksSnapshot(jwksSnapshotPath,oauth);
  return createSnapshotIngressPilot({oauth,jwksSnapshotPath,chats,listenHost,sweepMs});
}
