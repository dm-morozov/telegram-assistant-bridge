import { createRemoteJWKSet, customFetch, decodeProtectedHeader, jwtVerify } from 'jose';

import { createSnapshotKeyResolver } from './jwks-snapshot.mjs';
const domainScopes = new Set(['messages:read', 'drafts:create']);
function configuration(input) {
  if (!input || typeof input.ownerSubject !== 'string' || !input.ownerSubject.trim()) throw new Error('Explicit OAuth identity configuration required');
  let issuer, audience, jwks;
  try { issuer = new URL(input.issuer); audience = new URL(input.audience); jwks = new URL(input.jwksUri); } catch { throw new Error('Invalid OAuth URL configuration'); }
  for (const url of [issuer, audience, jwks]) if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('HTTPS-only fixed OAuth configuration required');
  if (jwks.origin !== issuer.origin) throw new Error('JWKS must share the explicitly configured issuer origin');
  return Object.freeze({ issuer: input.issuer, audience: input.audience, jwksUri: jwks.href, ownerSubject: input.ownerSubject });
}
export function createResourceVerifier(input, { jwksSnapshotPath } = {}) {
  const config = configuration(input);
  const keys = jwksSnapshotPath !== undefined ? createSnapshotKeyResolver(jwksSnapshotPath,config) : createRemoteJWKSet(new URL(config.jwksUri), {
    timeoutDuration: 3000, cooldownDuration: 30000, cacheMaxAge: 60000,
    [customFetch]: async (url, options) => {
      if (new URL(url).href !== config.jwksUri) throw new Error('Unexpected JWKS URL');
      const response = await fetch(url, { ...options, redirect: 'error' });
      if (response.status !== 200) throw new Error('JWKS unavailable');
      const reader = response.body?.getReader();
      if (!reader) throw new Error('Empty JWKS');
      const chunks = []; let length = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          length += value.length;
          if (length > 65536) { await reader.cancel(); throw new Error('JWKS too large'); }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      return new Response(Buffer.concat(chunks), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  async function verifyAccessToken(token, { requiredScopes = ['messages:read'] } = {}) {
    try {
      if (typeof token !== 'string' || token.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error();
      if (!Array.isArray(requiredScopes) || !requiredScopes.length || requiredScopes.some(scope => !domainScopes.has(scope))) throw new Error();
      const header = decodeProtectedHeader(token);
      if (header.alg !== 'RS256' || header.typ !== 'at+jwt' || !/^[A-Za-z0-9_-]{1,128}$/.test(header.kid ?? '') || header.jku || header.x5u || header.jwk || header.x5c) throw new Error();
      const { payload } = await jwtVerify(token, keys, { issuer: config.issuer, audience: config.audience, algorithms: ['RS256'], typ: 'at+jwt', requiredClaims: ['iss', 'aud', 'sub', 'exp', 'iat', 'scope'], maxTokenAge: 900, clockTolerance: 0 });
      if (payload.sub !== config.ownerSubject || !Number.isInteger(payload.iat) || !Number.isInteger(payload.exp) || payload.exp <= payload.iat || payload.exp - payload.iat > 900 || typeof payload.scope !== 'string' || payload.scope.length > 1024) throw new Error();
      const scopes = payload.scope.split(' ');
      if (scopes.some(scope => !/^[A-Za-z0-9:._-]+$/.test(scope)) || requiredScopes.some(scope => !scopes.includes(scope))) throw new Error();
      return Object.freeze({ issuer: payload.iss, audience: config.audience, subject: payload.sub, expiresAt: payload.exp * 1000, scopes: Object.freeze(scopes.filter(scope => domainScopes.has(scope))) });
    } catch { throw new Error('Access denied'); }
  }
  return Object.freeze({ verifyAccessToken, async verifyBearerHeader(header, options) {
    const match = typeof header === 'string' && /^Bearer ([A-Za-z0-9_.-]+)$/i.exec(header);
    if (!match) throw new Error('Access denied');
    return verifyAccessToken(match[1], options);
  }, async refreshTrustedKeys() { try { await keys.reload(); } catch { throw new Error('JWKS refresh failed'); } } });
}
