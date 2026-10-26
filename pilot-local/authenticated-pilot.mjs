import { createResourceVerifier } from './verifier.mjs';
import { SyntheticPilot } from './pilot.mjs';
// The only runtime construction path: no fixture verifier argument, env fallback or anonymous mode.
export function createAuthenticatedSyntheticPilot({ oauth, chats = [] } = {}) {
  const verifier = createResourceVerifier(oauth);
  return new SyntheticPilot({ issuer: oauth.issuer, audience: oauth.audience, owner: oauth.ownerSubject, chats, verifyAccessToken: token => verifier.verifyAccessToken(token) });
}
