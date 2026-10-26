import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createResourceVerifier } from './verifier.mjs';
import { createAuthenticatedSyntheticPilot } from './authenticated-pilot.mjs';
const config = { issuer:'https://issuer.invalid/', audience:'https://resource.invalid/mcp', jwksUri:'https://issuer.invalid/.well-known/jwks.json', ownerSubject:'synthetic-owner' };

test('standard JWT/JWKS resource verification with ephemeral keys and loopback-only JWKS', async t => {
  const first = await generateKeyPair('RS256', { modulusLength:2048, extractable:false });
  const second = await generateKeyPair('RS256', { modulusLength:2048, extractable:false });
  const publicJwk = async (pair, kid) => ({ ...await exportJWK(pair.publicKey), kid, alg:'RS256', use:'sig' });
  let jwks={keys:[await publicJwk(first,'first')]}; let mode='ok'; let requests=0;
  const server=createServer((req,res)=> {
    requests++; assert.equal(req.headers.authorization, undefined);
    if (mode==='unavailable') {res.writeHead(503).end();return;}
    if (mode==='redirect') {res.writeHead(302,{Location:'https://unexpected.invalid/jwks'}).end();return;}
    res.writeHead(200,{'content-type':'application/json'}).end(mode==='malformed' ? '{bad' : JSON.stringify(jwks));
  });
  server.listen(0,'127.0.0.1'); await once(server,'listening');
  const originalFetch=globalThis.fetch;
  t.mock.method(globalThis,'fetch', async (url, options) => {
    assert.equal(new URL(url).href,config.jwksUri);
    return originalFetch(`http://127.0.0.1:${server.address().port}/jwks`,options);
  });
  async function sign({claims={},header={},pair=first}={}) {
    const now=Math.floor(Date.now()/1000);
    return new SignJWT({iss:config.issuer,aud:config.audience,sub:config.ownerSubject,iat:now,exp:now+300,scope:'messages:read drafts:create',...claims}).setProtectedHeader({alg:'RS256',typ:'at+jwt',kid:'first',...header}).sign(pair.privateKey);
  }
  try {
    const verifier=createResourceVerifier(config);
    await t.test('valid signature yields an owner-bound principal and required draft scope', async()=> {
      const token=await sign(); const principal=await verifier.verifyBearerHeader(`Bearer ${token}`,{requiredScopes:['messages:read','drafts:create']});
      assert.equal(principal.subject,config.ownerSubject); assert.ok(Object.isFrozen(principal)); assert.ok(requests>=1);
    });
    await t.test('issuer, audience, owner, exp, nbf, missing claims, stale age and overscoped lifetime fail closed', async()=> {
      const now=Math.floor(Date.now()/1000);
      for(const claims of [{iss:'https://other.invalid/'},{aud:'https://other.invalid/'},{sub:'other'},{exp:now-1},{nbf:now+60},{scope:undefined},{exp:undefined},{iat:undefined},{iat:now-1000,exp:now+20},{exp:now+901}]) await assert.rejects(verifier.verifyAccessToken(await sign({claims})), /^Error: Access denied$/);
    });
    await t.test('scope, malformed bearer, header key URLs, algorithm confusion and signature tampering fail', async()=> {
      for(const claims of [{scope:'drafts:create'},{scope:'*'},{scope:'messages:read  drafts:create'}]) await assert.rejects(verifier.verifyAccessToken(await sign({claims})));
      for(const header of [{typ:'JWT'},{kid:undefined},{jku:'https://unexpected.invalid/jwks'},{jwk:{kty:'RSA'}}]) await assert.rejects(verifier.verifyAccessToken(await sign({header})));
      const hs=await new SignJWT({}).setProtectedHeader({alg:'HS256',typ:'at+jwt',kid:'first'}).sign(crypto.getRandomValues(new Uint8Array(32)));
      await assert.rejects(verifier.verifyAccessToken(hs));
      const token=await sign(); const parts=token.split('.'); parts[2]=(parts[2][0]==='a'?'b':'a')+parts[2].slice(1);
      await assert.rejects(verifier.verifyAccessToken(parts.join('.')));
      await assert.rejects(verifier.verifyBearerHeader('Basic synthetic')); await assert.rejects(verifier.verifyBearerHeader('Bearer not.a.token'));
      await assert.rejects(verifier.verifyAccessToken(token,{requiredScopes:['messages:send']}));
    });
    await t.test('JWKS rotation accepts new key and rejects retired key after explicit trusted refresh', async()=> {
      jwks={keys:[await publicJwk(second,'second')]}; await verifier.refreshTrustedKeys();
      await verifier.verifyAccessToken(await sign({pair:second,header:{kid:'second'}}));
      await assert.rejects(verifier.verifyAccessToken(await sign()));
    });
    await t.test('unknown kid refreshes after cooldown while retired keys are denied', async()=> {
      t.mock.timers.enable({ apis:['Date'], now:Date.now() });
      try {
        const automatic=createResourceVerifier(config);
        await automatic.verifyAccessToken(await sign({pair:second,header:{kid:'second'}}));
        jwks={keys:[await publicJwk(first,'first')]};
        const nextToken=await sign();
        await assert.rejects(automatic.verifyAccessToken(nextToken));
        t.mock.timers.tick(31000);
        await automatic.verifyAccessToken(nextToken);
        await assert.rejects(automatic.verifyAccessToken(await sign({pair:second,header:{kid:'second'}})));
      } finally { t.mock.timers.reset(); jwks={keys:[await publicJwk(second,'second')]}; }
    });
    await t.test('expired JWKS cache plus outage denies even a formerly valid signing key', async()=> {
      t.mock.timers.enable({ apis:['Date'], now:Date.now() });
      try {
        const warm=createResourceVerifier(config);
        const token=await sign({pair:second,header:{kid:'second'}});
        await warm.verifyAccessToken(token);
        mode='unavailable'; t.mock.timers.tick(61000);
        await assert.rejects(warm.verifyAccessToken(token));
      } finally { mode='ok'; t.mock.timers.reset(); }
    });
    await t.test('unavailable, redirecting and malformed cold JWKS never fall back to claims or fixtures', async()=> {
      for(const failure of ['unavailable','redirect','malformed']) {
        mode=failure; const cold=createResourceVerifier(config);
        await assert.rejects(cold.verifyAccessToken(await sign({pair:second,header:{kid:'second'}})));
      }
      mode='ok';
    });
    await t.test('runtime adapter uses real crypto verification and rejects fixture marker', async()=> {
      const pilot=createAuthenticatedSyntheticPilot({oauth:config,chats:[{id:'synthetic-a',activatedAt:0,consentUntil:Date.now()+60000,participantsConsented:true}]});
      await assert.rejects(pilot.listNewMessages('synthetic-fixture','synthetic-a'));
      assert.deepEqual(await pilot.listNewMessages(await sign({pair:second,header:{kid:'second'}}),'synthetic-a'),[]);
    });
  } finally { t.mock.restoreAll(); await new Promise(resolve=>server.close(resolve)); }
});
test('runtime has no missing-configuration or insecure-URL fallback',()=> {
 assert.throws(()=>createAuthenticatedSyntheticPilot());
 for(const patch of [{ownerSubject:''},{jwksUri:'http://127.0.0.1/jwks'},{jwksUri:'https://other.invalid/jwks'},{issuer:'https://issuer.invalid/?secret=value'}]) assert.throws(()=>createResourceVerifier({...config,...patch}));
});
